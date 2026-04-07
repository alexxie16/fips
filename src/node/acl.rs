//! Peer access control lists (ACLs) keyed by npub.

use crate::{NodeAddr, PeerIdentity};
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Default path for the peer allow list.
pub const DEFAULT_PEERS_ALLOW_PATH: &str = "/etc/fips/peers.allow";

/// Default path for the peer deny list.
pub const DEFAULT_PEERS_DENY_PATH: &str = "/etc/fips/peers.deny";

/// Result of evaluating a peer against the ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAclDecision {
    /// Explicitly permitted by `peers.allow`.
    AllowList,
    /// Explicitly rejected by `peers.deny`.
    DenyList,
    /// No rule matched; default-open behavior permits the peer.
    DefaultAllow,
}

impl PeerAclDecision {
    /// Whether the peer is allowed.
    pub fn allowed(self) -> bool {
        !matches!(self, Self::DenyList)
    }
}

/// Serializable ACL state for control-plane visibility.
#[derive(Debug, Clone, Serialize)]
pub struct PeerAclSnapshot {
    pub allow_file: String,
    pub deny_file: String,
    pub allow_entries: Vec<String>,
    pub deny_entries: Vec<String>,
    pub allow_all: bool,
    pub deny_all: bool,
    pub allow_count: usize,
    pub deny_count: usize,
}

/// Loaded peer ACL state.
#[derive(Debug, Clone, Default)]
pub struct PeerAcl {
    allow: HashSet<NodeAddr>,
    deny: HashSet<NodeAddr>,
    allow_entries: BTreeSet<String>,
    deny_entries: BTreeSet<String>,
    allow_all: bool,
    deny_all: bool,
}

impl PeerAcl {
    /// Create an empty ACL.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the allow/deny files into a new ACL.
    pub fn load_files(allow_path: &Path, deny_path: &Path) -> Self {
        let mut acl = Self::new();
        acl.load_file(allow_path, true);
        acl.load_file(deny_path, false);

        if !acl.is_empty() {
            debug!(
                allow_entries = acl.allow_entries.len(),
                deny_entries = acl.deny_entries.len(),
                allow_all = acl.allow_all,
                deny_all = acl.deny_all,
                "Loaded peer ACL files"
            );
        }

        acl
    }

    /// Evaluate whether a peer is allowed.
    pub fn check(&self, peer: &PeerIdentity) -> PeerAclDecision {
        let addr = peer.node_addr();

        if self.allow_all || self.allow.contains(addr) {
            PeerAclDecision::AllowList
        } else if self.deny_all || self.deny.contains(addr) {
            PeerAclDecision::DenyList
        } else {
            PeerAclDecision::DefaultAllow
        }
    }

    /// Whether the ACL has no entries or wildcards.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && !self.allow_all && !self.deny_all
    }

    /// Create a serializable snapshot of the current ACL state.
    pub fn snapshot(&self, allow_path: &Path, deny_path: &Path) -> PeerAclSnapshot {
        PeerAclSnapshot {
            allow_file: allow_path.display().to_string(),
            deny_file: deny_path.display().to_string(),
            allow_entries: self.allow_entries.iter().cloned().collect(),
            deny_entries: self.deny_entries.iter().cloned().collect(),
            allow_all: self.allow_all,
            deny_all: self.deny_all,
            allow_count: self.allow_entries.len(),
            deny_count: self.deny_entries.len(),
        }
    }

    fn load_file(&mut self, path: &Path, is_allow: bool) {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %path.display(), "No ACL file found, skipping");
                return;
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read ACL file");
                return;
            }
        };

        for (line_num, line) in contents.lines().enumerate() {
            let trimmed = line.split('#').next().unwrap_or("").trim();

            if trimmed.is_empty() {
                continue;
            }

            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() != 1 {
                warn!(
                    path = %path.display(),
                    line = line_num + 1,
                    content = %trimmed,
                    "Expected one ACL entry per line, skipping"
                );
                continue;
            }

            let entry = fields[0];
            if entry.eq_ignore_ascii_case("ALL") {
                if is_allow {
                    self.allow_all = true;
                } else {
                    self.deny_all = true;
                }
                continue;
            }

            let peer = match PeerIdentity::from_npub(entry) {
                Ok(peer) => peer,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        line = line_num + 1,
                        error = %e,
                        "Skipping invalid ACL entry"
                    );
                    continue;
                }
            };

            if is_allow {
                self.allow.insert(*peer.node_addr());
                self.allow_entries.insert(peer.npub());
            } else {
                self.deny.insert(*peer.node_addr());
                self.deny_entries.insert(peer.npub());
            }
        }
    }
}

/// Tracks peer ACL files and reloads them on mtime changes.
pub struct PeerAclReloader {
    acl: PeerAcl,
    allow_path: PathBuf,
    deny_path: PathBuf,
    last_allow_mtime: Option<SystemTime>,
    last_deny_mtime: Option<SystemTime>,
}

impl PeerAclReloader {
    /// Create a new ACL reloader from the configured file paths.
    pub fn new(allow_path: PathBuf, deny_path: PathBuf) -> Self {
        let last_allow_mtime = crate::upper::hosts::file_mtime(&allow_path);
        let last_deny_mtime = crate::upper::hosts::file_mtime(&deny_path);
        let acl = PeerAcl::load_files(&allow_path, &deny_path);

        Self {
            acl,
            allow_path,
            deny_path,
            last_allow_mtime,
            last_deny_mtime,
        }
    }

    /// Get the current ACL.
    pub fn acl(&self) -> &PeerAcl {
        &self.acl
    }

    /// Return a serializable snapshot of the effective ACL.
    pub fn snapshot(&self) -> PeerAclSnapshot {
        self.acl.snapshot(&self.allow_path, &self.deny_path)
    }

    /// Check whether either ACL file changed and reload if needed.
    pub fn check_reload(&mut self) -> bool {
        let allow_mtime = crate::upper::hosts::file_mtime(&self.allow_path);
        let deny_mtime = crate::upper::hosts::file_mtime(&self.deny_path);

        if allow_mtime == self.last_allow_mtime && deny_mtime == self.last_deny_mtime {
            return false;
        }

        self.last_allow_mtime = allow_mtime;
        self.last_deny_mtime = deny_mtime;
        self.acl = PeerAcl::load_files(&self.allow_path, &self.deny_path);

        let snapshot = self.snapshot();
        info!(
            allow_file = %snapshot.allow_file,
            deny_file = %snapshot.deny_file,
            allow_entries = snapshot.allow_count,
            deny_entries = snapshot.deny_count,
            allow_all = snapshot.allow_all,
            deny_all = snapshot.deny_all,
            "Reloaded peer ACL files"
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn test_npub() -> String {
        Identity::generate().npub()
    }

    #[test]
    fn test_acl_missing_files_default_open() {
        let acl = PeerAcl::load_files(
            Path::new("/nonexistent/allow"),
            Path::new("/nonexistent/deny"),
        );
        let peer = PeerIdentity::from_npub(&test_npub()).unwrap();

        assert_eq!(acl.check(&peer), PeerAclDecision::DefaultAllow);
        assert!(acl.is_empty());
    }

    #[test]
    fn test_acl_allow_match_wins() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();

        std::fs::write(&allow, format!("{npub}\n")).unwrap();
        std::fs::write(&deny, format!("ALL\n{npub}\n")).unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);
        let peer = PeerIdentity::from_npub(&npub).unwrap();

        assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
    }

    #[test]
    fn test_acl_deny_only() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let denied = test_npub();
        let other = test_npub();

        std::fs::write(&deny, format!("{denied}\n")).unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);

        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&denied).unwrap()),
            PeerAclDecision::DenyList
        );
        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&other).unwrap()),
            PeerAclDecision::DefaultAllow
        );
    }

    #[test]
    fn test_acl_deny_all() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");

        std::fs::write(&deny, "ALL\n").unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);
        let peer = PeerIdentity::from_npub(&test_npub()).unwrap();

        assert_eq!(acl.check(&peer), PeerAclDecision::DenyList);
    }

    #[test]
    fn test_acl_inline_comments_and_bad_lines() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();

        std::fs::write(
            &allow,
            format!("# comment\n{npub} # inline comment\ninvalid entry here\n"),
        )
        .unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);

        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&npub).unwrap()),
            PeerAclDecision::AllowList
        );
        assert_eq!(acl.snapshot(&allow, &deny).allow_count, 1);
    }

    #[test]
    fn test_acl_reloader_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let denied = test_npub();

        let mut reloader = PeerAclReloader::new(allow.clone(), deny.clone());
        assert!(!reloader.check_reload());

        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(&deny, format!("{denied}\n")).unwrap();

        assert!(reloader.check_reload());
        assert_eq!(
            reloader
                .acl()
                .check(&PeerIdentity::from_npub(&denied).unwrap()),
            PeerAclDecision::DenyList
        );
    }
}
