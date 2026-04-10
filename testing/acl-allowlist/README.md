# ACL Allowlist Test

Six Docker nodes use generated per-node ACL files mounted at the hardcoded runtime paths:

- `node-a` and `node-b` carry the insider allowlist (`a`, `b`, `e`, `f`)
- `node-c` and `node-d` each carry a broad local allowlist containing every test alias
- `node-e` and `node-f` do not mount any ACL files locally

This lets us test three different node behaviors at once:

- insiders (`a`, `b`) explicitly allow `a`, `b`, `e`, and `f`
- outsiders (`c`, `d`) allow everyone locally, but still cannot join because insiders reject them during handshake
- allowed remotes (`e`, `f`) rely on the insider ACLs and do not need local ACL files

## Test Identities

Allowed:

- `node-a`
  - `npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m`
  - `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
- `node-b`
  - `npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le`
  - `b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0`

Denied:

- `node-c`
  - `npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6`
  - `c102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc0`
- `node-d`
  - `npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl`
  - `d102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fd0`

Additional allowed:

- `node-e`
  - `npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6`
  - `nsec1egyrmekfw3u4l88v8zhrak9uht503s2kvn9v49tqgp6c5l2yuxgsv386l0`
- `node-f`
  - `npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c`
  - `nsec1afh3nysthqh47awpdewcw59wvvp499f8dvlyclmnv4gvpxdk56dsa6eqsn`

Each `fips.key` file contains the bare hex secret above. FIPS accepts hex or
`nsec1...` in key files.

## Run

Build the Linux binaries and test image:

```bash
./testing/scripts/build.sh --no-docker
```

Start the ACL test mesh:

```bash
./testing/acl-allowlist/generate-configs.sh
docker compose -f testing/acl-allowlist/docker-compose.yml up -d --build
```

Or run the full integration check:

```bash
./testing/acl-allowlist/test.sh
```

The ACL harness pins the expected test entrypoint explicitly so it does not
accidentally reuse an older `fips-test:latest` image with a different startup
script.

The generator writes `testing/acl-allowlist/generated-configs/`, including
per-node `fips.yaml`, `fips.key`, alias-based ACL files, and `/etc/fips/hosts`
fixtures. The compose file mounts that generated tree into containers.

ACL paths are fixed in this branch:

- `/etc/fips/peers.allow`
- `/etc/fips/peers.deny`

Mounted ACL files in this harness:

- `node-a` and `node-b`: insider allowlist
- `node-c` and `node-d`: broad local allowlist used by outsider nodes trying to blend in
- `node-e` and `node-f`: no ACL files mounted
- all nodes: `/etc/fips/hosts` aliases for `node-a` through `node-f`

Generated fixture location:

- `testing/acl-allowlist/generated-configs/`

Inspect ACL state:

```bash
docker exec fips-acl-a fipsctl acl show
docker exec fips-acl-a fipsctl acl reload
```

`fipsctl acl show` exposes both:

- `allow_raw_entries` / `deny_raw_entries`: the alias tokens exactly as written in the ACL files
- `allow_entries` / `deny_entries`: the resolved effective npub entries

Inspect peer state:

```bash
docker exec fips-acl-a fipsctl show peers
docker exec fips-acl-b fipsctl show peers
docker exec fips-acl-c fipsctl show peers
docker exec fips-acl-d fipsctl show peers
docker exec fips-acl-e fipsctl show peers
docker exec fips-acl-f fipsctl show peers
```

`fipsctl show peers` reports direct authenticated neighbors, not full end-to-end
mesh reachability.

Expected:

- `node-a` sees `node-b`, `node-e`, and `node-f`
- `node-b` sees `node-a`
- `node-c` sees no peers
- `node-d` sees no peers
- `node-e` sees `node-a`
- `node-f` sees `node-a`

Expected end-to-end mesh reachability:

- `node-a`, `node-b`, `node-e`, and `node-f` can `ping6` each other over the mesh
- `node-c` and `node-d` cannot join that mesh because `node-a` rejects them at the ACL layer

Visible rejection logs:

```bash
docker compose -f testing/acl-allowlist/docker-compose.yml logs -f node-a node-b node-c node-d node-e node-f
```

You should see warnings like:

```text
Rejected peer by ACL ... context=inbound_handshake decision=not in allowlist
```

In this alias-aware harness, `node-c` and `node-d` permit the outbound attempt
locally, but `node-a` still rejects them because they are not in the insider
allowlist.

Stop and clean up:

```bash
docker compose -f testing/acl-allowlist/docker-compose.yml down
```
