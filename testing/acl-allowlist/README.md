# ACL Allowlist Test

Four Docker nodes share the same ACL files mounted at the hardcoded runtime paths:

- `node-a` and `node-b` are in `peers.allow`
- `node-c` and `node-d` are not

Because `peers.allow` is non-empty, only A and B should be permitted to join.
`peers.deny` is intentionally empty in this test.

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

Each `fips.key` file contains the bare hex secret above. FIPS accepts hex or
`nsec1...` in key files.

## Run

Build the Linux binaries and test image:

```bash
./testing/scripts/build.sh --no-docker
```

Start the ACL test mesh:

```bash
docker compose -f testing/acl-allowlist/docker-compose.yml up -d --build
```

The ACL harness pins the expected test entrypoint explicitly so it does not
accidentally reuse an older `fips-test:latest` image with a different startup
script.

ACL paths are fixed in this branch:

- `/etc/fips/peers.allow`
- `/etc/fips/peers.deny`

Inspect peer state:

```bash
docker exec fips-acl-a fipsctl show peers
docker exec fips-acl-b fipsctl show peers
docker exec fips-acl-c fipsctl show peers
docker exec fips-acl-d fipsctl show peers
```

Expected:

- `node-a` sees `node-b`
- `node-b` sees `node-a`
- `node-c` sees no peers
- `node-d` sees no peers

Visible rejection logs:

```bash
docker compose -f testing/acl-allowlist/docker-compose.yml logs -f node-a node-b node-c node-d
```

You should see warnings like:

```text
Rejected peer by ACL ... context=inbound_handshake decision=not in allowlist
Rejected peer by ACL ... context=outbound_connect decision=not in allowlist
Rejected peer by ACL ... context=outbound_handshake decision=not in allowlist
```

Stop and clean up:

```bash
docker compose -f testing/acl-allowlist/docker-compose.yml down
```
