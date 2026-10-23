# Vigil

Zig/C firewall agent. YAML policies compile to nftables. Conntrack flows go into SQLite.

Needs Linux, Zig 0.15.2, libmnl, sqlite3 and nftables.

Build/test:

```sh
zig build
zig build test
```

From macOS:

```sh
docker build -f tests/Dockerfile -t vigil-tests .
docker run --rm --network none --cap-add NET_ADMIN vigil-tests
```

Run on Linux:

```sh
sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" /var/lib/vigil
sudo env VIGIL_AGENT_UID="$(id -u)" ./zig-out/bin/helper
```

Then in another terminal:

```sh
./zig-out/bin/agent --policy config/policy.yml --no-observer --watch
```

Observer permissions and shutdown still need sorting out, so leave it off for now.
