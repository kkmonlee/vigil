# Vigil

A host firewall agent pairing a declarative `nftables` policy engine with a real-time `conntrack` event observer. Vigil prioritises privilege separation, atomic ruleset updates and direct interaction with kernel subsystems.

### Stack

-   **Agent:** Zig (C interop, `comptime`-driven logic)
-   **Privileged helper:** C (`seccomp`-ready privilege boundary)
-   **Ruleset engine:** `nftables` (native `inet` family, atomic transactions, `set`/`map` optimisation)
-   **Observation:** `libmnl` (real-time kernel event subscription via `cnetlink`)
-   **Policy format:** YAML
-   **Datastore:** SQLite (`WAL`-enabled for concurrent R/W, zero-conf)

### Some thoughts (might change later)

* Firewall logic is defined in YAML, abstracting CIDR and port groups into reusable sets. The agent's compiler translates this high-level definition into an optimised, low-level `nftables` ruleset.
* All ruleset changes are applied atomically. The entire ruleset is generated and piped to `nft -f -`, ensuring the firewall is never in an intermittent or broken state during an update.
* The core agent runs unprivileged. All operations requiring `CAP_NET_ADMIN` are delegated to a minimal C helper over a UNIX domain socket. The helper's sole responsibility is to execute `nft` and has a severely restricted attack surface.
* New connections are observed in real time by subscribing to the `NFNLGRP_CONNTRACK_NEW` netlink multicast group via `libmnl`. This avoids inefficient polling of `/proc` and captures flow metadata as it is created by the kernel.
* Observed flows are aggregated by the minute and recorded in a SQLite database running in Write-Ahead Logging (WAL) mode for non-blocking writes. Not sure if this is a good idea yet.

The agent is split into two processes for privilege separation.

```
+--------------------------+      Unix Socket      +-----------------+
|   Agent (unprivileged)   |   (/tmp/vigil.sock)   | Helper (root)   |
|                          |---------------------->|                 |
| - Parse policy.yml       |  nftables script      | - exec("nft")   |
| - Compile nft ruleset    |                       |                 |
| - Observe conntrack      |                       |                 |
+--------------------------+                       +-----------------+
        |
        | (write)
        |
+--------------------------+
|  SQLite DB               |
| /var/lib/vigil/flows.db  |
+--------------------------+
```

### Build
Formal build steps are TBD. Figure it out yourself until the project is ready.

Just make sure you have libraries for `libmnl` and `sqlite3` are installed. `helper` and `agent` both need to run together - the agent applies policy and logs `conntrack` events.

