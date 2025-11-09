const std = @import("std");
const policy = @import("policy.zig");

// compiles the parsed policy into an nftables script string
pub fn compile(p: policy.Policy, alloc: std.mem.Allocator) ![]const u8 {
    var buffer = std.ArrayList(u8).init(alloc);
    const writer = buffer.writer();

    if (p.sourceSets.len == 0) {
        return error.InvalidPolicy;
    }

    if (p.services.len == 0) {
        return error.InvalidPolicy;
    }

    if (p.ipv6) |ipv6_policy| {
        if (ipv6_policy.sourceSets == null or ipv6_policy.rules == null) {
            return error.InvalidPolicy;
        }
    }

    try writer.writeAll("flush ruleset\n\n");

    try writer.writeAll("table inet vigilfw {\n");

    // 1. define all source sets (IPv4)
    try writer.writeAll("\n    # -- IPv4 Source Sets --\n");
    var source_set_iter = p.sourceSets.iterator();
    while (source_set_iter.next()) |entry| {
        try writer.print("    set {s} {{ type ipv4_addr; flags interval; elements = {{ {s} }} }}\n", .{
            entry.key_ptr.*,
            std.fmt.join(entry.value_ptr.*, ", "),
        });
    }

    // 2. define IPv6 source sets if enabled
    if (p.ipv6) |ipv6_policy| {
        if (ipv6_policy.enabled and ipv6_policy.sourceSets) |v6_sets| {
            try writer.writeAll("\n    # -- IPv6 Source Sets --\n");
            var v6_set_iter = v6_sets.iterator();
            while (v6_set_iter.next()) |entry| {
                try writer.print("    set {s} {{ type ipv6_addr; flags interval; elements = {{ {s} }} }}\n", .{
                    entry.key_ptr.*,
                    std.fmt.join(entry.value_ptr.*, ", "),
                });
            }
        }
    }

    // 3. define all service port sets
    try writer.writeAll("\n    # -- Service Port Sets --\n");
    var service_iter = p.services.iterator();
    while (service_iter.next()) |entry| {
        for (entry.value_ptr.listeners) |listener| {
            try writer.print("    set svc_{s}_{s} {{ type inet_service; elements = {{ {d} }} }}\n", .{
                entry.key_ptr.*,
                listener.proto,
                listener.port,
            });
        }
    }

    // 4. define main input chain
    const policy_action = if (std.mem.eql(u8, p.defaults.inbound, "deny")) "drop" else "accept";
    try writer.print(
        \\
        \\    chain input {{
        \\        type filter hook input priority 0; policy {s};
        \\
        \\        # Allow established and related traffic
        \\        ct state established,related accept
        \\
        \\        # Allow loopback traffic
        \\        iif lo accept
        \\
        \\        # Basic ICMP/ICMPv6 for network health
        \\        ip protocol icmp accept
        \\        ip6 nexthdr ipv6-icmp accept
        \\
        \\        # -- Begin Policy Rules --
        \\
    , .{policy_action});

    // 5. Generate rules from policy (IPv4)
    for (p.rules) |rule| {
        const service_name = rule.allow.service;
        const svc = p.services.get(service_name) orelse {
            std.log.warn("Rule references unknown service '{s}', skipping.", .{service_name});
            continue;
        };

        for (rule.allow.sources) |source_set_name| {
            if (p.sourceSets.get(source_set_name) == null) {
                std.log.warn("Rule references unknown source set '{s}', skipping.", .{source_set_name});
                continue;
            }
            for (svc.listeners) |listener| {
                try writer.print("        ip saddr @{s} {s} dport @svc_{s}_{s} accept\n", .{
                    source_set_name,
                    listener.proto,
                    service_name,
                    listener.proto,
                });
            }
        }
    }

    // 6. generate rules from policy (IPv6)
    if (p.ipv6) |ipv6_policy| {
        if (ipv6_policy.enabled and ipv6_policy.rules) |v6_rules| {
            for (v6_rules) |rule| {
                const service_name = rule.allow.service;
                const svc = p.services.get(service_name) orelse continue;

                for (rule.allow.sources) |source_set_name| {
                    if (ipv6_policy.sourceSets == null or ipv6_policy.sourceSets.?.get(source_set_name) == null) continue;

                    for (svc.listeners) |listener| {
                        try writer.print("        ip6 saddr @{s} {s} dport @svc_{s}_{s} accept\n", .{
                            source_set_name,
                            listener.proto,
                            service_name,
                            listener.proto,
                        });
                    }
                }
            }
        }
    }

    try writer.writeAll("    }\n");

    // TODO: Add DOCKER-USER chain integration (https://docs.docker.com/engine/network/firewall-nftables/)
    try writer.writeAll(
        \\
        \\    # You can add a 'forward' chain here if this host acts as a router
        \\    # chain forward {
        \\    #     type filter hook forward priority 0; policy drop;
        \\    # }
        \\
    );

    try writer.writeAll("}\n");

    return buffer.toOwnedSlice();
}
