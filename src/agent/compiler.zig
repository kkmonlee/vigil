// NFTables ruleset compiler: Transforms declarative policy into nftables syntax
// Generates table with named sets for sources/services and chains for input/output filtering
const std = @import("std");
const policy = @import("policy.zig");

pub fn compile(p: policy.Policy, alloc: std.mem.Allocator) ![]const u8 {
    var buffer: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer buffer.deinit(alloc);

    if (p.sourceSets.count() == 0) {
        return error.InvalidPolicy;
    }

    if (p.services.count() == 0) {
        return error.InvalidPolicy;
    }

    // IPv6 validation: if enabled, must have both sourceSets and rules defined
    if (p.ipv6) |ipv6_policy| {
        if (ipv6_policy.enabled and (ipv6_policy.sourceSets == null or ipv6_policy.rules == null)) {
            return error.InvalidPolicy;
        }
    }

    try buffer.appendSlice(alloc, "flush ruleset\n\n");
    try buffer.appendSlice(alloc, "table inet vigilfw {\n");
    try buffer.appendSlice(alloc, "\n");

    var source_set_iter = p.sourceSets.iterator();
    while (source_set_iter.next()) |entry| {
        const joined = try std.mem.join(alloc, ", ", entry.value_ptr.*);
        defer alloc.free(joined);
        try buffer.writer(alloc).print("    set {s} {{ type ipv4_addr; flags interval; elements = {{ {s} }} }}\n", .{
            entry.key_ptr.*,
            joined,
        });
    }

    if (p.ipv6) |ipv6_policy| {
        if (ipv6_policy.enabled) {
            if (ipv6_policy.sourceSets) |v6_sets| {
                try buffer.appendSlice(alloc, "\n");
                var v6_set_iter = v6_sets.iterator();
                while (v6_set_iter.next()) |entry| {
                    const joined = try std.mem.join(alloc, ", ", entry.value_ptr.*);
                    defer alloc.free(joined);
                    try buffer.writer(alloc).print("    set {s} {{ type ipv6_addr; flags interval; elements = {{ {s} }} }}\n", .{
                        entry.key_ptr.*,
                        joined,
                    });
                }
            }
        }
    }

    try buffer.appendSlice(alloc, "\n");
    var service_iter = p.services.iterator();
    while (service_iter.next()) |entry| {
        for (entry.value_ptr.listeners) |listener| {
            try buffer.writer(alloc).print("    set svc_{s}_{s} {{ type inet_service; elements = {{ {d} }} }}\n", .{
                entry.key_ptr.*,
                listener.proto,
                listener.port,
            });
        }
    }

    const policy_action = if (std.mem.eql(u8, p.defaults.inbound, "deny")) "drop" else "accept";
    try buffer.writer(alloc).print(
        \\
        \\    chain input {{
        \\        type filter hook input priority 0; policy {s};
        \\        ct state established,related accept
        \\        iif lo accept
        \\        ip protocol icmp accept
        \\        ip6 nexthdr ipv6-icmp accept
        \\
    , .{policy_action});

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
                try buffer.writer(alloc).print("        ip saddr @{s} {s} dport @svc_{s}_{s} accept\n", .{
                    source_set_name,
                    listener.proto,
                    service_name,
                    listener.proto,
                });
            }
        }
    }

    if (p.ipv6) |ipv6_policy| {
        if (ipv6_policy.enabled) {
            if (ipv6_policy.rules) |v6_rules| {
                for (v6_rules) |rule| {
                    const service_name = rule.allow.service;
                    const svc = p.services.get(service_name) orelse continue;

                    for (rule.allow.sources) |source_set_name| {
                        if (ipv6_policy.sourceSets == null or ipv6_policy.sourceSets.?.get(source_set_name) == null) continue;

                        for (svc.listeners) |listener| {
                            try buffer.writer(alloc).print("        ip6 saddr @{s} {s} dport @svc_{s}_{s} accept\n", .{
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
    }

    try buffer.appendSlice(alloc, "    }\n");

    const out_action = if (std.mem.eql(u8, p.defaults.outbound, "deny")) "drop" else "accept";
    try buffer.writer(alloc).print(
        \\
        \\    chain output {{
        \\        type filter hook output priority 0; policy {s};
        \\        ct state established,related accept
        \\        oif lo accept
        \\    }}
        \\
    , .{out_action});

    try buffer.appendSlice(alloc, "}\n");

    return try buffer.toOwnedSlice(alloc);
}
