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
        var tcp_ports: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
        defer tcp_ports.deinit(alloc);
        var udp_ports: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
        defer udp_ports.deinit(alloc);
        var has_tcp_range: bool = false;
        var has_udp_range: bool = false;

        for (entry.value_ptr.listeners) |listener| {
            if (listener.port) |port| {
                if (std.mem.eql(u8, listener.proto, "tcp")) {
                    if (tcp_ports.items.len > 0) try tcp_ports.appendSlice(alloc, ", ");
                    try tcp_ports.writer(alloc).print("{d}", .{port});
                } else if (std.mem.eql(u8, listener.proto, "udp")) {
                    if (udp_ports.items.len > 0) try udp_ports.appendSlice(alloc, ", ");
                    try udp_ports.writer(alloc).print("{d}", .{port});
                }
            } else if (listener.port_range) |range| {
                if (std.mem.eql(u8, listener.proto, "tcp")) {
                    if (tcp_ports.items.len > 0) try tcp_ports.appendSlice(alloc, ", ");
                    try tcp_ports.writer(alloc).print("{d}-{d}", .{ range.start, range.end });
                    has_tcp_range = true;
                } else if (std.mem.eql(u8, listener.proto, "udp")) {
                    if (udp_ports.items.len > 0) try udp_ports.appendSlice(alloc, ", ");
                    try udp_ports.writer(alloc).print("{d}-{d}", .{ range.start, range.end });
                    has_udp_range = true;
                }
            }
        }

        if (tcp_ports.items.len > 0) {
            const flags = if (has_tcp_range) "; flags interval" else "";
            try buffer.writer(alloc).print("    set svc_{s}_tcp {{ type inet_service{s}; elements = {{ {s} }} }}\n", .{
                entry.key_ptr.*,
                flags,
                tcp_ports.items,
            });
        }
        if (udp_ports.items.len > 0) {
            const flags = if (has_udp_range) "; flags interval" else "";
            try buffer.writer(alloc).print("    set svc_{s}_udp {{ type inet_service{s}; elements = {{ {s} }} }}\n", .{
                entry.key_ptr.*,
                flags,
                udp_ports.items,
            });
        }
    }

    var rate_limit_counter: u32 = 0;
    for (p.rules) |rule| {
        if (rule.allow) |allow| {
            if (allow.rate_limit != null) {
                try buffer.writer(alloc).print(
                    \\
                    \\    meter rate_limit_{d} {{ type ipv4_addr; size 65535; }}
                , .{rate_limit_counter});
                rate_limit_counter += 1;
            }
        }
    }

    if (rate_limit_counter > 0) {
        try buffer.appendSlice(alloc, "\n");
    }

    const policy_action = if (std.mem.eql(u8, p.defaults.inbound, "deny")) "drop" else "accept";
    try buffer.writer(alloc).print(
        \\
        \\    chain input {{
        \\        type filter hook input priority 0; policy {s};
        \\        ct state established,related accept
        \\        iif lo accept
        \\        ct state invalid drop
        \\        ip protocol icmp icmp type {{ echo-request, echo-reply, destination-unreachable, time-exceeded }} accept
        \\        ip6 nexthdr ipv6-icmp icmpv6 type {{ echo-request, echo-reply, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-router-solicit }} accept
        \\
    , .{policy_action});

    var rl_idx: u32 = 0;
    for (p.rules) |rule| {
        if (rule.deny) |deny| {
            try compileIpv4DenyRule(alloc, &buffer, p, deny);
        } else if (rule.allow) |allow| {
            try compileIpv4AllowRule(alloc, &buffer, p, allow, &rl_idx);
        }
    }

    if (p.ipv6) |ipv6_policy| {
        if (ipv6_policy.enabled) {
            if (ipv6_policy.rules) |v6_rules| {
                for (v6_rules) |rule| {
                    if (rule.deny) |deny| {
                        try compileIpv6DenyRule(alloc, &buffer, p, ipv6_policy, deny);
                    } else if (rule.allow) |allow| {
                        try compileIpv6AllowRule(alloc, &buffer, p, ipv6_policy, allow);
                    }
                }
            }
        }
    }

    if (p.logging.enabled and std.mem.eql(u8, p.defaults.inbound, "deny")) {
        try buffer.writer(alloc).print(
            \\        limit rate {d}/second burst {d} packets log prefix "{s}: " level warn
            \\
        , .{ p.logging.rate_limit, p.logging.burst, p.logging.prefix });
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

    try buffer.writer(alloc).print(
        \\
        \\    chain forward {{
        \\        type filter hook forward priority 0; policy drop;
        \\        ct state established,related accept
        \\    }}
        \\
    , .{});

    try buffer.appendSlice(alloc, "}\n");

    return try buffer.toOwnedSlice(alloc);
}

fn compileIpv4AllowRule(alloc: std.mem.Allocator, buffer: *std.ArrayList(u8), p: policy.Policy, allow: policy.AllowRule, rl_idx: *u32) !void {
    const service_name = allow.service;
    const svc = p.services.get(service_name) orelse {
        std.log.warn("Rule references unknown service '{s}', skipping.", .{service_name});
        return;
    };

    var has_tcp = false;
    var has_udp = false;
    for (svc.listeners) |listener| {
        if (std.mem.eql(u8, listener.proto, "tcp")) has_tcp = true;
        if (std.mem.eql(u8, listener.proto, "udp")) has_udp = true;
    }

    for (allow.sources) |source_set_name| {
        if (p.sourceSets.get(source_set_name) == null) {
            std.log.warn("Rule references unknown source set '{s}', skipping.", .{source_set_name});
            continue;
        }

        if (has_tcp) {
            if (allow.rate_limit) |rl| {
                try buffer.writer(alloc).print("        ip saddr @{s} tcp dport @svc_{s}_tcp meter rate_limit_{d} {{ ip saddr limit rate {d}/{s} burst {d} packets }} accept\n", .{
                    source_set_name,
                    service_name,
                    rl_idx.*,
                    rl.rate,
                    rl.unit,
                    rl.burst,
                });
                rl_idx.* += 1;
            } else {
                try buffer.writer(alloc).print("        ip saddr @{s} tcp dport @svc_{s}_tcp accept\n", .{
                    source_set_name,
                    service_name,
                });
            }
        }

        if (has_udp) {
            if (allow.rate_limit) |rl| {
                try buffer.writer(alloc).print("        ip saddr @{s} udp dport @svc_{s}_udp meter rate_limit_{d} {{ ip saddr limit rate {d}/{s} burst {d} packets }} accept\n", .{
                    source_set_name,
                    service_name,
                    rl_idx.*,
                    rl.rate,
                    rl.unit,
                    rl.burst,
                });
                rl_idx.* += 1;
            } else {
                try buffer.writer(alloc).print("        ip saddr @{s} udp dport @svc_{s}_udp accept\n", .{
                    source_set_name,
                    service_name,
                });
            }
        }
    }
}

fn compileIpv4DenyRule(alloc: std.mem.Allocator, buffer: *std.ArrayList(u8), p: policy.Policy, deny: policy.DenyRule) !void {
    for (deny.sources) |source_set_name| {
        if (p.sourceSets.get(source_set_name) == null) {
            std.log.warn("Deny rule references unknown source set '{s}', skipping.", .{source_set_name});
            continue;
        }

        if (deny.service) |service_name| {
            const svc = p.services.get(service_name) orelse {
                std.log.warn("Deny rule references unknown service '{s}', skipping.", .{service_name});
                continue;
            };

            var has_tcp = false;
            var has_udp = false;
            for (svc.listeners) |listener| {
                if (std.mem.eql(u8, listener.proto, "tcp")) has_tcp = true;
                if (std.mem.eql(u8, listener.proto, "udp")) has_udp = true;
            }

            if (has_tcp) {
                if (deny.log) {
                    try buffer.writer(alloc).print("        ip saddr @{s} tcp dport @svc_{s}_tcp log prefix \"VIGIL_DENY: \" drop\n", .{
                        source_set_name,
                        service_name,
                    });
                } else {
                    try buffer.writer(alloc).print("        ip saddr @{s} tcp dport @svc_{s}_tcp drop\n", .{
                        source_set_name,
                        service_name,
                    });
                }
            }
            if (has_udp) {
                if (deny.log) {
                    try buffer.writer(alloc).print("        ip saddr @{s} udp dport @svc_{s}_udp log prefix \"VIGIL_DENY: \" drop\n", .{
                        source_set_name,
                        service_name,
                    });
                } else {
                    try buffer.writer(alloc).print("        ip saddr @{s} udp dport @svc_{s}_udp drop\n", .{
                        source_set_name,
                        service_name,
                    });
                }
            }
        } else {
            if (deny.log) {
                try buffer.writer(alloc).print("        ip saddr @{s} log prefix \"VIGIL_DENY: \" drop\n", .{source_set_name});
            } else {
                try buffer.writer(alloc).print("        ip saddr @{s} drop\n", .{source_set_name});
            }
        }
    }
}

fn compileIpv6AllowRule(alloc: std.mem.Allocator, buffer: *std.ArrayList(u8), p: policy.Policy, ipv6_policy: policy.Ipv6Policy, allow: policy.AllowRule) !void {
    const service_name = allow.service;
    const svc = p.services.get(service_name) orelse return;

    var has_tcp = false;
    var has_udp = false;
    for (svc.listeners) |listener| {
        if (std.mem.eql(u8, listener.proto, "tcp")) has_tcp = true;
        if (std.mem.eql(u8, listener.proto, "udp")) has_udp = true;
    }

    for (allow.sources) |source_set_name| {
        if (ipv6_policy.sourceSets == null or ipv6_policy.sourceSets.?.get(source_set_name) == null) continue;

        if (has_tcp) {
            try buffer.writer(alloc).print("        ip6 saddr @{s} tcp dport @svc_{s}_tcp accept\n", .{
                source_set_name,
                service_name,
            });
        }
        if (has_udp) {
            try buffer.writer(alloc).print("        ip6 saddr @{s} udp dport @svc_{s}_udp accept\n", .{
                source_set_name,
                service_name,
            });
        }
    }
}

fn compileIpv6DenyRule(alloc: std.mem.Allocator, buffer: *std.ArrayList(u8), p: policy.Policy, ipv6_policy: policy.Ipv6Policy, deny: policy.DenyRule) !void {
    for (deny.sources) |source_set_name| {
        if (ipv6_policy.sourceSets == null or ipv6_policy.sourceSets.?.get(source_set_name) == null) continue;

        if (deny.service) |service_name| {
            const svc = p.services.get(service_name) orelse continue;

            var has_tcp = false;
            var has_udp = false;
            for (svc.listeners) |listener| {
                if (std.mem.eql(u8, listener.proto, "tcp")) has_tcp = true;
                if (std.mem.eql(u8, listener.proto, "udp")) has_udp = true;
            }

            if (has_tcp) {
                if (deny.log) {
                    try buffer.writer(alloc).print("        ip6 saddr @{s} tcp dport @svc_{s}_tcp log prefix \"VIGIL_DENY: \" drop\n", .{
                        source_set_name,
                        service_name,
                    });
                } else {
                    try buffer.writer(alloc).print("        ip6 saddr @{s} tcp dport @svc_{s}_tcp drop\n", .{
                        source_set_name,
                        service_name,
                    });
                }
            }
            if (has_udp) {
                if (deny.log) {
                    try buffer.writer(alloc).print("        ip6 saddr @{s} udp dport @svc_{s}_udp log prefix \"VIGIL_DENY: \" drop\n", .{
                        source_set_name,
                        service_name,
                    });
                } else {
                    try buffer.writer(alloc).print("        ip6 saddr @{s} udp dport @svc_{s}_udp drop\n", .{
                        source_set_name,
                        service_name,
                    });
                }
            }
        } else {
            if (deny.log) {
                try buffer.writer(alloc).print("        ip6 saddr @{s} log prefix \"VIGIL_DENY: \" drop\n", .{source_set_name});
            } else {
                try buffer.writer(alloc).print("        ip6 saddr @{s} drop\n", .{source_set_name});
            }
        }
    }
}
