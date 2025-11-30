// Policy parser: Custom YAML subset parser for firewall rule definitions
// Supports IPv4/IPv6 source sets, service definitions with listeners, allow rules, and default policies
// Avoids external dependencies for security-critical configuration parsing
const std = @import("std");

pub const Listener = struct {
    port: u16,
    proto: []const u8,
};

pub const Service = struct {
    listeners: []const Listener,
};

pub const AllowRule = struct {
    sources: []const []const u8,
    service: []const u8,
};

pub const Rule = struct {
    allow: AllowRule,
};

pub const Ipv6Policy = struct {
    enabled: bool = false,
    sourceSets: ?std.StringHashMap([]const []const u8) = null,
    rules: ?[]const Rule = null,
};

pub const Policy = struct {
    sourceSets: std.StringHashMap([]const []const u8),
    services: std.StringHashMap(Service),
    rules: []const Rule,
    defaults: struct {
        inbound: []const u8,
        outbound: []const u8,
    },
    ipv6: ?Ipv6Policy = null,

    // Memory ownership: Policy struct owns all allocated data
    // Caller must free: sourceSets (deinit), services (deinit), rules slice, 
    // defaults.inbound/outbound strings, ipv6.sourceSets (if set), ipv6.rules (if set)
    pub fn loadFromFile(alloc: std.mem.Allocator, path: []const u8) !Policy {
        const content = try std.fs.cwd().readFileAlloc(alloc, path, 1 * 1024 * 1024);
        defer alloc.free(content);

        return try parseYaml(alloc, content);
    }

    fn parseYaml(alloc: std.mem.Allocator, content: []const u8) !Policy {
        var sourceSets = std.StringHashMap([]const []const u8).init(alloc);
        errdefer sourceSets.deinit();

        var services = std.StringHashMap(Service).init(alloc);
        errdefer services.deinit();

        var rules: std.ArrayList(Rule) = .{ .items = &.{}, .capacity = 0 };
        errdefer rules.deinit(alloc);

        // Default policy actions - always allocate to maintain consistent ownership
        var defaults_inbound: []const u8 = try alloc.dupe(u8, "deny");
        errdefer alloc.free(defaults_inbound);
        var defaults_outbound: []const u8 = try alloc.dupe(u8, "allow");
        errdefer alloc.free(defaults_outbound);
        
        var ipv6: ?Ipv6Policy = null;

        var lines = std.mem.splitScalar(u8, content, '\n');
        var current_section: enum { none, sourceSets, services, rules, defaults, ipv6, ipv6_sourceSets, ipv6_rules } = .none;
        var current_service_name: ?[]const u8 = null;
        var current_service_listeners: std.ArrayList(Listener) = .{ .items = &.{}, .capacity = 0 };
        defer current_service_listeners.deinit(alloc);

        var ipv6_enabled = false;
        var ipv6_sourceSets_map: ?std.StringHashMap([]const []const u8) = null;
        var ipv6_rules_list: std.ArrayList(Rule) = .{ .items = &.{}, .capacity = 0 };

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.startsWith(u8, trimmed, "sourceSets:")) {
                if (current_section == .ipv6) {
                    current_section = .ipv6_sourceSets;
                    if (ipv6_sourceSets_map == null) {
                        ipv6_sourceSets_map = std.StringHashMap([]const []const u8).init(alloc);
                    }
                } else {
                    current_section = .sourceSets;
                }
                continue;
            } else if (std.mem.startsWith(u8, trimmed, "services:")) {
                current_section = .services;
                continue;
            } else if (std.mem.startsWith(u8, trimmed, "rules:")) {
                if (current_section == .ipv6 or current_section == .ipv6_sourceSets) {
                    current_section = .ipv6_rules;
                } else {
                    current_section = .rules;
                }
                continue;
            } else if (std.mem.startsWith(u8, trimmed, "defaults:")) {
                current_section = .defaults;
                continue;
            } else if (std.mem.startsWith(u8, trimmed, "ipv6:")) {
                current_section = .ipv6;
                continue;
            }

            switch (current_section) {
                .sourceSets => {
                    if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                        const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
                        const value_str = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");

                        if (std.mem.startsWith(u8, value_str, "[") and std.mem.endsWith(u8, value_str, "]")) {
                            const inner = std.mem.trim(u8, value_str[1 .. value_str.len - 1], " \t");
                            var values: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
                            var value_parts = std.mem.splitScalar(u8, inner, ',');
                            while (value_parts.next()) |part| {
                                const trimmed_part = std.mem.trim(u8, part, " \t\"");
                                if (trimmed_part.len > 0) {
                                    const owned = try alloc.dupe(u8, trimmed_part);
                                    try values.append(alloc, owned);
                                }
                            }
                            const owned_key = try alloc.dupe(u8, key);
                            try sourceSets.put(owned_key, try values.toOwnedSlice(alloc));
                        }
                    }
                },
                .services => {
                    if (std.mem.indexOf(u8, trimmed, "listeners:")) |_| {
                        if (current_service_name) |name| {
                            const owned_name = try alloc.dupe(u8, name);
                            try services.put(owned_name, .{ .listeners = try current_service_listeners.toOwnedSlice(alloc) });
                        }
                        current_service_listeners.clearRetainingCapacity();
                        current_service_name = null;
                    } else if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                        if (!std.mem.startsWith(u8, trimmed, "-")) {
                            const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
                            current_service_name = key;
                        }
                    } else if (std.mem.startsWith(u8, trimmed, "-")) {
                        if (std.mem.indexOf(u8, trimmed, "{")) |start_brace| {
                            if (std.mem.indexOf(u8, trimmed, "}")) |end_brace| {
                                const obj_str = std.mem.trim(u8, trimmed[start_brace + 1 .. end_brace], " \t");
                                var port: ?u16 = null;
                                var proto: ?[]const u8 = null;

                                var obj_parts = std.mem.splitScalar(u8, obj_str, ',');
                                while (obj_parts.next()) |part| {
                                    const trimmed_part = std.mem.trim(u8, part, " \t");
                                    if (std.mem.indexOf(u8, trimmed_part, ":")) |part_colon| {
                                        const k = std.mem.trim(u8, trimmed_part[0..part_colon], " \t");
                                        const v = std.mem.trim(u8, trimmed_part[part_colon + 1 ..], " \t");
                                        if (std.mem.eql(u8, k, "port")) {
                                            port = try std.fmt.parseInt(u16, v, 10);
                                        } else if (std.mem.eql(u8, k, "proto")) {
                                            proto = try alloc.dupe(u8, v);
                                        }
                                    }
                                }

                                if (port != null and proto != null) {
                                    try current_service_listeners.append(alloc, .{ .port = port.?, .proto = proto.? });
                                }
                            }
                        }
                    }
                },
                .rules => {
                    if (std.mem.startsWith(u8, trimmed, "-")) {
                        if (std.mem.indexOf(u8, trimmed, "allow:")) |allow_idx| {
                            if (std.mem.indexOf(u8, trimmed[allow_idx..], "{")) |start_brace| {
                                const actual_start = allow_idx + start_brace;
                                if (std.mem.indexOf(u8, trimmed[actual_start..], "}")) |end_brace| {
                                    const obj_str = std.mem.trim(u8, trimmed[actual_start + 1 .. actual_start + end_brace], " \t");
                                    var sources: ?[]const []const u8 = null;
                                    var service: ?[]const u8 = null;

                                    var obj_parts = std.mem.splitScalar(u8, obj_str, ',');
                                    while (obj_parts.next()) |part| {
                                        const trimmed_part = std.mem.trim(u8, part, " \t");
                                        if (std.mem.indexOf(u8, trimmed_part, ":")) |part_colon| {
                                            const k = std.mem.trim(u8, trimmed_part[0..part_colon], " \t");
                                            const v = std.mem.trim(u8, trimmed_part[part_colon + 1 ..], " \t");
                                            if (std.mem.eql(u8, k, "sources")) {
                                                if (std.mem.startsWith(u8, v, "[") and std.mem.endsWith(u8, v, "]")) {
                                                    const inner = std.mem.trim(u8, v[1 .. v.len - 1], " \t");
                                                    var src_list: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
                                                    var src_parts = std.mem.splitScalar(u8, inner, ',');
                                                    while (src_parts.next()) |src| {
                                                        const trimmed_src = std.mem.trim(u8, src, " \t\"");
                                                        if (trimmed_src.len > 0) {
                                                            try src_list.append(alloc, try alloc.dupe(u8, trimmed_src));
                                                        }
                                                    }
                                                    sources = try src_list.toOwnedSlice(alloc);
                                                }
                                            } else if (std.mem.eql(u8, k, "service")) {
                                                service = try alloc.dupe(u8, std.mem.trim(u8, v, "\""));
                                            }
                                        }
                                    }

                                    if (sources != null and service != null) {
                                        try rules.append(alloc, .{ .allow = .{ .sources = sources.?, .service = service.? } });
                                    }
                                }
                            }
                        }
                    }
                },
                .defaults => {
                    if (std.mem.indexOf(u8, trimmed, "inbound:")) |_| {
                        if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                            const value = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");
                            alloc.free(defaults_inbound);
                            defaults_inbound = try alloc.dupe(u8, value);
                        }
                    } else if (std.mem.indexOf(u8, trimmed, "outbound:")) |_| {
                        if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                            const value = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");
                            alloc.free(defaults_outbound);
                            defaults_outbound = try alloc.dupe(u8, value);
                        }
                    }
                },
                .ipv6 => {
                    if (std.mem.indexOf(u8, trimmed, "enabled:")) |_| {
                        if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                            const value = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");
                            ipv6_enabled = std.mem.eql(u8, value, "true");
                        }
                    }
                },
                .ipv6_sourceSets => {
                    if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                        const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
                        const value_str = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");

                        if (std.mem.startsWith(u8, value_str, "[") and std.mem.endsWith(u8, value_str, "]")) {
                            const inner = std.mem.trim(u8, value_str[1 .. value_str.len - 1], " \t");
                            var values: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
                            var value_parts = std.mem.splitScalar(u8, inner, ',');
                            while (value_parts.next()) |part| {
                                const trimmed_part = std.mem.trim(u8, part, " \t\"");
                                if (trimmed_part.len > 0) {
                                    const owned = try alloc.dupe(u8, trimmed_part);
                                    try values.append(alloc, owned);
                                }
                            }
                            const owned_key = try alloc.dupe(u8, key);
                            if (ipv6_sourceSets_map) |*map| {
                                try map.put(owned_key, try values.toOwnedSlice(alloc));
                            }
                        }
                    }
                },
                .ipv6_rules => {
                    if (std.mem.startsWith(u8, trimmed, "-")) {
                        if (std.mem.indexOf(u8, trimmed, "allow:")) |allow_idx| {
                            if (std.mem.indexOf(u8, trimmed[allow_idx..], "{")) |start_brace| {
                                const actual_start = allow_idx + start_brace;
                                if (std.mem.indexOf(u8, trimmed[actual_start..], "}")) |end_brace| {
                                    const obj_str = std.mem.trim(u8, trimmed[actual_start + 1 .. actual_start + end_brace], " \t");
                                    var sources: ?[]const []const u8 = null;
                                    var service: ?[]const u8 = null;

                                    var obj_parts = std.mem.splitScalar(u8, obj_str, ',');
                                    while (obj_parts.next()) |part| {
                                        const trimmed_part = std.mem.trim(u8, part, " \t");
                                        if (std.mem.indexOf(u8, trimmed_part, ":")) |part_colon| {
                                            const k = std.mem.trim(u8, trimmed_part[0..part_colon], " \t");
                                            const v = std.mem.trim(u8, trimmed_part[part_colon + 1 ..], " \t");
                                            if (std.mem.eql(u8, k, "sources")) {
                                                if (std.mem.startsWith(u8, v, "[") and std.mem.endsWith(u8, v, "]")) {
                                                    const inner = std.mem.trim(u8, v[1 .. v.len - 1], " \t");
                                                    var src_list: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
                                                    var src_parts = std.mem.splitScalar(u8, inner, ',');
                                                    while (src_parts.next()) |src| {
                                                        const trimmed_src = std.mem.trim(u8, src, " \t\"");
                                                        if (trimmed_src.len > 0) {
                                                            try src_list.append(alloc, try alloc.dupe(u8, trimmed_src));
                                                        }
                                                    }
                                                    sources = try src_list.toOwnedSlice(alloc);
                                                }
                                            } else if (std.mem.eql(u8, k, "service")) {
                                                service = try alloc.dupe(u8, std.mem.trim(u8, v, "\""));
                                            }
                                        }
                                    }

                                    if (sources != null and service != null) {
                                        try ipv6_rules_list.append(alloc, .{ .allow = .{ .sources = sources.?, .service = service.? } });
                                    }
                                }
                            }
                        }
                    }
                },
                .none => {},
            }
        }

        if (current_service_name) |name| {
            const owned_name = try alloc.dupe(u8, name);
            try services.put(owned_name, .{ .listeners = try current_service_listeners.toOwnedSlice(alloc) });
        }

        if (ipv6_enabled) {
            const ipv6_rules_slice = if (ipv6_rules_list.items.len > 0) try ipv6_rules_list.toOwnedSlice(alloc) else null;
            ipv6 = .{
                .enabled = true,
                .sourceSets = ipv6_sourceSets_map,
                .rules = ipv6_rules_slice,
            };
        }

        return Policy{
            .sourceSets = sourceSets,
            .services = services,
            .rules = try rules.toOwnedSlice(alloc),
            .defaults = .{
                .inbound = defaults_inbound,
                .outbound = defaults_outbound,
            },
            .ipv6 = ipv6,
        };
    }
};
