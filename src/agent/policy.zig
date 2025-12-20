// Policy parser: Custom YAML subset parser for firewall rule definitions
// Supports IPv4/IPv6 source sets, service definitions with listeners, allow rules, and default policies
// Avoids external dependencies for security-critical configuration parsing
const std = @import("std");

pub const PortRange = struct {
    start: u16,
    end: u16,
};

pub const Listener = struct {
    port: ?u16 = null,
    port_range: ?PortRange = null,
    proto: []const u8,

    pub fn getPortSpec(self: Listener) []const u8 {
        _ = self;
        return "";
    }
};

pub const Service = struct {
    listeners: []const Listener,
};

pub const RateLimit = struct {
    rate: u32,
    unit: []const u8,
    burst: u32,
};

pub const AllowRule = struct {
    sources: []const []const u8,
    service: []const u8,
    rate_limit: ?RateLimit = null,
};

pub const DenyRule = struct {
    sources: []const []const u8,
    service: ?[]const u8 = null,
    log: bool = false,
};

pub const Rule = struct {
    allow: ?AllowRule = null,
    deny: ?DenyRule = null,
};

pub const LoggingConfig = struct {
    enabled: bool = false,
    prefix: []const u8 = "VIGIL_DENY",
    rate_limit: u32 = 5,
    burst: u32 = 10,
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
    logging: LoggingConfig = .{},
    ipv6: ?Ipv6Policy = null,

    pub fn deinit(self: *Policy, alloc: std.mem.Allocator) void {
        var source_iter = self.sourceSets.iterator();
        while (source_iter.next()) |entry| {
            for (entry.value_ptr.*) |v| alloc.free(v);
            alloc.free(entry.value_ptr.*);
            alloc.free(entry.key_ptr.*);
        }
        self.sourceSets.deinit();

        var svc_iter = self.services.iterator();
        while (svc_iter.next()) |entry| {
            for (entry.value_ptr.listeners) |l| {
                alloc.free(l.proto);
            }
            alloc.free(entry.value_ptr.listeners);
            alloc.free(entry.key_ptr.*);
        }
        self.services.deinit();

        for (self.rules) |rule| {
            if (rule.allow) |allow| {
                for (allow.sources) |s| alloc.free(s);
                alloc.free(allow.sources);
                alloc.free(allow.service);
                if (allow.rate_limit) |rl| {
                    alloc.free(rl.unit);
                }
            }
            if (rule.deny) |deny| {
                for (deny.sources) |s| alloc.free(s);
                alloc.free(deny.sources);
                if (deny.service) |svc| alloc.free(svc);
            }
        }
        alloc.free(self.rules);

        alloc.free(self.defaults.inbound);
        alloc.free(self.defaults.outbound);

        if (@intFromPtr(self.logging.prefix.ptr) != @intFromPtr("VIGIL_DENY".ptr)) {
            alloc.free(self.logging.prefix);
        }

        if (self.ipv6) |*ipv6_policy| {
            if (ipv6_policy.sourceSets) |*sets| {
                var v6_iter = sets.iterator();
                while (v6_iter.next()) |entry| {
                    for (entry.value_ptr.*) |v| alloc.free(v);
                    alloc.free(entry.value_ptr.*);
                    alloc.free(entry.key_ptr.*);
                }
                sets.deinit();
            }
            if (ipv6_policy.rules) |rules| {
                for (rules) |rule| {
                    if (rule.allow) |allow| {
                        for (allow.sources) |s| alloc.free(s);
                        alloc.free(allow.sources);
                        alloc.free(allow.service);
                    }
                    if (rule.deny) |deny| {
                        for (deny.sources) |s| alloc.free(s);
                        alloc.free(deny.sources);
                        if (deny.service) |svc| alloc.free(svc);
                    }
                }
                alloc.free(rules);
            }
        }
    }

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

        var defaults_inbound: []const u8 = try alloc.dupe(u8, "deny");
        errdefer alloc.free(defaults_inbound);
        var defaults_outbound: []const u8 = try alloc.dupe(u8, "allow");
        errdefer alloc.free(defaults_outbound);

        var ipv6: ?Ipv6Policy = null;
        var logging_config = LoggingConfig{};

        var lines = std.mem.splitScalar(u8, content, '\n');
        var current_section: enum { none, sourceSets, services, rules, defaults, logging, ipv6, ipv6_sourceSets, ipv6_rules } = .none;
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
            } else if (std.mem.startsWith(u8, trimmed, "logging:")) {
                current_section = .logging;
                continue;
            } else if (std.mem.startsWith(u8, trimmed, "ipv6:")) {
                current_section = .ipv6;
                ipv6_enabled = true; // Enable ipv6 when we encounter the section
                continue;
            }

            switch (current_section) {
                .logging => {
                    if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                        const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
                        const value = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");

                        if (std.mem.eql(u8, key, "enabled")) {
                            logging_config.enabled = std.mem.eql(u8, value, "true");
                        } else if (std.mem.eql(u8, key, "prefix")) {
                            logging_config.prefix = try alloc.dupe(u8, std.mem.trim(u8, value, "\""));
                        } else if (std.mem.eql(u8, key, "rate_limit")) {
                            logging_config.rate_limit = std.fmt.parseInt(u32, value, 10) catch 5;
                        } else if (std.mem.eql(u8, key, "burst")) {
                            logging_config.burst = std.fmt.parseInt(u32, value, 10) catch 10;
                        }
                    }
                },
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
                    if (std.mem.startsWith(u8, trimmed, "-")) {
                        if (std.mem.indexOf(u8, trimmed, "{")) |start_brace| {
                            if (std.mem.indexOf(u8, trimmed, "}")) |end_brace| {
                                const obj_str = std.mem.trim(u8, trimmed[start_brace + 1 .. end_brace], " \t");
                                var port: ?u16 = null;
                                var port_range: ?PortRange = null;
                                var proto: ?[]const u8 = null;

                                var obj_parts = std.mem.splitScalar(u8, obj_str, ',');
                                while (obj_parts.next()) |part| {
                                    const trimmed_part = std.mem.trim(u8, part, " \t");
                                    if (std.mem.indexOf(u8, trimmed_part, ":")) |part_colon| {
                                        const k = std.mem.trim(u8, trimmed_part[0..part_colon], " \t");
                                        const v = std.mem.trim(u8, trimmed_part[part_colon + 1 ..], " \t");
                                        if (std.mem.eql(u8, k, "port")) {
                                            if (std.mem.indexOf(u8, v, "-")) |dash_idx| {
                                                const start_port = std.fmt.parseInt(u16, v[0..dash_idx], 10) catch continue;
                                                const end_port = std.fmt.parseInt(u16, v[dash_idx + 1 ..], 10) catch continue;
                                                port_range = .{ .start = start_port, .end = end_port };
                                            } else {
                                                port = std.fmt.parseInt(u16, v, 10) catch continue;
                                            }
                                        } else if (std.mem.eql(u8, k, "proto")) {
                                            proto = try alloc.dupe(u8, v);
                                        }
                                    }
                                }

                                if (proto != null) {
                                    if (port != null) {
                                        try current_service_listeners.append(alloc, .{ .port = port, .port_range = null, .proto = proto.? });
                                    } else if (port_range != null) {
                                        try current_service_listeners.append(alloc, .{ .port = null, .port_range = port_range, .proto = proto.? });
                                    }
                                }
                            }
                        }
                    } else if (std.mem.indexOf(u8, trimmed, "listeners:") != null) {} else if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                        if (current_service_name) |name| {
                            if (current_service_listeners.items.len > 0) {
                                const owned_name = try alloc.dupe(u8, name);
                                try services.put(owned_name, .{ .listeners = try current_service_listeners.toOwnedSlice(alloc) });
                                current_service_listeners.clearRetainingCapacity();
                            }
                        }
                        const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
                        current_service_name = key;
                    }
                },
                .rules => {
                    if (std.mem.startsWith(u8, trimmed, "-")) {
                        if (std.mem.indexOf(u8, trimmed, "deny:")) |deny_idx| {
                            const rule = try parseDenyRule(alloc, trimmed, deny_idx);
                            if (rule) |r| {
                                try rules.append(alloc, r);
                            }
                        } else if (std.mem.indexOf(u8, trimmed, "allow:")) |allow_idx| {
                            const rule = try parseAllowRule(alloc, trimmed, allow_idx);
                            if (rule) |r| {
                                try rules.append(alloc, r);
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
                        if (std.mem.indexOf(u8, trimmed, "deny:")) |deny_idx| {
                            const rule = try parseDenyRule(alloc, trimmed, deny_idx);
                            if (rule) |r| {
                                try ipv6_rules_list.append(alloc, r);
                            }
                        } else if (std.mem.indexOf(u8, trimmed, "allow:")) |allow_idx| {
                            const rule = try parseAllowRule(alloc, trimmed, allow_idx);
                            if (rule) |r| {
                                try ipv6_rules_list.append(alloc, r);
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
            .logging = logging_config,
            .ipv6 = ipv6,
        };
    }

    fn parseAllowRule(alloc: std.mem.Allocator, trimmed: []const u8, allow_idx: usize) !?Rule {
        const brace_start = std.mem.indexOf(u8, trimmed[allow_idx..], "{") orelse return null;
        const actual_start = allow_idx + brace_start;
        const brace_end = std.mem.lastIndexOf(u8, trimmed, "}") orelse return null;
        const obj_str = std.mem.trim(u8, trimmed[actual_start + 1 .. brace_end], " \t");

        var sources: ?[]const []const u8 = null;
        var service: ?[]const u8 = null;
        var rate_limit: ?RateLimit = null;

        var i: usize = 0;
        while (i < obj_str.len) {
            while (i < obj_str.len and (obj_str[i] == ' ' or obj_str[i] == '\t')) : (i += 1) {}
            if (i >= obj_str.len) break;

            const key_start = i;
            while (i < obj_str.len and obj_str[i] != ':') : (i += 1) {}
            if (i >= obj_str.len) break;
            const key = std.mem.trim(u8, obj_str[key_start..i], " \t");
            i += 1;

            while (i < obj_str.len and (obj_str[i] == ' ' or obj_str[i] == '\t')) : (i += 1) {}
            if (i >= obj_str.len) break;

            var value_end: usize = undefined;
            if (obj_str[i] == '[') {
                const bracket_end = std.mem.indexOf(u8, obj_str[i..], "]") orelse break;
                value_end = i + bracket_end + 1;
            } else if (obj_str[i] == '"') {
                i += 1;
                const quote_end = std.mem.indexOf(u8, obj_str[i..], "\"") orelse break;
                value_end = i + quote_end + 1;
                i -= 1;
            } else {
                const comma_idx = std.mem.indexOf(u8, obj_str[i..], ",");
                if (comma_idx) |idx| {
                    value_end = i + idx;
                } else {
                    value_end = obj_str.len;
                }
            }

            const value = std.mem.trim(u8, obj_str[i..value_end], " \t");
            i = value_end;

            while (i < obj_str.len and (obj_str[i] == ',' or obj_str[i] == ' ' or obj_str[i] == '\t')) : (i += 1) {}

            if (std.mem.eql(u8, key, "sources")) {
                sources = try parseSourcesList(alloc, value);
            } else if (std.mem.eql(u8, key, "service")) {
                service = try alloc.dupe(u8, std.mem.trim(u8, value, "\""));
            } else if (std.mem.eql(u8, key, "rate")) {
                rate_limit = try parseRateLimit(alloc, value);
            }
        }

        if (sources != null and service != null) {
            return Rule{ .allow = .{ .sources = sources.?, .service = service.?, .rate_limit = rate_limit } };
        }
        return null;
    }

    fn parseDenyRule(alloc: std.mem.Allocator, trimmed: []const u8, deny_idx: usize) !?Rule {
        const brace_start = std.mem.indexOf(u8, trimmed[deny_idx..], "{") orelse return null;
        const actual_start = deny_idx + brace_start;
        const brace_end = std.mem.lastIndexOf(u8, trimmed, "}") orelse return null;
        const obj_str = std.mem.trim(u8, trimmed[actual_start + 1 .. brace_end], " \t");

        var sources: ?[]const []const u8 = null;
        var service: ?[]const u8 = null;
        var log_enabled: bool = false;

        var i: usize = 0;
        while (i < obj_str.len) {
            while (i < obj_str.len and (obj_str[i] == ' ' or obj_str[i] == '\t')) : (i += 1) {}
            if (i >= obj_str.len) break;

            const key_start = i;
            while (i < obj_str.len and obj_str[i] != ':') : (i += 1) {}
            if (i >= obj_str.len) break;
            const key = std.mem.trim(u8, obj_str[key_start..i], " \t");
            i += 1;

            while (i < obj_str.len and (obj_str[i] == ' ' or obj_str[i] == '\t')) : (i += 1) {}
            if (i >= obj_str.len) break;

            var value_end: usize = undefined;
            if (obj_str[i] == '[') {
                const bracket_end = std.mem.indexOf(u8, obj_str[i..], "]") orelse break;
                value_end = i + bracket_end + 1;
            } else if (obj_str[i] == '"') {
                i += 1;
                const quote_end = std.mem.indexOf(u8, obj_str[i..], "\"") orelse break;
                value_end = i + quote_end + 1;
                i -= 1;
            } else {
                const comma_idx = std.mem.indexOf(u8, obj_str[i..], ",");
                if (comma_idx) |idx| {
                    value_end = i + idx;
                } else {
                    value_end = obj_str.len;
                }
            }

            const value = std.mem.trim(u8, obj_str[i..value_end], " \t");
            i = value_end;

            while (i < obj_str.len and (obj_str[i] == ',' or obj_str[i] == ' ' or obj_str[i] == '\t')) : (i += 1) {}

            if (std.mem.eql(u8, key, "sources")) {
                sources = try parseSourcesList(alloc, value);
            } else if (std.mem.eql(u8, key, "service")) {
                service = try alloc.dupe(u8, std.mem.trim(u8, value, "\""));
            } else if (std.mem.eql(u8, key, "log")) {
                log_enabled = std.mem.eql(u8, value, "true");
            }
        }

        if (sources != null) {
            return Rule{ .deny = .{ .sources = sources.?, .service = service, .log = log_enabled } };
        }
        return null;
    }

    fn parseSourcesList(alloc: std.mem.Allocator, v: []const u8) !?[]const []const u8 {
        if (!std.mem.startsWith(u8, v, "[") or !std.mem.endsWith(u8, v, "]")) {
            return null;
        }
        const inner = std.mem.trim(u8, v[1 .. v.len - 1], " \t");
        var src_list: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
        var src_parts = std.mem.splitScalar(u8, inner, ',');
        while (src_parts.next()) |src| {
            const trimmed_src = std.mem.trim(u8, src, " \t\"");
            if (trimmed_src.len > 0) {
                try src_list.append(alloc, try alloc.dupe(u8, trimmed_src));
            }
        }
        return try src_list.toOwnedSlice(alloc);
    }

    fn parseRateLimit(alloc: std.mem.Allocator, v: []const u8) !?RateLimit {
        var rate: u32 = 0;
        var unit: []const u8 = "second";
        const burst: u32 = 5;

        const stripped = std.mem.trim(u8, v, "\"");
        var parts = std.mem.splitScalar(u8, stripped, '/');
        if (parts.next()) |rate_str| {
            rate = std.fmt.parseInt(u32, rate_str, 10) catch return null;
        }
        if (parts.next()) |unit_str| {
            unit = try alloc.dupe(u8, unit_str);
        }

        return RateLimit{
            .rate = rate,
            .unit = unit,
            .burst = burst,
        };
    }

    pub fn validate(self: *const Policy) !void {
        if (self.sourceSets.count() == 0) {
            return error.EmptySourceSets;
        }

        if (self.services.count() == 0) {
            return error.EmptyServices;
        }

        var source_iter = self.sourceSets.iterator();
        while (source_iter.next()) |entry| {
            for (entry.value_ptr.*) |cidr| {
                try validateCidr(cidr);
            }
        }

        for (self.rules) |rule| {
            if (rule.allow) |allow| {
                if (self.services.get(allow.service) == null) {
                    return error.UnknownService;
                }
                for (allow.sources) |source| {
                    if (self.sourceSets.get(source) == null) {
                        return error.UnknownSourceSet;
                    }
                }
            }
            if (rule.deny) |deny| {
                if (deny.service) |svc| {
                    if (self.services.get(svc) == null) {
                        return error.UnknownService;
                    }
                }
                for (deny.sources) |source| {
                    if (self.sourceSets.get(source) == null) {
                        return error.UnknownSourceSet;
                    }
                }
            }
        }
    }
};

fn validateCidr(cidr: []const u8) !void {
    if (std.mem.indexOf(u8, cidr, "/")) |slash_idx| {
        const prefix_str = cidr[slash_idx + 1 ..];
        const prefix = std.fmt.parseInt(u8, prefix_str, 10) catch return error.InvalidCidrPrefix;
        if (std.mem.indexOf(u8, cidr[0..slash_idx], ":")) |_| {
            if (prefix > 128) return error.InvalidCidrPrefix;
        } else {
            if (prefix > 32) return error.InvalidCidrPrefix;
        }

        const ip_part = cidr[0..slash_idx];
        if (std.mem.indexOf(u8, ip_part, ":")) |_| {
            var segments: u8 = 0;
            var iter = std.mem.splitScalar(u8, ip_part, ':');
            while (iter.next()) |_| {
                segments += 1;
            }
            if (segments < 2 or segments > 8) return error.InvalidCidrAddress;
        } else {
            var octets: u8 = 0;
            var iter = std.mem.splitScalar(u8, ip_part, '.');
            while (iter.next()) |octet_str| {
                const octet = std.fmt.parseInt(u8, octet_str, 10) catch return error.InvalidCidrAddress;
                _ = octet;
                octets += 1;
            }
            if (octets != 4) return error.InvalidCidrAddress;
        }
    } else {
        return error.InvalidCidrFormat;
    }
}
