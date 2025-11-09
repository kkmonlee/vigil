const std = @import("std");
const yaml = @import("yaml");

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

    pub fn loadFromFile(alloc: std.mem.Allocator, path: []const u8) !Policy {
        const content = try std.fs.cwd().readFileAlloc(alloc, path, 1 * 1024 * 1024);
        defer alloc.free(content);

        var tree = try yaml.parser.parse(alloc, content);
        defer tree.deinit();

        if (tree.get("sourceSets") == null or tree.get("services") == null or tree.get("rules") == null) {
            return error.InvalidPolicy;
        }

        return try tree.to(Policy);
    }
};
