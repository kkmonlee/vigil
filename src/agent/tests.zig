const std = @import("std");
const compiler = @import("compiler.zig");
const policy = @import("policy.zig");
const helper_client = @import("helper_client.zig");
const protocol = @import("common/protocol.zig");

test "policy replacement only deletes Vigil's table" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var sources = std.StringHashMap([]const []const u8).init(alloc);
    try sources.put("lan", &.{"192.0.2.0/24"});
    var services = std.StringHashMap(policy.Service).init(alloc);
    try services.put("ssh", .{ .listeners = &.{.{ .port = 22, .proto = "tcp" }} });
    const pol = policy.Policy{
        .sourceSets = sources,
        .services = services,
        .rules = &.{.{ .allow = .{ .sources = &.{"lan"}, .service = "ssh" } }},
        .defaults = .{ .inbound = "deny", .outbound = "allow" },
    };
    const script = try compiler.compile(pol, alloc);
    try std.testing.expect(std.mem.startsWith(u8, script, "add table inet vigilfw\ndelete table inet vigilfw\n\ntable inet vigilfw {\n"));
    try std.testing.expect(std.mem.indexOf(u8, script, "flush ruleset") == null);
    try std.testing.expect(std.mem.indexOf(u8, script, "ip saddr @lan tcp dport @svc_ssh_tcp accept") != null);
}

test "invalid policy cannot produce an empty replacement" {
    const pol = policy.Policy{
        .sourceSets = std.StringHashMap([]const []const u8).init(std.testing.allocator),
        .services = std.StringHashMap(policy.Service).init(std.testing.allocator),
        .rules = &.{},
        .defaults = .{ .inbound = "deny", .outbound = "allow" },
    };
    try std.testing.expectError(error.InvalidPolicy, compiler.compile(pol, std.testing.allocator));
}

test "client rejects invalid lengths before connecting" {
    try std.testing.expectError(error.InvalidRulesetSize, helper_client.apply("/does-not-exist", ""));
    const oversized = try std.testing.allocator.alloc(u8, protocol.MAX_RULESET_SIZE + 1);
    defer std.testing.allocator.free(oversized);
    try std.testing.expectError(error.InvalidRulesetSize, helper_client.apply("/does-not-exist", oversized));
}
