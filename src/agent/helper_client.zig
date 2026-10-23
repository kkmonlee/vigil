const std = @import("std");
const protocol = @import("common/protocol.zig");

pub fn socketPath(alloc: std.mem.Allocator) ![]const u8 {
    const path = std.process.getEnvVarOwned(alloc, "VIGIL_SOCKET_PATH") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return alloc.dupe(u8, protocol.SOCKET_PATH),
        else => return err,
    };
    if (path.len == 0 or !std.fs.path.isAbsolute(path)) {
        alloc.free(path);
        return error.InvalidSocketPath;
    }
    return path;
}

// Frame: big-endian u32 length, then script.
pub fn apply(socket_path: []const u8, script: []const u8) !void {
    if (script.len == 0 or script.len > protocol.MAX_RULESET_SIZE) {
        return error.InvalidRulesetSize;
    }
    const stream = try std.net.connectUnixSocket(socket_path);
    defer stream.close();

    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, &header, @intCast(script.len), .big);
    try stream.writeAll(&header);
    try stream.writeAll(script);

    var response: [2]u8 = undefined;
    if (try stream.readAtLeast(&response, response.len) != response.len) {
        return error.HelperNoResponse;
    }
    if (!std.mem.eql(u8, &response, "OK")) {
        return error.PolicyApplicationFailed;
    }
}
