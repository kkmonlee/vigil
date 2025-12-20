const std = @import("std");
const builtin = @import("builtin");
const policy = @import("policy.zig");
const compiler = @import("compiler.zig");

const c = if (builtin.os.tag == .linux) @cImport({
    @cInclude("sys/inotify.h");
    @cInclude("unistd.h");
    @cInclude("poll.h");
}) else struct {};

const INOTIFY_EVENT_SIZE = if (builtin.os.tag == .linux) @sizeOf(c.inotify_event) else 0;
const INOTIFY_BUF_LEN = 1024 * (INOTIFY_EVENT_SIZE + 16);

pub const ReloadCallback = *const fn ([]const u8) void;

const WatcherContext = struct {
    allocator: std.mem.Allocator,
    policy_path: []const u8,
    socket_path: []const u8,
    should_stop: *std.atomic.Value(bool),
    on_reload: ?ReloadCallback,
};

pub const PolicyWatcher = struct {
    allocator: std.mem.Allocator,
    policy_path: []const u8,
    socket_path: []const u8,
    thread: ?std.Thread = null,
    should_stop: *std.atomic.Value(bool),
    on_reload: ?ReloadCallback = null,

    pub fn init(allocator: std.mem.Allocator, policy_path: []const u8, socket_path: []const u8) !PolicyWatcher {
        const should_stop = try allocator.create(std.atomic.Value(bool));
        should_stop.* = std.atomic.Value(bool).init(false);

        return PolicyWatcher{
            .allocator = allocator,
            .policy_path = try allocator.dupe(u8, policy_path),
            .socket_path = try allocator.dupe(u8, socket_path),
            .should_stop = should_stop,
        };
    }

    pub fn deinit(self: *PolicyWatcher) void {
        self.stop();
        self.allocator.free(self.policy_path);
        self.allocator.free(self.socket_path);
        self.allocator.destroy(self.should_stop);
    }

    pub fn start(self: *PolicyWatcher) !void {
        if (builtin.os.tag != .linux) {
            std.log.warn("Policy watcher only supported on Linux", .{});
            return error.WatcherNotSupported;
        }

        if (self.thread != null) {
            return error.AlreadyRunning;
        }

        const ctx = try self.allocator.create(WatcherContext);
        ctx.* = .{
            .allocator = self.allocator,
            .policy_path = self.policy_path,
            .socket_path = self.socket_path,
            .should_stop = self.should_stop,
            .on_reload = self.on_reload,
        };

        self.thread = try std.Thread.spawn(.{}, watchLoop, .{ctx});
    }

    pub fn stop(self: *PolicyWatcher) void {
        self.should_stop.store(true, .release);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    pub fn setReloadCallback(self: *PolicyWatcher, callback: ReloadCallback) void {
        self.on_reload = callback;
    }
};

fn watchLoop(ctx: *WatcherContext) void {
    if (builtin.os.tag != .linux) return;

    defer ctx.allocator.destroy(ctx);

    const ifd = c.inotify_init1(c.IN_NONBLOCK);
    if (ifd < 0) {
        std.log.err("Failed to initialize inotify", .{});
        return;
    }
    defer _ = c.close(ifd);

    const dir_path = std.fs.path.dirname(ctx.policy_path) orelse ".";
    const dir_path_z = std.mem.span(@as([*:0]const u8, @ptrCast(dir_path.ptr)));

    const wd = c.inotify_add_watch(ifd, dir_path_z.ptr, c.IN_MODIFY | c.IN_CLOSE_WRITE | c.IN_MOVED_TO);
    if (wd < 0) {
        std.log.err("Failed to add inotify watch for {s}", .{dir_path});
        return;
    }
    defer _ = c.inotify_rm_watch(ifd, wd);

    std.log.info("Policy watcher started for {s}", .{ctx.policy_path});

    var buf: [INOTIFY_BUF_LEN]u8 = undefined;
    var pfd = [_]c.pollfd{.{ .fd = ifd, .events = c.POLLIN, .revents = 0 }};

    const filename = std.fs.path.basename(ctx.policy_path);
    var last_reload: i64 = 0;

    while (!ctx.should_stop.load(.acquire)) {
        const poll_result = c.poll(&pfd, 1, 1000);
        if (poll_result < 0) {
            if (std.posix.errno(-1) == .INTR) continue;
            std.log.err("Poll error", .{});
            break;
        }

        if (poll_result == 0) continue;

        const len = c.read(ifd, &buf, INOTIFY_BUF_LEN);
        if (len < 0) {
            if (std.posix.errno(-1) == .AGAIN) continue;
            std.log.err("Read error", .{});
            break;
        }

        var i: usize = 0;
        while (i < @as(usize, @intCast(len))) {
            const event = @as(*const c.inotify_event, @ptrCast(@alignCast(&buf[i])));

            if (event.len > 0) {
                const name_ptr = @as([*]const u8, @ptrCast(&buf[i + INOTIFY_EVENT_SIZE]));
                const name = std.mem.sliceTo(name_ptr, 0);

                if (std.mem.eql(u8, name, filename)) {
                    const now = std.time.timestamp();
                    if (now - last_reload >= 2) {
                        last_reload = now;
                        std.log.info("Policy file changed, reloading...", .{});

                        std.Thread.sleep(100 * std.time.ns_per_ms);

                        reloadPolicy(ctx) catch |err| {
                            std.log.err("Failed to reload policy: {}", .{err});
                        };

                        if (ctx.on_reload) |callback| {
                            callback(ctx.policy_path);
                        }
                    }
                }
            }

            i += INOTIFY_EVENT_SIZE + event.len;
        }
    }

    std.log.info("Policy watcher stopped", .{});
}

fn reloadPolicy(ctx: *WatcherContext) !void {
    var pol = try policy.Policy.loadFromFile(ctx.allocator, ctx.policy_path);
    defer {
        pol.sourceSets.deinit();
        pol.services.deinit();
        ctx.allocator.free(pol.rules);
        ctx.allocator.free(pol.defaults.inbound);
        ctx.allocator.free(pol.defaults.outbound);
        if (pol.ipv6) |*ipv6| {
            if (ipv6.sourceSets) |*sets| sets.deinit();
            if (ipv6.rules) |rules| ctx.allocator.free(rules);
        }
    }

    try pol.validate();

    const script = try compiler.compile(pol, ctx.allocator);
    defer ctx.allocator.free(script);

    const stream = std.net.connectUnixSocket(ctx.socket_path) catch |err| {
        std.log.err("Failed to connect to helper: {}", .{err});
        return err;
    };
    defer stream.close();

    const len: u32 = @intCast(script.len);
    try stream.writeAll(std.mem.asBytes(&len));
    try stream.writeAll(script);

    var resp: [8]u8 = undefined;
    const n = try stream.read(&resp);
    if (n == 0) {
        return error.HelperNoResponse;
    }

    const response_buf = resp[0..n];
    if (std.mem.eql(u8, response_buf, "OK")) {
        std.log.info("Policy reloaded and applied successfully", .{});
    } else {
        std.log.err("Failed to apply reloaded policy", .{});
        return error.PolicyApplicationFailed;
    }
}
