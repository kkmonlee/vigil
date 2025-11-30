const std = @import("std");
const protocol = @import("common/protocol.zig");
const policy = @import("policy.zig");
const compiler = @import("compiler.zig");
const datastore = @import("datastore.zig");
const observer = @import("observer.zig");

const alloc = std.heap.page_allocator;

fn applyLatestPolicy() !void {
    var p = try policy.Policy.loadFromFile(alloc, "config/policy.yml");
    defer p.sourceSets.deinit();
    defer p.services.deinit();
    std.log.info("Policy loaded successfully.", .{});

    const nft_script = try compiler.compile(p, alloc);
    defer alloc.free(nft_script);

    std.log.debug("Compiled nftables script:\n---\n{s}\n---", .{nft_script});

    const sock_addr = try std.net.Address.initUnix(protocol.SOCKET_PATH);
    const stream = try std.net.connectUnixSocket(&sock_addr.un.path);
    defer stream.close();

    std.log.info("Connected to helper, sending {d} bytes of rules.", .{nft_script.len});
    _ = try stream.writeAll(nft_script);

    var response_buf: [4]u8 = undefined;
    const n = try stream.read(&response_buf);

    if (!std.mem.eql(u8, response_buf[0..n], "OK") and !std.mem.eql(u8, response_buf[0..n], "FAIL")) {
        std.log.err("Unexpected response from helper: {s}", .{response_buf[0..n]});
        return error.InvalidHelperResponse;
    }

    if (std.mem.eql(u8, response_buf[0..n], "OK")) {
        std.log.info("Helper reported success applying policy.", .{});
    } else {
        std.log.err("Helper reported failure applying policy.", .{});
        return error.HelperFailed;
    }
}

pub fn main() !void {
    std.log.info("Vigil Agent starting...", .{});

    applyLatestPolicy() catch |err| {
        std.log.err("Could not apply initial policy: {s}", .{@errorName(err)});
        return err;
    };

    var ds = try datastore.Datastore.init(alloc);
    defer ds.deinit();

    const observer_thread = observer.start(&ds) catch |err| {
        std.log.warn("Observer failed to start: {s}", .{@errorName(err)});
        return err;
    };

    std.log.info("Agent is running. Press Ctrl-C to stop.", .{});

    // use a semaphore to wait for a SIGINT or SIGTERM
    var stop_flag: u8 = 0;
    global_stop_flag = &stop_flag;

    const act = std.posix.Sigaction{
        .handler = .{ .handler = @ptrCast(&sigHandlerWrapper) },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    while (@atomicLoad(u8, &stop_flag, .acquire) == 0) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }

    // the observer thread should and will exit when the main process dies
    // or send a signal to gracefully kill it
    std.log.info("Shutdown signal received. Cleaning up...", .{});
    _ = observer_thread;
}

var global_stop_flag: ?*u8 = null;

fn sigHandlerWrapper(sig: c_int) callconv(.c) void {
    _ = sig;
    if (global_stop_flag) |flag| {
        @atomicStore(u8, flag, 1, .release);
    }
}

fn sigHandler(context: ?*anyopaque, signum: u8, siginfo: *const std.posix.siginfo_t) void {
    _ = signum;
    _ = siginfo;
    if (context) |ctx| {
        const flag = @as(*u8, @ptrCast(@alignCast(ctx)));
        @atomicStore(u8, flag, 1, .release);
    }
}
