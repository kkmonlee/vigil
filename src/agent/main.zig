const std = @import("std");
const protocol = @import("common/protocol.zig");
const policy = @import("policy.zig");
const compiler = @import("compiler.zig");
const datastore = @import("datastore.zig");
const observer = @import("observer.zig");

const alloc = std.heap.page_allocator;

fn compilePolicyToNft(policy_path: []const u8) ![]const u8 {
    var p = try policy.Policy.loadFromFile(alloc, policy_path);
    defer p.sourceSets.deinit();
    defer p.services.deinit();

    return try compiler.compile(p, alloc);
}

fn applyLatestPolicy(policy_path: []const u8) !void {
    const nft_script = try compilePolicyToNft(policy_path);
    defer alloc.free(nft_script);

    std.log.debug("Compiled nftables script:\n---\n{s}\n---", .{nft_script});

    const sock_addr = try std.net.Address.initUnix(protocol.SOCKET_PATH);
    var stream = try std.net.connectStream(sock_addr, .{});
    defer stream.close();

    std.log.info("Connected to helper, sending {d} bytes of rules.", .{nft_script.len});
    try stream.writer().writeAll(nft_script);

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

fn runDryRun(policy_path: []const u8) !void {
    std.log.info("Running dry-run: compiling policy and validating with nft -c", .{});
    const nft_script = try compilePolicyToNft(policy_path);
    defer alloc.free(nft_script);

    std.debug.print("Compiled nftables script:\n---\n{s}\n---\n", .{nft_script});

    var child = std.ChildProcess.init(&[_][]const u8{ "nft", "-c", "-f", "-" }, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();

    if (child.stdin) |stdin| {
        try stdin.writer().writeAll(nft_script);
        stdin.close();
    }

    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code == 0) {
                std.log.info("Dry-run validation succeeded (nft -c).", .{});
            } else {
                std.log.err("nft -c exited with code {d}", .{code});
                return error.NftValidationFailed;
            }
        },
        else => {
            std.log.err("nft -c did not exit cleanly", .{});
            return error.NftValidationFailed;
        },
    }
}

pub fn main() !void {
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    var dry_run = false;
    var policy_path: []const u8 = "config/policy.yml";
    var observer_enabled = true;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "--policy")) {
            if (i + 1 >= args.len) {
                std.log.err("--policy requires a path argument", .{});
                return error.InvalidArgument;
            }
            policy_path = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--no-observer")) {
            observer_enabled = false;
        } else {
            std.log.err("Unknown argument: {s}", .{arg});
            return error.InvalidArgument;
        }
    }

    if (dry_run) {
        try runDryRun(policy_path);
        return;
    }

    std.log.info("Vigil Agent starting...", .{});

    applyLatestPolicy(policy_path) catch |err| {
        std.log.err("Could not apply initial policy: {s}", .{@errorName(err)});
        return err;
    };

    var ds_storage: datastore.Datastore = undefined;
    var started_observer = false;
    var observer_thread: ?std.Thread = null;

    if (observer_enabled) {
        ds_storage = try datastore.Datastore.init(alloc);
        errdefer ds_storage.deinit();
        observer_thread = try observer.start(&ds_storage);
        started_observer = true;
    } else {
        std.log.warn("Observer disabled via --no-observer; flow logging will be skipped.", .{});
    }

    std.log.info("Agent is running. Press Ctrl-C to stop.", .{});

    // use a semaphore to wait for a SIGINT or SIGTERM
    var stop_flag: u8 = 0;
    std.os.setPosixSignalHandler(.INT, sigHandler, &stop_flag);
    std.os.setPosixSignalHandler(.TERM, sigHandler, &stop_flag);

    while (@atomicLoad(u8, &stop_flag, .Acquire) == 0) {
        std.time.sleep(1 * std.time.ns_per_s);
    }

    // the observer thread should and will exit when the main process dies
    // or send a signal to gracefully kill it
    std.log.info("Shutdown signal received. Cleaning up...", .{});

    if (started_observer) {
        ds_storage.deinit();
        _ = observer_thread;
    }
}

fn sigHandler(context: ?*anyopaque, signum: u8, siginfo: *const std.os.siginfo_t) void {
    _ = signum;
    _ = siginfo;
    if (context) |ctx| {
        const flag = @as(*u8, @ptrCast(@alignCast(ctx)));
        @atomicStore(u8, flag, 1, .Release);
    }
}
