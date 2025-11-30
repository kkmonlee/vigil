// Vigil Agent: Unprivileged process that compiles firewall policies and coordinates with privileged helper.
// Architecture: Agent parses YAML policies, compiles to nftables syntax, sends to helper via Unix socket,
// and monitors network flows via netfilter conntrack for audit logging.
const std = @import("std");
const protocol = @import("common/protocol.zig");
const policy = @import("policy.zig");
const compiler = @import("compiler.zig");
const datastore = @import("datastore.zig");
const observer = @import("observer.zig");

const alloc = std.heap.page_allocator;

// Loads policy from disk, compiles to nftables ruleset, and applies via privileged helper
fn applyLatestPolicy() !void {
    var p = try policy.Policy.loadFromFile(alloc, "config/policy.yml");
    defer {
        p.sourceSets.deinit();
        p.services.deinit();
        alloc.free(p.rules);
        alloc.free(p.defaults.inbound);
        alloc.free(p.defaults.outbound);
        if (p.ipv6) |*ipv6| {
            if (ipv6.sourceSets) |*sets| sets.deinit();
            if (ipv6.rules) |rules| alloc.free(rules);
        }
    }
    std.log.info("Policy loaded successfully.", .{});

fn applyLatestPolicy(policy_path: []const u8) !void {
    const nft_script = try compilePolicyToNft(policy_path);
    defer alloc.free(nft_script);

    std.log.debug("Compiled nftables script:\n---\n{s}\n---", .{nft_script});

    const sock_addr = try std.net.Address.initUnix(protocol.SOCKET_PATH);
    const stream = try std.net.connectUnixSocket(&sock_addr.un.path);
    defer stream.close();

    std.log.info("Connected to helper, sending {d} bytes of rules.", .{nft_script.len});
    _ = try stream.writeAll(nft_script);

    var response_buf: [8]u8 = undefined;
    const n = try stream.read(&response_buf);

    if (n == 0) {
        std.log.err("Helper closed connection without response", .{});
        return error.HelperNoResponse;
    }

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

    var ds = try datastore.Datastore.init(alloc);
    defer ds.deinit();

    // Start observer thread for netfilter conntrack monitoring (Linux only)
    const observer_thread = observer.start(&ds) catch |err| {
        std.log.warn("Observer failed to start: {s}", .{@errorName(err)});
        return err;
    };

    std.log.info("Agent is running. Press Ctrl-C to stop.", .{});

    // Atomic flag for signal-safe shutdown coordination
    var stop_flag: u8 = 0;
    global_stop_flag = &stop_flag;

    const act = std.posix.Sigaction{
        .handler = .{ .handler = @ptrCast(&sigHandlerWrapper) },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    // Main event loop - sleep until signal received
    while (@atomicLoad(u8, &stop_flag, .acquire) == 0) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }

    std.log.info("Shutdown signal received. Cleaning up...", .{});

    // Observer thread will terminate when process exits (daemon thread)
    // For production, implement graceful observer shutdown via context.should_stop
    observer_thread.detach();
}

// Global pointer for signal handler to access stop flag (signal-safe pattern)
var global_stop_flag: ?*u8 = null;

// Signal handler wrapper - must be async-signal-safe
fn sigHandlerWrapper(sig: c_int) callconv(.c) void {
    _ = sig;
    if (global_stop_flag) |flag| {
        @atomicStore(u8, flag, 1, .release);
    }
}
