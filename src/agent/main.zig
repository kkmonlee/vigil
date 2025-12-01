// Vigil Agent: Unprivileged process that compiles firewall policies and coordinates with privileged helper.
// Architecture: Agent parses YAML policies, compiles to nftables syntax, sends to helper via Unix socket,
// and monitors network flows via netfilter conntrack for audit logging.
const std = @import("std");
const policy = @import("policy.zig");
const compiler = @import("compiler.zig");
const datastore = @import("datastore.zig");
const observer = @import("observer.zig");

const VERSION = "0.1.0";

fn compilePolicyToNft(alloc: std.mem.Allocator, policy_path: []const u8) ![]const u8 {
    var pol = try policy.Policy.loadFromFile(alloc, policy_path);
    defer {
        pol.sourceSets.deinit();
        pol.services.deinit();
        alloc.free(pol.rules);
        alloc.free(pol.defaults.inbound);
        alloc.free(pol.defaults.outbound);
        if (pol.ipv6) |*ipv6| {
            if (ipv6.sourceSets) |*sets| sets.deinit();
            if (ipv6.rules) |rules| alloc.free(rules);
        }
    }

    const script = try compiler.compile(pol, alloc);
    defer alloc.free(script);

    return script;
}

fn applyLatestPolicy(alloc: std.mem.Allocator, policy_path: []const u8) !void {
    const script = try compilePolicyToNft(alloc, policy_path);
    defer alloc.free(script);

    const socket_path = "/tmp/vigil.sock";
    const stream = std.net.connectUnixSocket(socket_path) catch |err| {
        std.log.err("Failed to connect to helper at {s}: {}", .{ socket_path, err });
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
        std.log.info("Policy applied successfully", .{});
    } else {
        std.log.err("Failed to apply policy", .{});
        return error.PolicyApplicationFailed;
    }
}

fn runDryRun(alloc: std.mem.Allocator, policy_path: []const u8) !void {
    const script = try compilePolicyToNft(alloc, policy_path);
    defer alloc.free(script);

    var child = std.process.Child.init(&[_][]const u8{ "nft", "-c", "-f", "-" }, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();

    if (child.stdin) |stdin| {
        try stdin.writeAll(script);
        stdin.close();
        child.stdin = null;
    }

    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code == 0) {
                std.debug.print("Dry-run validation passed.\n", .{});
            } else {
                std.debug.print("Dry-run validation failed with exit code {d}\n", .{code});
            }
        },
        else => {
            std.debug.print("nft process terminated unexpectedly\n", .{});
        },
    }
}

var should_exit = std.atomic.Value(bool).init(false);

fn handleSignal(sig: i32) callconv(.c) void {
    _ = sig;
    should_exit.store(true, .release);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    _ = args.skip();

    var dry_run_requested = false;
    var policy_path: []const u8 = "config/policy.yml";
    var disable_observer = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run_requested = true;
        } else if (std.mem.eql(u8, arg, "--policy")) {
            if (args.next()) |path| {
                policy_path = path;
            } else {
                std.debug.print("Error: --policy requires a path argument\n", .{});
                return error.MissingPolicyPath;
            }
        } else if (std.mem.eql(u8, arg, "--no-observer")) {
            disable_observer = true;
        } else {
            alloc.free(arg);
        }
    }

    if (dry_run_requested) {
        try runDryRun(alloc, policy_path);
        return;
    }

    const sig_action = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sig_action, null);
    std.posix.sigaction(std.posix.SIG.INT, &sig_action, null);

    var ds = try datastore.Datastore.init(alloc);
    defer ds.deinit();

    var observer_thread: ?std.Thread = null;
    if (!disable_observer) {
        if (observer.start(&ds)) |thread| {
            observer_thread = thread;
        } else |err| {
            std.log.warn("Failed to start observer: {}", .{err});
        }
    }

    std.log.info("Applying policy from {s}...", .{policy_path});
    applyLatestPolicy(alloc, policy_path) catch |err| {
        std.log.err("Failed to apply policy: {}", .{err});
    };

    std.log.info("Vigil agent running. Press Ctrl+C to exit.", .{});
    while (!should_exit.load(.acquire)) {
        std.Thread.sleep(std.time.ns_per_s);
    }

    std.log.info("Shutting down...", .{});
    if (observer_thread) |thread| {
        thread.join();
    }

    std.log.info("Vigil agent stopped.", .{});
}
