const std = @import("std");
const builtin = @import("builtin");
const policy = @import("policy.zig");
const compiler = @import("compiler.zig");
const datastore = @import("datastore.zig");
const observer = @import("observer.zig");
const watcher = @import("watcher.zig");
const health = @import("health.zig");

const VERSION = "0.2.0";
const SOCKET_PATH = "/tmp/vigil.sock";

const Config = struct {
    policy_path: []const u8 = "config/policy.yml",
    dry_run: bool = false,
    disable_observer: bool = false,
    enable_watcher: bool = false,
    enable_health_api: bool = true,
    validate_only: bool = false,
    show_compiled: bool = false,
    retention_days: u32 = 30,
};

fn parseArgs(alloc: std.mem.Allocator) !Config {
    var config = Config{};
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    _ = args.skip();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dry-run")) {
            config.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--policy")) {
            if (args.next()) |path| {
                config.policy_path = path;
            } else {
                std.debug.print("Error: --policy requires a path argument\n", .{});
                return error.MissingPolicyPath;
            }
        } else if (std.mem.eql(u8, arg, "--no-observer")) {
            config.disable_observer = true;
        } else if (std.mem.eql(u8, arg, "--watch")) {
            config.enable_watcher = true;
        } else if (std.mem.eql(u8, arg, "--no-health-api")) {
            config.enable_health_api = false;
        } else if (std.mem.eql(u8, arg, "--validate")) {
            config.validate_only = true;
        } else if (std.mem.eql(u8, arg, "--show-compiled")) {
            config.show_compiled = true;
        } else if (std.mem.eql(u8, arg, "--retention-days")) {
            if (args.next()) |days_str| {
                config.retention_days = std.fmt.parseInt(u32, days_str, 10) catch 30;
            }
        } else if (std.mem.eql(u8, arg, "--version")) {
            std.debug.print("Vigil Agent v{s}\n", .{VERSION});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        }
    }

    return config;
}

fn printHelp() void {
    std.debug.print(
        \\Vigil Agent v{s}
        \\
        \\Usage: agent [OPTIONS]
        \\
        \\Options:
        \\  --policy <path>      Path to policy.yml (default: config/policy.yml)
        \\  --dry-run            Validate policy with nft -c without applying
        \\  --validate           Validate policy syntax only, do not apply
        \\  --show-compiled      Print compiled nftables script and exit
        \\  --no-observer        Disable conntrack flow observer
        \\  --watch              Watch policy file for changes and auto-reload
        \\  --no-health-api      Disable health check API
        \\  --retention-days <n> Flow data retention period (default: 30)
        \\  --version            Show version and exit
        \\  --help               Show this help
        \\
    , .{VERSION});
}

fn loadAndValidatePolicy(alloc: std.mem.Allocator, policy_path: []const u8) !policy.Policy {
    var pol = try policy.Policy.loadFromFile(alloc, policy_path);
    errdefer {
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

    try pol.validate();
    return pol;
}

fn compilePolicyToNft(alloc: std.mem.Allocator, policy_path: []const u8) ![]const u8 {
    var pol = try loadAndValidatePolicy(alloc, policy_path);
    defer pol.deinit(alloc);

    return try compiler.compile(pol, alloc);
}

fn applyLatestPolicy(alloc: std.mem.Allocator, policy_path: []const u8) !void {
    const script = try compilePolicyToNft(alloc, policy_path);
    defer alloc.free(script);

    const stream = std.net.connectUnixSocket(SOCKET_PATH) catch |err| {
        std.log.err("Failed to connect to helper at {s}: {}", .{ SOCKET_PATH, err });
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

    const config = try parseArgs(alloc);

    std.log.info("Vigil Agent v{s} starting...", .{VERSION});

    if (config.validate_only) {
        var pol = loadAndValidatePolicy(alloc, config.policy_path) catch |err| {
            std.debug.print("Policy validation failed: {}\n", .{err});
            std.process.exit(1);
        };
        pol.deinit(alloc);
        std.debug.print("Policy validation passed.\n", .{});
        return;
    }

    if (config.show_compiled) {
        const script = compilePolicyToNft(alloc, config.policy_path) catch |err| {
            std.debug.print("Failed to compile policy: {}\n", .{err});
            std.process.exit(1);
        };
        defer alloc.free(script);
        std.debug.print("{s}", .{script});
        return;
    }

    if (config.dry_run) {
        try runDryRun(alloc, config.policy_path);
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

    var health_api: ?health.HealthApi = null;
    if (config.enable_health_api) {
        health_api = try health.HealthApi.init(alloc, &ds, config.policy_path);
        try health_api.?.start();
    }
    defer if (health_api) |*api| api.deinit();

    var observer_thread: ?std.Thread = null;
    if (!config.disable_observer) {
        if (observer.start(&ds)) |thread| {
            observer_thread = thread;
            if (health_api) |*api| api.setObserverRunning(true);
        } else |err| {
            std.log.warn("Failed to start observer: {}", .{err});
        }
    }

    var policy_watcher: ?watcher.PolicyWatcher = null;
    if (config.enable_watcher and builtin.os.tag == .linux) {
        policy_watcher = try watcher.PolicyWatcher.init(alloc, config.policy_path, SOCKET_PATH);
        try policy_watcher.?.start();
    }
    defer if (policy_watcher) |*w| w.deinit();

    std.log.info("Applying policy from {s}...", .{config.policy_path});
    applyLatestPolicy(alloc, config.policy_path) catch |err| {
        std.log.err("Failed to apply policy: {}", .{err});
    };

    if (health_api) |*api| api.setPolicyLoaded(true);

    std.log.info("Vigil agent running. Press Ctrl+C to exit.", .{});

    var last_prune: i64 = std.time.timestamp();
    while (!should_exit.load(.acquire)) {
        std.Thread.sleep(std.time.ns_per_s);

        const now = std.time.timestamp();
        if (now - last_prune > 3600) {
            last_prune = now;
            const pruned = ds.pruneOldFlows(config.retention_days) catch 0;
            if (pruned > 0) {
                std.log.info("Pruned {d} old flow records", .{pruned});
            }
        }
    }

    std.log.info("Shutting down...", .{});

    if (policy_watcher) |*w| {
        w.stop();
    }

    if (health_api) |*api| {
        api.stop();
    }

    if (observer_thread) |thread| {
        thread.join();
    }

    std.log.info("Vigil agent stopped.", .{});
}
