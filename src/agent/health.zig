const std = @import("std");
const builtin = @import("builtin");
const datastore = @import("datastore.zig");

const HEALTH_SOCKET_PATH = "/tmp/vigil-health.sock";

pub const HealthStatus = struct {
    version: []const u8,
    uptime_seconds: u64,
    policy_path: []const u8,
    policy_loaded: bool,
    policy_load_time: u64,
    observer_running: bool,
    datastore_connected: bool,
    total_flows_recorded: u64,
    unique_sources_seen: u64,
    unique_destinations_seen: u64,
};

pub const HealthApi = struct {
    allocator: std.mem.Allocator,
    ds: *datastore.Datastore,
    start_time: i64,
    policy_path: []const u8,
    policy_loaded: bool,
    policy_load_time: u64,
    observer_running: bool,
    thread: ?std.Thread = null,
    should_stop: *std.atomic.Value(bool),
    server_fd: ?std.posix.socket_t = null,

    pub fn init(allocator: std.mem.Allocator, ds: *datastore.Datastore, policy_path: []const u8) !HealthApi {
        const should_stop = try allocator.create(std.atomic.Value(bool));
        should_stop.* = std.atomic.Value(bool).init(false);

        return HealthApi{
            .allocator = allocator,
            .ds = ds,
            .start_time = std.time.timestamp(),
            .policy_path = try allocator.dupe(u8, policy_path),
            .policy_loaded = false,
            .policy_load_time = 0,
            .observer_running = false,
            .should_stop = should_stop,
        };
    }

    pub fn deinit(self: *HealthApi) void {
        self.stop();
        self.allocator.free(self.policy_path);
        self.allocator.destroy(self.should_stop);
    }

    pub fn start(self: *HealthApi) !void {
        if (self.thread != null) {
            return error.AlreadyRunning;
        }

        self.thread = try std.Thread.spawn(.{}, serverLoop, .{self});
    }

    pub fn stop(self: *HealthApi) void {
        self.should_stop.store(true, .release);

        if (self.server_fd) |fd| {
            std.posix.close(fd);
            self.server_fd = null;
        }

        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        std.fs.cwd().deleteFile(HEALTH_SOCKET_PATH) catch {};
    }

    pub fn setPolicyLoaded(self: *HealthApi, loaded: bool) void {
        self.policy_loaded = loaded;
        if (loaded) {
            self.policy_load_time = @intCast(std.time.timestamp());
        }
    }

    pub fn setObserverRunning(self: *HealthApi, running: bool) void {
        self.observer_running = running;
    }

    fn serverLoop(self: *HealthApi) void {
        std.fs.cwd().deleteFile(HEALTH_SOCKET_PATH) catch {};

        const addr = std.net.Address.initUnix(HEALTH_SOCKET_PATH) catch |err| {
            std.log.err("Failed to create unix address: {}", .{err});
            return;
        };

        const server = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0) catch |err| {
            std.log.err("Failed to create socket: {}", .{err});
            return;
        };
        self.server_fd = server;

        std.posix.bind(server, &addr.any, addr.getOsSockLen()) catch |err| {
            std.log.err("Failed to bind socket: {}", .{err});
            std.posix.close(server);
            return;
        };

        std.posix.listen(server, 5) catch |err| {
            std.log.err("Failed to listen: {}", .{err});
            std.posix.close(server);
            return;
        };

        std.log.info("Health API listening on {s}", .{HEALTH_SOCKET_PATH});

        while (!self.should_stop.load(.acquire)) {
            var pollfds = [_]std.posix.pollfd{
                .{ .fd = server, .events = std.posix.POLL.IN, .revents = 0 },
            };

            const poll_result = std.posix.poll(&pollfds, 500) catch |err| {
                if (err == error.Interrupted) continue;
                std.log.err("Poll error: {}", .{err});
                break;
            };

            if (poll_result == 0) continue;

            if (pollfds[0].revents & std.posix.POLL.IN != 0) {
                const client = std.posix.accept(server, null, null, 0) catch |err| {
                    std.log.warn("Accept failed: {}", .{err});
                    continue;
                };
                defer std.posix.close(client);

                self.handleClient(client) catch |err| {
                    std.log.warn("Failed to handle client: {}", .{err});
                };
            }
        }

        std.posix.close(server);
        self.server_fd = null;
        std.fs.cwd().deleteFile(HEALTH_SOCKET_PATH) catch {};
        std.log.info("Health API stopped", .{});
    }

    fn handleClient(self: *HealthApi, client: std.posix.socket_t) !void {
        var buf: [256]u8 = undefined;
        const n = try std.posix.read(client, &buf);
        if (n == 0) return;

        const request = std.mem.trim(u8, buf[0..n], " \r\n\t");

        if (std.mem.eql(u8, request, "STATUS")) {
            try self.sendStatus(client);
        } else if (std.mem.eql(u8, request, "STATS")) {
            try self.sendStats(client);
        } else if (std.mem.eql(u8, request, "TOP_SOURCES")) {
            try self.sendTopSources(client);
        } else if (std.mem.eql(u8, request, "TOP_PORTS")) {
            try self.sendTopPorts(client);
        } else if (std.mem.eql(u8, request, "PING")) {
            _ = try std.posix.write(client, "PONG\n");
        } else {
            _ = try std.posix.write(client, "ERROR: Unknown command. Available: STATUS, STATS, TOP_SOURCES, TOP_PORTS, PING\n");
        }
    }

    fn sendStatus(self: *HealthApi, client: std.posix.socket_t) !void {
        const now = std.time.timestamp();
        const uptime: u64 = @intCast(now - self.start_time);

        var response: [1024]u8 = undefined;
        const len = try std.fmt.bufPrint(&response,
            \\STATUS: OK
            \\VERSION: 0.1.0
            \\UPTIME_SECONDS: {d}
            \\POLICY_PATH: {s}
            \\POLICY_LOADED: {s}
            \\POLICY_LOAD_TIME: {d}
            \\OBSERVER_RUNNING: {s}
            \\DATASTORE_CONNECTED: true
            \\
        , .{
            uptime,
            self.policy_path,
            if (self.policy_loaded) "true" else "false",
            self.policy_load_time,
            if (self.observer_running) "true" else "false",
        });

        _ = try std.posix.write(client, len);
    }

    fn sendStats(self: *HealthApi, client: std.posix.socket_t) !void {
        const stats = self.ds.getStats(null, null) catch |err| {
            var error_buf: [128]u8 = undefined;
            const error_msg = std.fmt.bufPrint(&error_buf, "ERROR: Failed to get stats: {}\n", .{err}) catch return;
            _ = try std.posix.write(client, error_msg);
            return;
        };

        var response: [512]u8 = undefined;
        const len = try std.fmt.bufPrint(&response,
            \\TOTAL_FLOWS: {d}
            \\UNIQUE_SOURCES: {d}
            \\UNIQUE_DESTINATIONS: {d}
            \\TCP_FLOWS: {d}
            \\UDP_FLOWS: {d}
            \\ICMP_FLOWS: {d}
            \\FIRST_SEEN: {d}
            \\LAST_SEEN: {d}
            \\
        , .{
            stats.total_flows,
            stats.unique_sources,
            stats.unique_destinations,
            stats.tcp_flows,
            stats.udp_flows,
            stats.icmp_flows,
            stats.first_seen,
            stats.last_seen,
        });

        _ = try std.posix.write(client, len);
    }

    fn sendTopSources(self: *HealthApi, client: std.posix.socket_t) !void {
        const top_sources = self.ds.getTopSources(10, null, null) catch |err| {
            var error_buf: [128]u8 = undefined;
            const error_msg = std.fmt.bufPrint(&error_buf, "ERROR: Failed to get top sources: {}\n", .{err}) catch return;
            _ = try std.posix.write(client, error_msg);
            return;
        };
        defer self.allocator.free(top_sources);

        var response: [2048]u8 = undefined;
        var offset: usize = 0;

        for (top_sources, 0..) |source, idx| {
            const line = std.fmt.bufPrint(response[offset..], "{d}. {s}: {d} flows\n", .{
                idx + 1,
                source.address[0..source.address_len],
                source.flow_count,
            }) catch break;
            offset += line.len;
        }

        if (offset == 0) {
            _ = try std.posix.write(client, "No sources recorded\n");
        } else {
            _ = try std.posix.write(client, response[0..offset]);
        }
    }

    fn sendTopPorts(self: *HealthApi, client: std.posix.socket_t) !void {
        const top_ports = self.ds.getTopPorts(10, null, null) catch |err| {
            var error_buf: [128]u8 = undefined;
            const error_msg = std.fmt.bufPrint(&error_buf, "ERROR: Failed to get top ports: {}\n", .{err}) catch return;
            _ = try std.posix.write(client, error_msg);
            return;
        };
        defer self.allocator.free(top_ports);

        var response: [2048]u8 = undefined;
        var offset: usize = 0;

        for (top_ports, 0..) |port_stat, idx| {
            const proto_name = if (port_stat.proto == 6) "tcp" else if (port_stat.proto == 17) "udp" else "other";
            const line = std.fmt.bufPrint(response[offset..], "{d}. {d}/{s}: {d} flows\n", .{
                idx + 1,
                port_stat.port,
                proto_name,
                port_stat.flow_count,
            }) catch break;
            offset += line.len;
        }

        if (offset == 0) {
            _ = try std.posix.write(client, "No ports recorded\n");
        } else {
            _ = try std.posix.write(client, response[0..offset]);
        }
    }
};
