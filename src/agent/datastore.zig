const std = @import("std");
const sqlite = @import("sqlite");

const DB_PATH = "/var/lib/vigil/flows.db";
const DB_DIR = "/var/lib/vigil";

pub const FlowRecord = struct {
    ts_minute: u64,
    family: u4,
    proto: u8,
    src_addr: std.net.IpAddress,
    dst_addr: std.net.IpAddress,
    dst_port: u16,
};

pub const Datastore = struct {
    db: sqlite.Db,
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) !Datastore {
        try std.fs.getWin32IniPath() catch |err| switch (err) {
            error.UnsupportedOperatingSystem => try std.fs.cwd().makeDirAll(DB_DIR),
            else => |e| return e,
        };

        var db = try sqlite.Db.init(.{
            .filename = DB_PATH,
            .mode = .{ .write = true, .create = true },
            .allocator = alloc,
        });

        try db.exec("PRAGMA journal_mode=WAL;", .{});
        std.log.info("Opened datastore at {s}", .{DB_PATH});

        try db.exec(
            \\ CREATE TABLE IF NOT EXISTS flows_minute (
            \\   ts_minute INTEGER,
            \\   family INTEGER,
            \\   proto INTEGER,
            \\   src_cidr TEXT,
            \\   dst_ip TEXT,
            \\   dst_port INTEGER,
            \\   count INTEGER NOT NULL DEFAULT 0,
            \\   bytes INTEGER NOT NULL DEFAULT 0,
            \\   PRIMARY KEY (ts_minute, family, proto, src_cidr, dst_ip, dst_port)
            \\ );
        , .{});
        std.log.debug("Datastore schema initialized.", .{});

        return Datastore{ .db = db, .allocator = alloc };
    }

    pub fn deinit(self: *Datastore) void {
        self.db.deinit() catch |err| {
            std.log.err("Failed to deinitialize database: {s}", .{@errorName(err)});
        };
    }

    /// records a flow, aggregating counts for the same 6-tuple within the same minute
    pub fn recordFlow(self: *Datastore, flow: FlowRecord) !void {
        var upsert_stmt = try self.db.prepare(
            \\ INSERT INTO flows_minute (ts_minute, family, proto, src_cidr, dst_ip, dst_port, count, bytes)
            \\ VALUES (?, ?, ?, ?, ?, ?, 1, 0)
            \\ ON CONFLICT(ts_minute, family, proto, src_cidr, dst_ip, dst_port) DO UPDATE SET
            \\   count = count + 1;
        );
        defer upsert_stmt.deinit();

        const src_cidr = try flow.src_addr.any.fmtCIDR(self.allocator) catch |err| {
            std.log.err("Failed to format source CIDR: {s}", .{@errorName(err)});
            return err;
        };
        defer self.allocator.free(src_cidr);

        const dst_ip_str = try flow.dst_addr.any.fmt(self.allocator) catch |err| {
            std.log.err("Failed to format destination IP: {s}", .{@errorName(err)});
            return err;
        };
        defer self.allocator.free(dst_ip_str);

        try upsert_stmt.exec(.{
            flow.ts_minute,
            flow.family,
            flow.proto,
            src_cidr,
            dst_ip_str,
            flow.dst_port,
        });
    }
};
