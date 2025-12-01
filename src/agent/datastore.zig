// Flow datastore: SQLite-backed audit log for network connection tracking
// Records deduplicated flow tuples (5-tuple + timestamp) for compliance and forensics
// Uses per-minute granularity to balance storage efficiency with temporal resolution
const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

const DB_PATH = "/var/lib/vigil/flows.db";
const DB_DIR = "/var/lib/vigil";

pub const FlowRecord = struct {
    ts_minute: u64,
    family: u4,
    proto: u8,
    src_addr: std.net.Address,
    dst_addr: std.net.Address,
    dst_port: u16,
};

pub const Datastore = struct {
    allocator: std.mem.Allocator,
    db: *c.sqlite3,

    pub fn init(alloc: std.mem.Allocator) !Datastore {
        std.fs.cwd().makePath(DB_DIR) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var db: ?*c.sqlite3 = null;
        const db_path_z = DB_PATH ++ "";
        const rc = c.sqlite3_open(db_path_z.ptr, &db);
        if (rc != c.SQLITE_OK) {
            std.log.err("Failed to open database: {s}", .{c.sqlite3_errmsg(db)});
            return error.DatabaseOpenFailed;
        }

        const create_table_sql =
            \\CREATE TABLE IF NOT EXISTS flows (
            \\  ts_minute INTEGER NOT NULL,
            \\  family INTEGER NOT NULL,
            \\  proto INTEGER NOT NULL,
            \\  src_addr TEXT NOT NULL,
            \\  dst_addr TEXT NOT NULL,
            \\  dst_port INTEGER NOT NULL,
            \\  PRIMARY KEY (ts_minute, family, proto, src_addr, dst_addr, dst_port)
            \\)
        ;

        var errmsg: [*c]u8 = null;
        const create_rc = c.sqlite3_exec(db, create_table_sql.ptr, null, null, &errmsg);
        if (create_rc != c.SQLITE_OK) {
            std.log.err("Failed to create table: {s}", .{errmsg});
            c.sqlite3_free(errmsg);
            _ = c.sqlite3_close(db);
            return error.DatabaseInitFailed;
        }

        std.log.info("Opened datastore at {s}", .{DB_PATH});
        std.log.debug("Datastore schema initialized.", .{});

        return Datastore{
            .allocator = alloc,
            .db = db.?,
        };
    }

    pub fn deinit(self: *Datastore) void {
        _ = c.sqlite3_close(self.db);
    }

    pub fn recordFlow(self: *Datastore, flow: FlowRecord) !void {
        const insert_sql =
            \\INSERT OR IGNORE INTO flows 
            \\(ts_minute, family, proto, src_addr, dst_addr, dst_port)
            \\VALUES (?, ?, ?, ?, ?, ?)
        ;

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, insert_sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            std.log.err("Failed to prepare statement: {s}", .{c.sqlite3_errmsg(self.db)});
            return error.DatabasePrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int64(stmt, 1, @intCast(flow.ts_minute));
        _ = c.sqlite3_bind_int(stmt, 2, flow.family);
        _ = c.sqlite3_bind_int(stmt, 3, flow.proto);

        var src_buf: [128]u8 = undefined;
        var dst_buf: [128]u8 = undefined;
        const src_str = try std.fmt.bufPrint(&src_buf, "{}", .{flow.src_addr});
        const dst_str = try std.fmt.bufPrint(&dst_buf, "{}", .{flow.dst_addr});

        _ = c.sqlite3_bind_text(stmt, 4, src_str.ptr, @intCast(src_str.len), c.SQLITE_TRANSIENT);
        _ = c.sqlite3_bind_text(stmt, 5, dst_str.ptr, @intCast(dst_str.len), c.SQLITE_TRANSIENT);
        _ = c.sqlite3_bind_int(stmt, 6, flow.dst_port);

        rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) {
            std.log.err("Failed to insert flow record: {s}", .{c.sqlite3_errmsg(self.db)});
            return error.DatabaseInsertFailed;
        }
    }
};
