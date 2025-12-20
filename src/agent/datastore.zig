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

pub const FlowStats = struct {
    total_flows: u64,
    unique_sources: u64,
    unique_destinations: u64,
    tcp_flows: u64,
    udp_flows: u64,
    icmp_flows: u64,
    first_seen: u64,
    last_seen: u64,
};

pub const TopTalker = struct {
    address: [128]u8,
    address_len: usize,
    flow_count: u64,
};

pub const PortStats = struct {
    port: u16,
    proto: u8,
    flow_count: u64,
};

pub const TimeSeriesPoint = struct {
    ts_minute: u64,
    flow_count: u64,
};

pub const Datastore = struct {
    allocator: std.mem.Allocator,
    db: *c.sqlite3,
    insert_stmt: ?*c.sqlite3_stmt = null,

    pub fn init(alloc: std.mem.Allocator) !Datastore {
        std.fs.cwd().makePath(DB_DIR) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var db: ?*c.sqlite3 = null;
        const db_path_z = DB_PATH ++ "";
        var rc = c.sqlite3_open(db_path_z.ptr, &db);
        if (rc != c.SQLITE_OK) {
            std.log.err("Failed to open database: {s}", .{c.sqlite3_errmsg(db)});
            return error.DatabaseOpenFailed;
        }

        const pragma_sql = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=10000; PRAGMA temp_store=MEMORY;";
        var errmsg: [*c]u8 = null;
        rc = c.sqlite3_exec(db, pragma_sql.ptr, null, null, &errmsg);
        if (rc != c.SQLITE_OK) {
            std.log.warn("Failed to set pragmas: {s}", .{errmsg});
            c.sqlite3_free(errmsg);
        }

        const create_table_sql =
            \\CREATE TABLE IF NOT EXISTS flows (
            \\  ts_minute INTEGER NOT NULL,
            \\  family INTEGER NOT NULL,
            \\  proto INTEGER NOT NULL,
            \\  src_addr TEXT NOT NULL,
            \\  dst_addr TEXT NOT NULL,
            \\  dst_port INTEGER NOT NULL,
            \\  count INTEGER DEFAULT 1,
            \\  PRIMARY KEY (ts_minute, family, proto, src_addr, dst_addr, dst_port)
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts_minute);
            \\CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_addr);
            \\CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_addr);
            \\CREATE INDEX IF NOT EXISTS idx_flows_port ON flows(dst_port);
        ;

        rc = c.sqlite3_exec(db, create_table_sql.ptr, null, null, &errmsg);
        if (rc != c.SQLITE_OK) {
            std.log.err("Failed to create table: {s}", .{errmsg});
            c.sqlite3_free(errmsg);
            _ = c.sqlite3_close(db);
            return error.DatabaseInitFailed;
        }

        const insert_sql =
            \\INSERT INTO flows (ts_minute, family, proto, src_addr, dst_addr, dst_port, count)
            \\VALUES (?, ?, ?, ?, ?, ?, 1)
            \\ON CONFLICT(ts_minute, family, proto, src_addr, dst_addr, dst_port)
            \\DO UPDATE SET count = count + 1
        ;

        var insert_stmt: ?*c.sqlite3_stmt = null;
        rc = c.sqlite3_prepare_v2(db, insert_sql.ptr, -1, &insert_stmt, null);
        if (rc != c.SQLITE_OK) {
            std.log.err("Failed to prepare insert statement: {s}", .{c.sqlite3_errmsg(db)});
            _ = c.sqlite3_close(db);
            return error.DatabasePrepareFailed;
        }

        std.log.info("Opened datastore at {s}", .{DB_PATH});
        std.log.debug("Datastore schema initialized with WAL mode.", .{});

        return Datastore{
            .allocator = alloc,
            .db = db.?,
            .insert_stmt = insert_stmt,
        };
    }

    pub fn deinit(self: *Datastore) void {
        if (self.insert_stmt) |stmt| {
            _ = c.sqlite3_finalize(stmt);
        }
        _ = c.sqlite3_close(self.db);
    }

    pub fn recordFlow(self: *Datastore, flow: FlowRecord) !void {
        const stmt = self.insert_stmt orelse return error.StatementNotPrepared;

        _ = c.sqlite3_reset(stmt);
        _ = c.sqlite3_clear_bindings(stmt);

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

        const rc = c.sqlite3_step(stmt);
        if (rc != c.SQLITE_DONE) {
            std.log.err("Failed to insert flow record: {s}", .{c.sqlite3_errmsg(self.db)});
            return error.DatabaseInsertFailed;
        }
    }

    pub fn getStats(self: *Datastore, start_ts: ?u64, end_ts: ?u64) !FlowStats {
        var stats = FlowStats{
            .total_flows = 0,
            .unique_sources = 0,
            .unique_destinations = 0,
            .tcp_flows = 0,
            .udp_flows = 0,
            .icmp_flows = 0,
            .first_seen = 0,
            .last_seen = 0,
        };

        const base_sql = if (start_ts != null and end_ts != null)
            "SELECT SUM(count), COUNT(DISTINCT src_addr), COUNT(DISTINCT dst_addr), " ++
                "SUM(CASE WHEN proto = 6 THEN count ELSE 0 END), " ++
                "SUM(CASE WHEN proto = 17 THEN count ELSE 0 END), " ++
                "SUM(CASE WHEN proto = 1 OR proto = 58 THEN count ELSE 0 END), " ++
                "MIN(ts_minute), MAX(ts_minute) FROM flows WHERE ts_minute >= ? AND ts_minute <= ?"
        else
            "SELECT SUM(count), COUNT(DISTINCT src_addr), COUNT(DISTINCT dst_addr), " ++
                "SUM(CASE WHEN proto = 6 THEN count ELSE 0 END), " ++
                "SUM(CASE WHEN proto = 17 THEN count ELSE 0 END), " ++
                "SUM(CASE WHEN proto = 1 OR proto = 58 THEN count ELSE 0 END), " ++
                "MIN(ts_minute), MAX(ts_minute) FROM flows";

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, base_sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            return error.QueryFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        if (start_ts != null and end_ts != null) {
            _ = c.sqlite3_bind_int64(stmt, 1, @intCast(start_ts.?));
            _ = c.sqlite3_bind_int64(stmt, 2, @intCast(end_ts.?));
        }

        const step_rc = c.sqlite3_step(stmt);
        if (step_rc == c.SQLITE_ROW) {
            stats.total_flows = @intCast(c.sqlite3_column_int64(stmt, 0));
            stats.unique_sources = @intCast(c.sqlite3_column_int64(stmt, 1));
            stats.unique_destinations = @intCast(c.sqlite3_column_int64(stmt, 2));
            stats.tcp_flows = @intCast(c.sqlite3_column_int64(stmt, 3));
            stats.udp_flows = @intCast(c.sqlite3_column_int64(stmt, 4));
            stats.icmp_flows = @intCast(c.sqlite3_column_int64(stmt, 5));
            stats.first_seen = @intCast(c.sqlite3_column_int64(stmt, 6));
            stats.last_seen = @intCast(c.sqlite3_column_int64(stmt, 7));
        }

        return stats;
    }

    pub fn getTopSources(self: *Datastore, limit: u32, start_ts: ?u64, end_ts: ?u64) ![]TopTalker {
        const sql = if (start_ts != null and end_ts != null)
            "SELECT src_addr, SUM(count) as total FROM flows WHERE ts_minute >= ? AND ts_minute <= ? GROUP BY src_addr ORDER BY total DESC LIMIT ?"
        else
            "SELECT src_addr, SUM(count) as total FROM flows GROUP BY src_addr ORDER BY total DESC LIMIT ?";

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            return error.QueryFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        var bind_idx: c_int = 1;
        if (start_ts != null and end_ts != null) {
            _ = c.sqlite3_bind_int64(stmt, bind_idx, @intCast(start_ts.?));
            bind_idx += 1;
            _ = c.sqlite3_bind_int64(stmt, bind_idx, @intCast(end_ts.?));
            bind_idx += 1;
        }
        _ = c.sqlite3_bind_int(stmt, bind_idx, @intCast(limit));

        var results: std.ArrayList(TopTalker) = .{ .items = &.{}, .capacity = 0 };

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            var talker = TopTalker{
                .address = undefined,
                .address_len = 0,
                .flow_count = @intCast(c.sqlite3_column_int64(stmt, 1)),
            };

            const addr_text = c.sqlite3_column_text(stmt, 0);
            const addr_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
            if (addr_text != null and addr_len > 0 and addr_len < 128) {
                @memcpy(talker.address[0..addr_len], addr_text[0..addr_len]);
                talker.address_len = addr_len;
                try results.append(self.allocator, talker);
            }
        }

        return try results.toOwnedSlice(self.allocator);
    }

    pub fn getTopDestinations(self: *Datastore, limit: u32, start_ts: ?u64, end_ts: ?u64) ![]TopTalker {
        const sql = if (start_ts != null and end_ts != null)
            "SELECT dst_addr, SUM(count) as total FROM flows WHERE ts_minute >= ? AND ts_minute <= ? GROUP BY dst_addr ORDER BY total DESC LIMIT ?"
        else
            "SELECT dst_addr, SUM(count) as total FROM flows GROUP BY dst_addr ORDER BY total DESC LIMIT ?";

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            return error.QueryFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        var bind_idx: c_int = 1;
        if (start_ts != null and end_ts != null) {
            _ = c.sqlite3_bind_int64(stmt, bind_idx, @intCast(start_ts.?));
            bind_idx += 1;
            _ = c.sqlite3_bind_int64(stmt, bind_idx, @intCast(end_ts.?));
            bind_idx += 1;
        }
        _ = c.sqlite3_bind_int(stmt, bind_idx, @intCast(limit));

        var results: std.ArrayList(TopTalker) = .{ .items = &.{}, .capacity = 0 };

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            var talker = TopTalker{
                .address = undefined,
                .address_len = 0,
                .flow_count = @intCast(c.sqlite3_column_int64(stmt, 1)),
            };

            const addr_text = c.sqlite3_column_text(stmt, 0);
            const addr_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
            if (addr_text != null and addr_len > 0 and addr_len < 128) {
                @memcpy(talker.address[0..addr_len], addr_text[0..addr_len]);
                talker.address_len = addr_len;
                try results.append(self.allocator, talker);
            }
        }

        return try results.toOwnedSlice(self.allocator);
    }

    pub fn getTopPorts(self: *Datastore, limit: u32, start_ts: ?u64, end_ts: ?u64) ![]PortStats {
        const sql = if (start_ts != null and end_ts != null)
            "SELECT dst_port, proto, SUM(count) as total FROM flows WHERE ts_minute >= ? AND ts_minute <= ? AND dst_port > 0 GROUP BY dst_port, proto ORDER BY total DESC LIMIT ?"
        else
            "SELECT dst_port, proto, SUM(count) as total FROM flows WHERE dst_port > 0 GROUP BY dst_port, proto ORDER BY total DESC LIMIT ?";

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            return error.QueryFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        var bind_idx: c_int = 1;
        if (start_ts != null and end_ts != null) {
            _ = c.sqlite3_bind_int64(stmt, bind_idx, @intCast(start_ts.?));
            bind_idx += 1;
            _ = c.sqlite3_bind_int64(stmt, bind_idx, @intCast(end_ts.?));
            bind_idx += 1;
        }
        _ = c.sqlite3_bind_int(stmt, bind_idx, @intCast(limit));

        var results: std.ArrayList(PortStats) = .{ .items = &.{}, .capacity = 0 };

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const port_stats = PortStats{
                .port = @intCast(c.sqlite3_column_int(stmt, 0)),
                .proto = @intCast(c.sqlite3_column_int(stmt, 1)),
                .flow_count = @intCast(c.sqlite3_column_int64(stmt, 2)),
            };
            try results.append(self.allocator, port_stats);
        }

        return try results.toOwnedSlice(self.allocator);
    }

    pub fn getTimeSeries(self: *Datastore, start_ts: u64, end_ts: u64, bucket_minutes: u32) ![]TimeSeriesPoint {
        const bucket_seconds = @as(u64, bucket_minutes) * 60;

        const sql = "SELECT (ts_minute / ?) * ? as bucket, SUM(count) FROM flows WHERE ts_minute >= ? AND ts_minute <= ? GROUP BY bucket ORDER BY bucket";

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            return error.QueryFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int64(stmt, 1, @intCast(bucket_seconds));
        _ = c.sqlite3_bind_int64(stmt, 2, @intCast(bucket_seconds));
        _ = c.sqlite3_bind_int64(stmt, 3, @intCast(start_ts));
        _ = c.sqlite3_bind_int64(stmt, 4, @intCast(end_ts));

        var results: std.ArrayList(TimeSeriesPoint) = .{ .items = &.{}, .capacity = 0 };

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            const point = TimeSeriesPoint{
                .ts_minute = @intCast(c.sqlite3_column_int64(stmt, 0)),
                .flow_count = @intCast(c.sqlite3_column_int64(stmt, 1)),
            };
            try results.append(self.allocator, point);
        }

        return try results.toOwnedSlice(self.allocator);
    }

    pub fn getFlowsBySource(self: *Datastore, source_addr: []const u8, limit: u32) ![]FlowRecord {
        const sql = "SELECT ts_minute, family, proto, src_addr, dst_addr, dst_port FROM flows WHERE src_addr = ? ORDER BY ts_minute DESC LIMIT ?";

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            return error.QueryFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_text(stmt, 1, source_addr.ptr, @intCast(source_addr.len), c.SQLITE_TRANSIENT);
        _ = c.sqlite3_bind_int(stmt, 2, @intCast(limit));

        var results: std.ArrayList(FlowRecord) = .{ .items = &.{}, .capacity = 0 };

        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
            _ = try results.addOne(self.allocator);
        }

        return try results.toOwnedSlice(self.allocator);
    }

    pub fn pruneOldFlows(self: *Datastore, retention_days: u32) !u64 {
        const cutoff = @as(u64, @intCast(std.time.timestamp())) - (@as(u64, retention_days) * 24 * 60 * 60);

        const sql = "DELETE FROM flows WHERE ts_minute < ?";

        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK) {
            return error.QueryFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        _ = c.sqlite3_bind_int64(stmt, 1, @intCast(cutoff));

        const step_rc = c.sqlite3_step(stmt);
        if (step_rc != c.SQLITE_DONE) {
            return error.DeleteFailed;
        }

        return @intCast(c.sqlite3_changes(self.db));
    }

    pub fn vacuum(self: *Datastore) !void {
        const rc = c.sqlite3_exec(self.db, "VACUUM", null, null, null);
        if (rc != c.SQLITE_OK) {
            return error.VacuumFailed;
        }
    }
};
