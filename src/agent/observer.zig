const std = @import("std");
const datastore = @import("datastore.zig");
const builtin = @import("builtin");

const c = if (builtin.os.tag == .linux) @cImport({
    @cInclude("libmnl/libmnl.h");
    @cInclude("linux/netfilter/nfnetlink.h");
    @cInclude("linux/netfilter/nfnetlink_conntrack.h");
}) else struct {};

const ThreadContext = struct {
    ds: *datastore.Datastore,
    should_stop: *std.atomic.Value(bool),
};

pub fn start(ds: *datastore.Datastore) !std.Thread {
    if (builtin.os.tag != .linux) {
        std.log.warn("Observer only supported on Linux, skipping", .{});
        return error.ObserverNotSupported;
    }

    const should_stop = try ds.allocator.create(std.atomic.Value(bool));
    should_stop.* = std.atomic.Value(bool).init(false);

    const ctx = try ds.allocator.create(ThreadContext);
    ctx.* = .{
        .ds = ds,
        .should_stop = should_stop,
    };

    return try std.Thread.spawn(.{}, listenLoop, .{ctx});
}

fn listenLoop(ctx: *ThreadContext) void {
    if (builtin.os.tag != .linux) return;
    const nl = c.mnl_socket_open(c.NETLINK_NETFILTER);
    if (nl == null) {
        std.log.err("Failed to open netlink socket", .{});
        return;
    }
    defer c.mnl_socket_close(nl);

    if (c.mnl_socket_bind(nl, 0, c.MNL_SOCKET_AUTOPID) < 0) {
        std.log.err("Failed to bind netlink socket", .{});
        return;
    }

    if (c.mnl_socket_setsockopt(nl, c.NETLINK_ADD_MEMBERSHIP, &c.NF_NETLINK_CONNTRACK_NEW, @sizeOf(@TypeOf(c.NF_NETLINK_CONNTRACK_NEW))) < 0) {
        std.log.err("Failed to join conntrack multicast group", .{});
        return;
    }

    var buf: [8192]u8 align(@alignOf(c.nlmsghdr)) = undefined;

    std.log.info("Observer started, listening for conntrack events", .{});

    while (!ctx.should_stop.load(.acquire)) {
        const ret = c.mnl_socket_recvfrom(nl, &buf, buf.len);
        if (ret == -1) {
            if (std.posix.errno(-1) == .INTR) continue;
            std.log.err("Error receiving netlink message", .{});
            break;
        }

        if (c.mnl_cb_run(&buf, @intCast(ret), 0, 0, dataCallback, ctx) == c.MNL_CB_ERROR) {
            std.log.err("Error processing netlink message", .{});
        }
    }

    std.log.info("Observer stopped", .{});
}

fn dataCallback(nlh: ?*const c.nlmsghdr, data: ?*anyopaque) callconv(.c) c_int {
    const ctx = @as(*ThreadContext, @ptrCast(@alignCast(data)));

    const nfg = @as(*c.nfgenmsg, @ptrCast(@alignCast(c.mnl_nlmsg_get_payload(nlh))));

    var tb: [c.CTA_MAX + 1]?*c.nlattr = undefined;
    @memset(&tb, null);

    _ = c.mnl_attr_parse(nlh, @sizeOf(c.nfgenmsg), attrCallback, &tb);

    if (tb[c.CTA_TUPLE_ORIG] == null) return c.MNL_CB_OK;

    var tb_orig: [c.CTA_TUPLE_MAX + 1]?*c.nlattr = undefined;
    @memset(&tb_orig, null);
    _ = c.mnl_attr_parse_nested(tb[c.CTA_TUPLE_ORIG], tupleCallback, &tb_orig);

    if (tb_orig[c.CTA_TUPLE_IP] == null or tb_orig[c.CTA_TUPLE_PROTO] == null) {
        return c.MNL_CB_OK;
    }

    var tb_ip: [c.CTA_IP_MAX + 1]?*c.nlattr = undefined;
    @memset(&tb_ip, null);
    _ = c.mnl_attr_parse_nested(tb_orig[c.CTA_TUPLE_IP], ipCallback, &tb_ip);

    var tb_proto: [c.CTA_PROTO_MAX + 1]?*c.nlattr = undefined;
    @memset(&tb_proto, null);
    _ = c.mnl_attr_parse_nested(tb_orig[c.CTA_TUPLE_PROTO], protoCallback, &tb_proto);

    const family: u4 = @intCast(nfg.*.nfgen_family);
    const proto: u8 = if (tb_proto[c.CTA_PROTO_NUM]) |attr| c.mnl_attr_get_u8(attr) else return c.MNL_CB_OK;

    var src_addr: std.net.Address = undefined;
    var dst_addr: std.net.Address = undefined;
    var dst_port: u16 = 0;

    if (family == std.posix.AF.INET) {
        if (tb_ip[c.CTA_IP_V4_SRC] != null and tb_ip[c.CTA_IP_V4_DST] != null) {
            const src_ip = c.mnl_attr_get_u32(tb_ip[c.CTA_IP_V4_SRC].?);
            const dst_ip = c.mnl_attr_get_u32(tb_ip[c.CTA_IP_V4_DST].?);

            src_addr = std.net.Address.initIp4(@bitCast(src_ip), 0);
            dst_addr = std.net.Address.initIp4(@bitCast(dst_ip), 0);
        } else {
            return c.MNL_CB_OK;
        }
    } else if (family == std.posix.AF.INET6) {
        if (tb_ip[c.CTA_IP_V6_SRC] != null and tb_ip[c.CTA_IP_V6_DST] != null) {
            const src_ip = c.mnl_attr_get_payload(tb_ip[c.CTA_IP_V6_SRC].?);
            const dst_ip = c.mnl_attr_get_payload(tb_ip[c.CTA_IP_V6_DST].?);

            src_addr = std.net.Address.initIp6(@as(*const [16]u8, @ptrCast(src_ip)).*, 0, 0, 0);
            dst_addr = std.net.Address.initIp6(@as(*const [16]u8, @ptrCast(dst_ip)).*, 0, 0, 0);
        } else {
            return c.MNL_CB_OK;
        }
    } else {
        return c.MNL_CB_OK;
    }

    if (proto == std.posix.IPPROTO.TCP or proto == std.posix.IPPROTO.UDP) {
        if (tb_proto[c.CTA_PROTO_DST_PORT]) |attr| {
            dst_port = std.mem.bigToNative(u16, c.mnl_attr_get_u16(attr));
        }
    }

    const now = std.time.timestamp();
    const ts_minute: u64 = @intCast(@divFloor(now, 60) * 60);

    const flow = datastore.FlowRecord{
        .ts_minute = ts_minute,
        .family = family,
        .proto = proto,
        .src_addr = src_addr,
        .dst_addr = dst_addr,
        .dst_port = dst_port,
    };

    ctx.ds.recordFlow(flow) catch |err| {
        std.log.err("Failed to record flow: {}", .{err});
    };

    return c.MNL_CB_OK;
}

fn attrCallback(attr: ?*const c.nlattr, data: ?*anyopaque) callconv(.c) c_int {
    const tb = @as([*]?*c.nlattr, @ptrCast(@alignCast(data)));
    const attr_type = c.mnl_attr_get_type(attr);

    if (c.mnl_attr_type_valid(attr, c.CTA_MAX) < 0) {
        return c.MNL_CB_OK;
    }

    tb[attr_type] = @constCast(attr);
    return c.MNL_CB_OK;
}

fn tupleCallback(attr: ?*const c.nlattr, data: ?*anyopaque) callconv(.c) c_int {
    const tb = @as([*]?*c.nlattr, @ptrCast(@alignCast(data)));
    const attr_type = c.mnl_attr_get_type(attr);

    if (c.mnl_attr_type_valid(attr, c.CTA_TUPLE_MAX) < 0) {
        return c.MNL_CB_OK;
    }

    tb[attr_type] = @constCast(attr);
    return c.MNL_CB_OK;
}

fn ipCallback(attr: ?*const c.nlattr, data: ?*anyopaque) callconv(.c) c_int {
    const tb = @as([*]?*c.nlattr, @ptrCast(@alignCast(data)));
    const attr_type = c.mnl_attr_get_type(attr);

    if (c.mnl_attr_type_valid(attr, c.CTA_IP_MAX) < 0) {
        return c.MNL_CB_OK;
    }

    tb[attr_type] = @constCast(attr);
    return c.MNL_CB_OK;
}

fn protoCallback(attr: ?*const c.nlattr, data: ?*anyopaque) callconv(.c) c_int {
    const tb = @as([*]?*c.nlattr, @ptrCast(@alignCast(data)));
    const attr_type = c.mnl_attr_get_type(attr);

    if (c.mnl_attr_type_valid(attr, c.CTA_PROTO_MAX) < 0) {
        return c.MNL_CB_OK;
    }

    tb[attr_type] = @constCast(attr);
    return c.MNL_CB_OK;
}
