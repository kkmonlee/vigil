const std = @import("std");
const datastore = @import("datastore.zig");

// libmnl and netfilter headers
const c = @cImport({
    @cInclude("libmnl/libmnl.h");
    @cInclude("string.h");
    @cInclude("time.h");
    @cInclude("arpa/inet.h");
    @cInclude("linux/netfilter.h");
    @cInclude("linux/netfilter/nfnetlink.h");
    @cInclude("linux/netfilter/nfnetlink_conntrack.h");
});

const CallbackContext = struct {
    ds: *datastore.Datastore,
};

// libmnl invokes thisfor each netlink message
fn dataCallback(nlh: [*c]const c.nlmsghdr, data: ?*anyopaque) c_int {
    const context = if (data) |ptr| {
        if (ptr == null) return c.MNL_CB_ERROR;
        return @as(*CallbackContext, @ptrCast(@alignCast(ptr)));
    } else {
        return c.MNL_CB_OK;
    };

    var nested: [*c]c.nlattr = null;

    // parse netlink attributes for the connection details
    // CTA_TUPLE_ORIG contains the source-to-destination tuple
    if (c.mnl_attr_parse_nested(nlh, c.CTA_TUPLE_ORIG, &nested) != 0) {
        return c.MNL_CB_OK;
    }

    if (nested == null) {
        std.log.err("Nested attribute is null, skipping.", .{});
        return c.MNL_CB_ERROR;
    }

    // family packed in nlmsg_type lower byte
    var flow = datastore.FlowRecord{
        .ts_minute = @divFloor(@as(u64, @intCast(c.time(null))), 60),
        .family = nlh.nlmsg_type & 0xFF,
        .proto = 0,
        .src_addr = undefined,
        .dst_addr = undefined,
        .dst_port = 0,
    };

    var attr = c.mnl_attr_get_next(nested);
    while (attr != null) {
        const attr_type = c.mnl_attr_get_type(attr);

        switch (attr_type) {
            // L3 Protocol (IPv4/IPv6)
            c.CTA_TUPLE_IP => {
                const ip_nested = c.mnl_attr_get_payload(attr);
                var ip_attr = c.mnl_attr_get_next(ip_nested);

                while (ip_attr != null) {
                    const ip_attr_type = c.mnl_attr_get_type(ip_attr);
                    switch (ip_attr_type) {
                        c.CTA_IP_V4_SRC => {
                            flow.src_addr.any.family = .ipv4;
                            c.memcpy(&flow.src_addr.any.ipv4, c.mnl_attr_get_payload(ip_attr), 4);
                        },
                        c.CTA_IP_V4_DST => {
                            flow.dst_addr.any.family = .ipv4;
                            c.memcpy(&flow.dst_addr.any.ipv4, c.mnl_attr_get_payload(ip_attr), 4);
                        },
                        else => {},
                    }
                    ip_attr = c.mnl_attr_get_next(ip_attr);
                }
            },
            // L4 Protocol (TCP/UDP)
            c.CTA_TUPLE_L4_PROTO => {
                const l4_nested = c.mnl_attr_get_payload(attr);
                var l4_attr = c.mnl_attr_get_next(l4_nested);

                while (l4_attr != null) {
                    const l4_attr_type = c.mnl_attr_get_type(l4_attr);
                    const payload = c.mnl_attr_get_payload(l4_attr);

                    switch (l4_attr_type) {
                        c.CTA_PROTO_NUM => flow.proto = payload.*,
                        c.CTA_PROTO_DST_PORT => flow.dst_port = std.mem.readInt(u16, @as([*]const u8, @ptrCast(payload)), .big),
                        else => {},
                    }
                    l4_attr = c.mnl_attr_get_next(l4_attr);
                }
            },
            else => {},
        }
        attr = c.mnl_attr_get_next(attr);
    }

    if (flow.proto == c.IPPROTO_TCP or flow.proto == c.IPPROTO_UDP) {
        std.log.debug("Observed flow: {any} -> {any}:{d} ({d})", .{ flow.src_addr, flow.dst_addr, flow.dst_port, flow.proto });
        context.ds.recordFlow(flow) catch |err| {
            std.log.err("Failed to record flow: {}", .{err});
        };
    }

    return c.MNL_CB_OK;
}

/// spawns a thread to listen for conntrack events
pub fn start(ds: *datastore.Datastore) !std.Thread {
    const thread = try std.Thread.spawn(.{}, listenLoop, .{ds});
    return thread;
}

fn listenLoop(ds: *datastore.Datastore) !void {
    std.log.info("Starting conntrack observer...", .{});

    // NOTE: This requires CAP_NET_ADMIN
    // run agent as root
    const nl = c.mnl_socket_open(c.NETLINK_NETFILTER);
    if (nl == null) {
        std.log.err("mnl_socket_open failed. Are you root?", .{});
        return error.SocketOpenFailed;
    }
    defer c.mnl_socket_close(nl);

    // subscribe to events for new, updated, and destroyed connections
    const groups = (1 << (c.NFNLGRP_CONNTRACK_NEW - 1));
    if (c.mnl_socket_bind(nl, groups, c.MNL_SOCKET_AUTOPID) < 0) {
        std.log.err("mnl_socket_bind failed.", .{});
        return error.SocketBindFailed;
    }

    var context = CallbackContext{ .ds = ds };
    var buf: [c.MNL_SOCKET_BUFFER_SIZE]u8 = undefined;

    while (true) {
        const ret = c.mnl_socket_recvfrom(nl, &buf, buf.len);
        if (ret == -1) {
            // EAGAIN error means no message yet
            if (std.c.errno != std.c.EAGAIN) {
                std.log.err("mnl_socket_recvfrom failed: {s}", .{@errorName(std.os.errno(std.c.errno))});
                break;
            }
            continue;
        }

        if (c.mnl_cb_run(&buf, @as(c_uint, ret), 0, 0, dataCallback, &context) < 0) {
            std.log.err("mnl_cb_run failed", .{});
            break;
        }
    }
}
