const std = @import("std");

pub const SOCKET_PATH = std.os.getenv("VIGIL_SOCKET_PATH") orelse "/tmp/vigil.sock";
