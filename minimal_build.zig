const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "test",
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);
}
