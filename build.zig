const std = @import("std");

pub fn build(b: *std.Build) void {
    b.minimumVersion("0.11.0");

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const helper_exe = b.addExecutable(.{
        .name = "helper",
        .root_source_file = .{ .path = "src/helper/helper.c" },
        .target = target,
        .optimize = optimize,
    });

    helper_exe.linkSystemLibrary("c");
    b.installArtifact(helper_exe);

    const agent_exe = b.addExecutable(.{
        .name = "agent",
        .root_source_file = .{ .path = "src/agent/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const yaml_dep = b.dependency("zig-yaml", .{
        .target = target,
        .optimize = optimize,
    });
    agent_exe.addModule("yaml", yaml_dep.module("yaml"));

    b.installArtifact(agent_exe);

    const run_cmd = b.addRunArtifact(agent_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the agent");
    run_step.dependOn(&run_cmd.step);
}
