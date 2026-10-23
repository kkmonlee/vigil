const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const helper_exe = b.addExecutable(.{
        .name = "helper",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });
    helper_exe.addCSourceFile(.{
        .file = b.path("src/helper/helper.c"),
        .flags = &.{},
    });
    helper_exe.linkLibC();
    b.installArtifact(helper_exe);

    const agent_exe = b.addExecutable(.{
        .name = "agent",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/agent/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    agent_exe.root_module.addAnonymousImport("common/protocol.zig", .{
        .root_source_file = b.path("src/common/protocol.zig"),
    });
    agent_exe.linkLibC();
    agent_exe.addCSourceFile(.{
        .file = b.path("src/common/sqlite.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" },
    });
    agent_exe.linkSystemLibrary("sqlite3");

    if (target.result.os.tag == .linux) {
        agent_exe.linkSystemLibrary("mnl");
    }

    b.installArtifact(agent_exe);

    const run_cmd = b.addRunArtifact(agent_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the agent");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/agent/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.addAnonymousImport("common/protocol.zig", .{
        .root_source_file = b.path("src/common/protocol.zig"),
    });
    const run_tests = b.addRunArtifact(tests);
    const helper_tests = b.addExecutable(.{
        .name = "helper-tests",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
    });
    helper_tests.addCSourceFile(.{
        .file = b.path("tests/helper_test.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" },
    });
    helper_tests.linkLibC();
    const run_helper_tests = b.addRunArtifact(helper_tests);
    const test_step = b.step("test", "Run compiler, client and privileged helper regression tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_helper_tests.step);
}
