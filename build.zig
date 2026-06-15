const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The reusable library module: the EVM core.
    const mod = b.addModule("zetherum", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // CLI: `zig build run -- <hex-bytecode> [gas]`
    const exe = b.addExecutable(.{
        .name = "zetherum",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zetherum", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run the bytecode CLI");
    run_step.dependOn(&run_cmd.step);

    // Unit tests across the whole library.
    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Benchmark: `zig build bench -Doptimize=ReleaseFast`
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zetherum", .module = mod }},
        }),
    });
    const run_bench = b.addRunArtifact(bench);
    const bench_step = b.step("bench", "Run the poop-style EVM benchmark comparison");
    bench_step.dependOn(&run_bench.step);

    // Machine-readable single-program runner for the cross-client harness.
    const runner = b.addExecutable(.{
        .name = "zeth-run",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/runner.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zetherum", .module = mod }},
        }),
    });
    b.installArtifact(runner);

    // EELS conformance runner (root-checked against official ethereum/tests).
    const eels = b.addExecutable(.{
        .name = "eels",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/eels.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zetherum", .module = mod }},
        }),
    });
    b.installArtifact(eels);

    // GeneralStateTests runner (root-checked state transitions).
    const statetest = b.addExecutable(.{
        .name = "statetest",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/statetest.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zetherum", .module = mod }},
        }),
    });
    b.installArtifact(statetest);

    // BlockchainTests runner (per-block state-root checked).
    const blocktest = b.addExecutable(.{
        .name = "blocktest",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/blocktest.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zetherum", .module = mod }},
        }),
    });
    b.installArtifact(blocktest);
}
