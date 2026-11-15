const std = @import("std");

const wasm_libc_path = "builds/wasm32-freestanding";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const wasm_freestanding_libc = b.option(
        bool,
        "wasm_freestanding_libc",
        "Include the built-in libc compatibility layer for wasm32-freestanding.",
    ) orelse true;

    const wasm_freestanding =
        target.result.cpu.arch.isWasm() and target.result.os.tag == .freestanding;

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = !wasm_freestanding,
        .strip = true,
    });

    mod.addCSourceFile(.{
        .file = b.path("hydrogen.c"),
    });
    if (wasm_freestanding) {
        mod.addSystemIncludePath(b.path(wasm_libc_path ++ "/include"));
        if (wasm_freestanding_libc) {
            mod.addCSourceFile(.{
                .file = b.path(wasm_libc_path ++ "/libc.c"),
            });
        }
    }

    const lib = b.addLibrary(.{
        .name = "hydrogen",
        .linkage = .static,
        .root_module = mod,
    });

    b.installArtifact(lib);

    _ = b.addModule("libhydrogen", .{
        .root_source_file = b.path("hydrogen.c"),
        .target = target,
        .optimize = optimize,
        .link_libc = !wasm_freestanding,
    });

    // The tests need a libc.
    if (wasm_freestanding) {
        return;
    }

    const test_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addCSourceFile(.{
        .file = b.path("tests/tests.c"),
    });
    test_mod.addIncludePath(b.path("."));
    test_mod.linkLibrary(lib);

    const test_exe = b.addExecutable(.{
        .name = "hydrogen-tests",
        .root_module = test_mod,
    });

    const run_tests = b.addRunArtifact(test_exe);
    const test_step = b.step("test", "Run the test suite");
    test_step.dependOn(&run_tests.step);
}
