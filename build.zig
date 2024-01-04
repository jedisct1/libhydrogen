const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });
    const lib = b.addStaticLibrary(.{
        .name = "hydrogen",
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    lib.addCSourceFile(.{
        .file = .{ .path = "hydrogen.c" },
    });
    lib.linkLibC();
    b.installArtifact(lib);
}
