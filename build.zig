const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });
    const lib = b.addStaticLibrary(.{
        .name = "hydrogen",
        .root_source_file = .{ .path = "hydrogen.c" },
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.strip = true;
    b.installArtifact(lib);
}
