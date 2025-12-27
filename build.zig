const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = true,
    });

    mod.addCSourceFile(.{
        .file = b.path("hydrogen.c"),
    });

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
        .link_libc = true,
    });
}
