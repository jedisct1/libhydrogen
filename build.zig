const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const lib = b.addStaticLibrary("hydrogen", "hydrogen.c");
    lib.linkLibC();
    lib.setBuildMode(.ReleaseSmall);
    lib.setTarget(target);
    lib.strip = true;
    lib.install();
}
