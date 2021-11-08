const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const lib = b.addStaticLibrary("hydrogen", null);
    lib.addCSourceFile("hydrogen.c", &.{});
    lib.setBuildMode(.ReleaseSmall);
    lib.setTarget(target);
    lib.strip = true;
    lib.install();
}
