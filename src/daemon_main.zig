const std = @import("std");
const daemon = @import("daemon.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    try daemon.run(gpa.allocator());
}
