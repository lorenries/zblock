const std = @import("std");
const cli = @import("zblock").cli;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var args_iter = try std.process.argsWithAllocator(arena.allocator());
    defer args_iter.deinit();

    const ctx = cli.RunContext{
        .allocator = arena.allocator(),
        .stdout_fd = std.posix.STDOUT_FILENO,
        .stderr_fd = std.posix.STDERR_FILENO,
    };

    const exit_code = cli.run(ctx, &args_iter) catch |err| {
        std.debug.print("zblock: {s}\n", .{@errorName(err)});
        return;
    };

    std.process.exit(exit_code);
}
