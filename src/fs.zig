const std = @import("std");

pub const Error = error{
    InvalidPathName,
};

pub fn ensureAbsoluteDir(path: []const u8) !void {
    std.fs.makeDirAbsolute(path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

pub fn atomicWriteFileAbsolute(path: []const u8, data: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse return Error.InvalidPathName;
    var dir = try std.fs.openDirAbsolute(dir_path, .{});
    defer dir.close();

    var write_buffer: [4096]u8 = undefined;
    var atomic = try dir.atomicFile(std.fs.path.basename(path), .{ .write_buffer = write_buffer[0..] });
    defer atomic.deinit();

    try atomic.file_writer.interface.writeAll(data);
    try atomic.finish();
}

pub fn atomicWriteFileAbsoluteWithMode(path: []const u8, data: []const u8, mode: std.fs.File.Mode) !void {
    const dir_path = std.fs.path.dirname(path) orelse return Error.InvalidPathName;
    var dir = try std.fs.openDirAbsolute(dir_path, .{});
    defer dir.close();

    var write_buffer: [4096]u8 = undefined;
    var atomic = try dir.atomicFile(std.fs.path.basename(path), .{ .mode = mode, .write_buffer = write_buffer[0..] });
    defer atomic.deinit();

    try atomic.file_writer.interface.writeAll(data);
    try atomic.finish();
}


pub fn ensureParentDir(path: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse return Error.InvalidPathName;
    if (dir_path.len == 0 or std.mem.eql(u8, dir_path, ".")) return;
    if (std.mem.eql(u8, dir_path, "/")) return;

    var root = try std.fs.openDirAbsolute("/", .{});
    defer root.close();

    const rel = if (dir_path.len > 0 and dir_path[0] == '/') dir_path[1..] else dir_path;
    if (rel.len == 0) return;
    try root.makePath(rel);
}
