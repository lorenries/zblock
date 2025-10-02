const std = @import("std");
const testing = std.testing;

pub const DEFAULT_SOCKET_PATH = "/var/run/zblock/zblockd.sock";

pub const AddressConfig = struct {
    path: []u8,
};

pub const Error = error{
    InvalidFormat,
};

pub fn getAddress(allocator: std.mem.Allocator) !AddressConfig {
    const env_value = try getEnvOwned(allocator, "ZBLOCK_SOCKET_PATH");
    defer if (env_value) |value| allocator.free(value);

    const path_slice = if (env_value) |value| value else DEFAULT_SOCKET_PATH;
    const path_copy = try allocator.dupe(u8, path_slice);
    return AddressConfig{ .path = path_copy };
}

pub fn freeAddress(allocator: std.mem.Allocator, addr: *AddressConfig) void {
    allocator.free(addr.path);
    addr.* = undefined;
}

pub fn sendRequest(allocator: std.mem.Allocator, address: AddressConfig, payload: []const u8) ![]u8 {
    var stream = try std.net.connectUnixSocket(address.path);
    defer stream.close();

    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(write_buffer[0..]);
    try writer.interface.writeAll(payload);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();

    var response = std.ArrayListUnmanaged(u8){};
    errdefer response.deinit(allocator);

    var read_buffer: [1024]u8 = undefined;
    while (true) {
        const amount = try stream.read(read_buffer[0..]);
        if (amount == 0) break;

        const slice = read_buffer[0..amount];
        if (std.mem.indexOfScalar(u8, slice, '\n')) |idx| {
            try response.appendSlice(allocator, slice[0..idx]);
            break;
        }

        try response.appendSlice(allocator, slice);
    }

    return response.toOwnedSlice(allocator);
}

pub fn readRequest(allocator: std.mem.Allocator, stream: *std.net.Stream) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);

    var buffer: [1024]u8 = undefined;
    while (true) {
        const amount = try stream.read(buffer[0..]);
        if (amount == 0) break;

        const slice = buffer[0..amount];
        if (std.mem.indexOfScalar(u8, slice, '\n')) |idx| {
            try list.appendSlice(allocator, slice[0..idx]);
            break;
        }

        try list.appendSlice(allocator, slice);
    }

    return list.toOwnedSlice(allocator);
}

pub fn writeResponse(stream: *std.net.Stream, payload: []const u8) !void {
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(write_buffer[0..]);
    try writer.interface.writeAll(payload);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}

fn getEnvOwned(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => err,
    };
}

// ---------------------- Protocol ----------------------

pub const RequestOp = enum { start, status, ping };

pub const StartCommand = struct {
    group: []u8,
    duration_seconds: u64,
    dns_lockdown: bool = false,

    pub fn deinit(self: *StartCommand, allocator: std.mem.Allocator) void {
        allocator.free(self.group);
        self.* = undefined;
    }
};

pub const Request = struct {
    op: RequestOp,
    start: ?StartCommand = null,

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        if (self.start) |*start_cmd| {
            start_cmd.deinit(allocator);
        }
        self.* = undefined;
    }
};

pub const StatusData = struct {
    active: bool,
    group: ?[]u8 = null,
    until_epoch: ?i64 = null,
    remaining_seconds: ?u64 = null,
    dns_lockdown: bool = false,
    v4_count: usize = 0,
    v6_count: usize = 0,

    pub fn deinit(self: *StatusData, allocator: std.mem.Allocator) void {
        if (self.group) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const Response = struct {
    ok: bool,
    message: ?[]u8 = null,
    status: ?StatusData = null,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        if (self.message) |value| allocator.free(value);
        if (self.status) |*status_ptr| status_ptr.deinit(allocator);
        self.* = undefined;
    }
};

pub fn encodeRequest(allocator: std.mem.Allocator, request: Request) ![]u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(allocator);

    try buffer.appendSlice(allocator, "{\"op\":");
    try appendJsonString(&buffer, allocator, @tagName(request.op));

    if (request.start) |start_cmd| {
        try buffer.appendSlice(allocator, ",\"start\":{");
        try buffer.appendSlice(allocator, "\"group\":");
        try appendJsonString(&buffer, allocator, start_cmd.group);
        try buffer.appendSlice(allocator, ",\"duration_seconds\":");
        try appendUnsigned(&buffer, allocator, start_cmd.duration_seconds);
        try buffer.appendSlice(allocator, ",\"dns_lockdown\":");
        try buffer.appendSlice(allocator, if (start_cmd.dns_lockdown) "true" else "false");
        try buffer.append(allocator, '}');
    }

    try buffer.append(allocator, '}');
    return buffer.toOwnedSlice(allocator);
}

pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) !Request {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const obj = switch (root) {
        .object => |o| o,
        else => return error.InvalidFormat,
    };

    const op_value = obj.get("op") orelse return error.InvalidFormat;
    const op_str = switch (op_value) {
        .string => |s| s,
        else => return error.InvalidFormat,
    };

    const op = std.meta.stringToEnum(RequestOp, op_str) orelse return error.InvalidFormat;

    var request = Request{ .op = op, .start = null };

    if (obj.getPtr("start")) |start_node_ptr| {
        const start_obj = switch (start_node_ptr.*) {
            .object => |o| o,
            else => return error.InvalidFormat,
        };

        const group_value_ptr = start_obj.getPtr("group") orelse return error.InvalidFormat;
        const group_str = switch (group_value_ptr.*) {
            .string => |s| s,
            else => return error.InvalidFormat,
        };
        const group_copy = try allocator.dupe(u8, group_str);

        const duration_value_ptr = start_obj.getPtr("duration_seconds") orelse return error.InvalidFormat;
        const duration_seconds = switch (duration_value_ptr.*) {
            .integer => |i| @as(u64, @intCast(if (i < 0) return error.InvalidFormat else i)),
            else => return error.InvalidFormat,
        };

        const dns_lockdown = if (start_obj.getPtr("dns_lockdown")) |node_ptr| switch (node_ptr.*) {
            .bool => |b| b,
            else => return error.InvalidFormat,
        } else false;

        request.start = StartCommand{
            .group = group_copy,
            .duration_seconds = duration_seconds,
            .dns_lockdown = dns_lockdown,
        };
    }

    return request;
}

pub fn encodeResponse(allocator: std.mem.Allocator, response: Response) ![]u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(allocator);

    try buffer.appendSlice(allocator, "{\"ok\":");
    try buffer.appendSlice(allocator, if (response.ok) "true" else "false");

    if (response.message) |msg| {
        try buffer.appendSlice(allocator, ",\"message\":");
        try appendJsonString(&buffer, allocator, msg);
    }

    if (response.status) |status| {
        try buffer.appendSlice(allocator, ",\"status\":{");
        try buffer.appendSlice(allocator, "\"active\":");
        try buffer.appendSlice(allocator, if (status.active) "true" else "false");

        if (status.group) |group| {
            try buffer.appendSlice(allocator, ",\"group\":");
            try appendJsonString(&buffer, allocator, group);
        }

        if (status.until_epoch) |until_epoch| {
            try buffer.appendSlice(allocator, ",\"until_epoch\":");
            try appendSigned(&buffer, allocator, until_epoch);
        }

        if (status.remaining_seconds) |remaining| {
            try buffer.appendSlice(allocator, ",\"remaining_seconds\":");
            try appendUnsigned(&buffer, allocator, remaining);
        }

        try buffer.appendSlice(allocator, ",\"dns_lockdown\":");
        try buffer.appendSlice(allocator, if (status.dns_lockdown) "true" else "false");

        try buffer.appendSlice(allocator, ",\"tables\":{");
        try buffer.appendSlice(allocator, "\"v4\":");
        try appendUnsigned(&buffer, allocator, status.v4_count);
        try buffer.appendSlice(allocator, ",\"v6\":");
        try appendUnsigned(&buffer, allocator, status.v6_count);
        try buffer.appendSlice(allocator, "}}");
    }

    try buffer.append(allocator, '}');
    return buffer.toOwnedSlice(allocator);
}

pub fn decodeResponse(allocator: std.mem.Allocator, bytes: []const u8) !Response {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const obj = switch (root) {
        .object => |o| o,
        else => return error.InvalidFormat,
    };

    const ok_value_ptr = obj.getPtr("ok") orelse return error.InvalidFormat;
    const ok = switch (ok_value_ptr.*) {
        .bool => |b| b,
        else => return error.InvalidFormat,
    };

    var response = Response{ .ok = ok, .message = null, .status = null };

    if (obj.getPtr("message")) |message_value| {
        const msg_str = switch (message_value.*) {
            .string => |s| s,
            else => return error.InvalidFormat,
        };
        response.message = try allocator.dupe(u8, msg_str);
    }

    if (obj.getPtr("status")) |status_value| {
        const status_obj = switch (status_value.*) {
            .object => |o| o,
            else => return error.InvalidFormat,
        };

        var status = StatusData{ .active = false, .dns_lockdown = false, .v4_count = 0, .v6_count = 0 };

        if (status_obj.getPtr("active")) |active_value| {
            status.active = switch (active_value.*) {
                .bool => |b| b,
                else => return error.InvalidFormat,
            };
        }

        if (status_obj.getPtr("group")) |group_value| {
            const group_str = switch (group_value.*) {
                .string => |s| s,
                else => return error.InvalidFormat,
            };
            status.group = try allocator.dupe(u8, group_str);
        }

        if (status_obj.getPtr("until_epoch")) |until_value| {
            status.until_epoch = switch (until_value.*) {
                .integer => |i| i,
                else => return error.InvalidFormat,
            };
        }

        if (status_obj.getPtr("remaining_seconds")) |remaining_value| {
            status.remaining_seconds = switch (remaining_value.*) {
                .integer => |i| @as(u64, @intCast(if (i < 0) return error.InvalidFormat else i)),
                else => return error.InvalidFormat,
            };
        }

        if (status_obj.getPtr("dns_lockdown")) |dns_value| {
            status.dns_lockdown = switch (dns_value.*) {
                .bool => |b| b,
                else => return error.InvalidFormat,
            };
        }

        if (status_obj.getPtr("tables")) |tables_value| {
            const tables_obj = switch (tables_value.*) {
                .object => |o| o,
                else => return error.InvalidFormat,
            };

            if (tables_obj.getPtr("v4")) |v4_value| {
                status.v4_count = switch (v4_value.*) {
                    .integer => |i| @as(usize, @intCast(if (i < 0) return error.InvalidFormat else i)),
                    else => return error.InvalidFormat,
                };
            }

            if (tables_obj.getPtr("v6")) |v6_value| {
                status.v6_count = switch (v6_value.*) {
                    .integer => |i| @as(usize, @intCast(if (i < 0) return error.InvalidFormat else i)),
                    else => return error.InvalidFormat,
                };
            }
        }

        response.status = status;
    }

    return response;
}

fn appendJsonString(buffer: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try buffer.append(allocator, '"');
    for (value) |ch| {
        switch (ch) {
            '"' => try buffer.appendSlice(allocator, "\\\""),
            '\\' => try buffer.appendSlice(allocator, "\\\\"),
            '\n' => try buffer.appendSlice(allocator, "\\n"),
            '\r' => try buffer.appendSlice(allocator, "\\r"),
            '\t' => try buffer.appendSlice(allocator, "\\t"),
            else => {
                if (ch < 0x20) {
                    var tmp: [6]u8 = undefined;
                    const written = try std.fmt.bufPrint(&tmp, "\\u{0:0>4}", .{@as(u16, ch)});
                    try buffer.appendSlice(allocator, written);
                } else {
                    try buffer.append(allocator, ch);
                }
            },
        }
    }
    try buffer.append(allocator, '"');
}

fn appendUnsigned(buffer: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: anytype) !void {
    var tmp: [32]u8 = undefined;
    const slice = try std.fmt.bufPrint(&tmp, "{}", .{value});
    try buffer.appendSlice(allocator, slice);
}

fn appendSigned(buffer: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: anytype) !void {
    var tmp: [32]u8 = undefined;
    const slice = try std.fmt.bufPrint(&tmp, "{}", .{value});
    try buffer.appendSlice(allocator, slice);
}

test "encode/decode start request round trip" {
    var allocator = testing.allocator;
    var request = Request{
        .op = .start,
        .start = StartCommand{
            .group = try allocator.dupe(u8, "default"),
            .duration_seconds = 60,
            .dns_lockdown = true,
        },
    };
    defer request.deinit(allocator);

    const encoded = try encodeRequest(allocator, request);
    defer allocator.free(encoded);

    var decoded = try decodeRequest(allocator, encoded);
    defer decoded.deinit(allocator);

    try testing.expectEqual(RequestOp.start, decoded.op);
    try testing.expect(decoded.start != null);
    try testing.expectEqualStrings("default", decoded.start.?.group);
    try testing.expectEqual(@as(u64, 60), decoded.start.?.duration_seconds);
    try testing.expect(decoded.start.?.dns_lockdown);
}

test "decodeRequest fails on missing op" {
    const payload = "{\"start\":{}}";
    try testing.expectError(Error.InvalidFormat, decodeRequest(testing.allocator, payload));
}

test "encode/decode response with status" {
    var allocator = testing.allocator;
    var response = Response{
        .ok = true,
        .status = StatusData{ .active = true, .group = try allocator.dupe(u8, "default"), .until_epoch = 123, .remaining_seconds = 45, .dns_lockdown = false, .v4_count = 2, .v6_count = 1 },
    };
    defer response.deinit(allocator);

    const encoded = try encodeResponse(allocator, response);
    defer allocator.free(encoded);

    var decoded = try decodeResponse(allocator, encoded);
    defer decoded.deinit(allocator);

    try testing.expect(decoded.ok);
    try testing.expect(decoded.status != null);
    try testing.expectEqualStrings("default", decoded.status.?.group.?);
    try testing.expectEqual(@as(usize, 2), decoded.status.?.v4_count);
}
