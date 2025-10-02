const std = @import("std");
const testing = std.testing;

pub const Targets = struct {
    v4: [][]u8,
    v6: [][]u8,

    pub fn deinit(self: *Targets, allocator: std.mem.Allocator) void {
        for (self.v4) |addr| allocator.free(addr);
        allocator.free(self.v4);
        for (self.v6) |addr| allocator.free(addr);
        allocator.free(self.v6);
        self.* = undefined;
    }
};

pub fn resolveDomains(allocator: std.mem.Allocator, domains: []const []const u8) !Targets {
    var v4_list = std.ArrayListUnmanaged([]u8){};
    errdefer {
        for (v4_list.items) |addr| allocator.free(addr);
        v4_list.deinit(allocator);
    }

    var v6_list = std.ArrayListUnmanaged([]u8){};
    errdefer {
        for (v6_list.items) |addr| allocator.free(addr);
        v6_list.deinit(allocator);
    }

    for (domains) |domain| {
        resolveHost(allocator, domain, &v4_list, &v6_list) catch {};

        if (shouldResolveWwwAlias(domain)) {
            const alias = std.fmt.allocPrint(allocator, "www.{s}", .{domain}) catch continue;
            defer allocator.free(alias);
            resolveHost(allocator, alias, &v4_list, &v6_list) catch {};
        }
    }

    return Targets{
        .v4 = try v4_list.toOwnedSlice(allocator),
        .v6 = try v6_list.toOwnedSlice(allocator),
    };
}

fn resolveHost(
    allocator: std.mem.Allocator,
    host: []const u8,
    v4_list: *std.ArrayListUnmanaged([]u8),
    v6_list: *std.ArrayListUnmanaged([]u8),
) !void {
    var list = std.net.getAddressList(allocator, host, 0) catch return;
    defer list.deinit();

    for (list.addrs) |addr| {
        const rendered = addressToString(allocator, addr) catch continue;

        switch (addr.any.family) {
            std.posix.AF.INET => appendUnique(v4_list, allocator, rendered) catch allocator.free(rendered),
            std.posix.AF.INET6 => appendUnique(v6_list, allocator, rendered) catch allocator.free(rendered),
            else => allocator.free(rendered),
        }
    }
}

fn shouldResolveWwwAlias(domain: []const u8) bool {
    if (domain.len == 0) return false;
    if (std.mem.startsWith(u8, domain, "www.")) return false;
    return countDots(domain) == 1;
}

fn countDots(slice: []const u8) usize {
    var total: usize = 0;
    for (slice) |ch| {
        if (ch == '.') total += 1;
    }
    return total;
}

test "appendUnique deduplicates entries" {
    var list = std.ArrayListUnmanaged([]u8){};
    defer {
        for (list.items) |addr| testing.allocator.free(addr);
        list.deinit(testing.allocator);
    }

    try appendUnique(&list, testing.allocator, try testing.allocator.dupe(u8, "1.2.3.4"));
    try appendUnique(&list, testing.allocator, try testing.allocator.dupe(u8, "1.2.3.4"));
    try appendUnique(&list, testing.allocator, try testing.allocator.dupe(u8, "5.6.7.8"));

    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expect(std.mem.eql(u8, list.items[0], "1.2.3.4"));
    try testing.expect(std.mem.eql(u8, list.items[1], "5.6.7.8"));
}

test "shouldResolveWwwAlias logic" {
    try testing.expect(!shouldResolveWwwAlias(""));
    try testing.expect(!shouldResolveWwwAlias("www.example.com"));
    try testing.expect(shouldResolveWwwAlias("example.com"));
    try testing.expect(!shouldResolveWwwAlias("deep.sub.example.com"));
}

fn appendUnique(list: *std.ArrayListUnmanaged([]u8), allocator: std.mem.Allocator, addr: []u8) !void {
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, addr)) {
            allocator.free(addr);
            return;
        }
    }
    try list.append(allocator, addr);
}

fn addressToString(allocator: std.mem.Allocator, addr: std.net.Address) ![]u8 {
    if (addr.any.family == std.posix.AF.INET) {
        const ip4 = addr.in;
        const octets = @as(*const [4]u8, @ptrCast(&ip4.sa.addr));
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            octets[0],
            octets[1],
            octets[2],
            octets[3],
        });
    }

    if (addr.any.family == std.posix.AF.INET6) {
        const ip6 = addr.in6;
        var list = std.ArrayListUnmanaged(u8){};
        errdefer list.deinit(allocator);

        const bytes = ip6.sa.addr;
        var i: usize = 0;
        while (i < 16) : (i += 2) {
            const value = (@as(u16, bytes[i]) << 8) | bytes[i + 1];
            var segment_buf: [4]u8 = undefined;
            const segment = try std.fmt.bufPrint(&segment_buf, "{x:0>4}", .{value});
            try list.appendSlice(allocator, segment);
            if (i < 14) try list.append(allocator, ':');
        }

        return list.toOwnedSlice(allocator);
    }

    return error.UnsupportedAddress;
}
