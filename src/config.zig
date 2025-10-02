const std = @import("std");
const fs_util = @import("fs.zig");

pub const Error = error{
    InvalidDomain,
    EmptyDomain,
    InvalidGroupName,
};

pub const DomainSet = std.StringArrayHashMapUnmanaged(void);

pub const Config = struct {
    allocator: std.mem.Allocator,
    groups: std.StringArrayHashMapUnmanaged(DomainSet),

    pub const default_group = "default";
    pub const max_config_bytes: usize = 1 << 18; // 256 KiB upper bound

    pub fn init(allocator: std.mem.Allocator) Config {
        return Config{
            .allocator = allocator,
            .groups = .{},
        };
    }

    pub fn deinit(self: *Config) void {
        var it = self.groups.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.groups.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn ensureGroup(self: *Config, group_name: []const u8) !*DomainSet {
        const normalized = try normalizeGroupName(self.allocator, group_name);
        var free_normalized = true;
        defer if (free_normalized) self.allocator.free(normalized);

        var entry = try self.groups.getOrPut(self.allocator, normalized);
        if (entry.found_existing) {
            return entry.value_ptr;
        }

        entry.key_ptr.* = normalized;
        entry.value_ptr.* = DomainSet{};
        free_normalized = false;
        return entry.value_ptr;
    }

    pub fn hasGroup(self: *const Config, group_name: []const u8) bool {
        return getGroup(self, group_name) != null;
    }

    pub fn getGroup(self: *const Config, group_name: []const u8) ?*const DomainSet {
        const normalized = normalizeGroupName(self.allocator, group_name) catch return null;
        defer self.allocator.free(normalized);
        return self.groups.getPtr(normalized);
    }

    pub fn addDomains(self: *Config, group_name: []const u8, domains: []const []const u8) !void {
        var group_ptr = try self.ensureGroup(group_name);
        for (domains) |domain| {
            const normalized = normalizeDomain(self.allocator, domain) catch |err| switch (err) {
                Error.EmptyDomain, Error.InvalidDomain => return err,
                else => return err,
            };
            var free_normalized = true;
            defer if (free_normalized) self.allocator.free(normalized);

            var domain_entry = try group_ptr.getOrPut(self.allocator, normalized);
            if (domain_entry.found_existing) {
                continue;
            }

            domain_entry.key_ptr.* = normalized;
            domain_entry.value_ptr.* = {};
            free_normalized = false;
        }
    }

    pub fn groupsIterator(self: *const Config) std.StringArrayHashMapUnmanaged(DomainSet).Iterator {
        return self.groups.iterator();
    }

    pub fn domainIterator(group: *const DomainSet) DomainIterator {
        return DomainIterator{ .inner = group.iterator() };
    }

    pub fn sortedDomains(self: *const Config, allocator: std.mem.Allocator, group_name: []const u8) ![][]const u8 {
        const group = self.getGroup(group_name) orelse return error.InvalidGroupName;
        var list = std.ArrayListUnmanaged([]const u8){};
        errdefer list.deinit(allocator);

        var it = group.iterator();
        while (it.next()) |entry| {
            try list.append(allocator, entry.key_ptr.*);
        }
        std.mem.sort([]const u8, list.items, {}, compareStringLessThan);
        return list.toOwnedSlice(allocator);
    }

    fn compareStringLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
        return std.mem.lessThan(u8, lhs, rhs);
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        var file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => {
                var cfg = Config.init(allocator);
                errdefer cfg.deinit();
                _ = try cfg.ensureGroup(default_group);
                return cfg;
            },
            else => return err,
        };
        defer file.close();

        const file_size = try file.getEndPos();
        if (file_size > max_config_bytes) return error.FileTooBig;

        if (file_size == 0) {
            var cfg = Config.init(allocator);
            errdefer cfg.deinit();
            _ = try cfg.ensureGroup(default_group);
            return cfg;
        }

        const alloc_len = std.math.cast(usize, file_size) orelse return error.FileTooBig;
        var buffer = try allocator.alloc(u8, alloc_len);
        defer allocator.free(buffer);

        const read_len = try file.readAll(buffer);
        const bytes = buffer[0..read_len];

        if (bytes.len == 0) {
            var cfg = Config.init(allocator);
            errdefer cfg.deinit();
            _ = try cfg.ensureGroup(default_group);
            return cfg;
        }

        return parseFromSlice(allocator, bytes);
    }

    pub fn parseFromSlice(allocator: std.mem.Allocator, bytes: []const u8) !Config {
        var config = Config.init(allocator);
        errdefer config.deinit();

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer parsed.deinit();

        const root = parsed.value;
        switch (root) {
            .object => |obj| {
                if (obj.get("groups")) |groups_node| {
                    try parseGroups(&config, groups_node);
                }
            },
            else => return error.InvalidFormat,
        }

        if (!config.hasGroup(default_group)) {
            _ = try config.ensureGroup(default_group);
        }

        return config;
    }

    fn parseGroups(config: *Config, node: std.json.Value) !void {
        const obj = switch (node) {
            .object => |o| o,
            else => return error.InvalidFormat,
        };

        var it = obj.iterator();
        while (it.next()) |entry| {
            const group_name = entry.key_ptr.*;
            const values = entry.value_ptr.*;
            const arr = switch (values) {
                .array => |a| a,
                else => return error.InvalidFormat,
            };

            var tmp_domains = std.ArrayListUnmanaged([]const u8){};
            defer tmp_domains.deinit(config.allocator);

            for (arr.items) |domain_value| {
                const str = switch (domain_value) {
                    .string => |s| s,
                    else => return error.InvalidFormat,
                };
                try tmp_domains.append(config.allocator, str);
            }

            try config.addDomains(group_name, tmp_domains.items);
        }
    }

    pub fn saveToFile(self: *const Config, path: []const u8) !void {
        const payload = try self.toJson(self.allocator);
        defer self.allocator.free(payload);

        try fs_util.atomicWriteFileAbsolute(path, payload);
    }

    pub fn toJson(self: *const Config, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayListUnmanaged(u8){};
        errdefer buffer.deinit(allocator);

        try buffer.appendSlice(allocator, "{\n  \"groups\": {\n");

        var group_it = self.groupsIterator();
        var first_group = true;
        while (group_it.next()) |entry| {
            if (!first_group) {
                try buffer.appendSlice(allocator, ",\n");
            }
            first_group = false;

            try buffer.appendSlice(allocator, "    \"");
            try buffer.appendSlice(allocator, entry.key_ptr.*);
            try buffer.appendSlice(allocator, "\": [");

            var domain_it = entry.value_ptr.iterator();
            var domain_index: usize = 0;
            while (domain_it.next()) |domain_entry| {
                if (domain_index != 0) try buffer.appendSlice(allocator, ", ");
                try buffer.appendSlice(allocator, "\"");
                try buffer.appendSlice(allocator, domain_entry.key_ptr.*);
                try buffer.appendSlice(allocator, "\"");
                domain_index += 1;
            }

            try buffer.appendSlice(allocator, "]");
        }

        if (!first_group) {
            try buffer.appendSlice(allocator, "\n");
        }

        try buffer.appendSlice(allocator, "  }\n}\n");
        return buffer.toOwnedSlice(allocator);
    }
};

pub const DomainIterator = struct {
    inner: DomainSet.Iterator,

    pub fn next(self: *DomainIterator) ?[]const u8 {
        if (self.inner.next()) |entry| {
            return entry.key_ptr.*;
        }
        return null;
    }
};

fn normalizeGroupName(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return Error.InvalidGroupName;

    const buf = try allocator.dupe(u8, trimmed);
    errdefer allocator.free(buf);

    for (buf) |*c| {
        if (c.* == '-' or c.* == '_' or c.* == '.') {
            continue;
        }
        if (!std.ascii.isAlphanumeric(c.*)) {
            return Error.InvalidGroupName;
        }
        c.* = std.ascii.toLower(c.*);
    }

    return buf;
}

pub fn normalizeGroupNameCopy(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    return normalizeGroupName(allocator, raw);
}

fn normalizeDomain(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return Error.EmptyDomain;

    if (std.mem.indexOfScalar(u8, trimmed, '/') != null) return Error.InvalidDomain;
    if (std.mem.indexOf(u8, trimmed, "://")) |_| return Error.InvalidDomain;
    if (std.mem.indexOfScalar(u8, trimmed, ':') != null) return Error.InvalidDomain;

    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '.') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    if (trimmed.len == 0) return Error.InvalidDomain;

    const buf = try allocator.dupe(u8, trimmed);
    errdefer allocator.free(buf);

    var label_start: usize = 0;
    var idx: usize = 0;
    while (idx < buf.len) : (idx += 1) {
        var c = buf[idx];
        if (std.ascii.isUpper(c)) {
            c = std.ascii.toLower(c);
            buf[idx] = c;
        }

        switch (c) {
            '-' => {
                if (idx == label_start) return Error.InvalidDomain;
            },
            '.' => {
                if (idx == label_start) return Error.InvalidDomain;
                if (buf[idx - 1] == '-') return Error.InvalidDomain;
                if (idx - label_start > 63) return Error.InvalidDomain;
                label_start = idx + 1;
            },
            else => {
                if (!std.ascii.isDigit(c) and !std.ascii.isLower(c)) {
                    return Error.InvalidDomain;
                }
            },
        }
    }

    if (buf[buf.len - 1] == '-') return Error.InvalidDomain;
    if (buf.len - label_start > 63) return Error.InvalidDomain;

    return buf;
}

test "normalize domain" {
    const allocator = std.testing.allocator;
    const normalized = try normalizeDomain(allocator, " Example.COM. ");
    defer allocator.free(normalized);
    try std.testing.expect(std.mem.eql(u8, normalized, "example.com"));
}

test "reject invalid domain" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidDomain, normalizeDomain(allocator, "http://example.com"));
    try std.testing.expectError(Error.InvalidDomain, normalizeDomain(allocator, "example_com"));
    try std.testing.expectError(Error.InvalidDomain, normalizeDomain(allocator, ".example.com"));
}

test "add domains deduplicates" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try config.addDomains("default", &.{ "Example.com", "example.com", "sub.example.com" });

    const group = config.getGroup("default").?;
    try std.testing.expectEqual(@as(usize, 2), group.count());
    try std.testing.expect(group.contains("example.com"));
    try std.testing.expect(group.contains("sub.example.com"));
}

test "serialize and parse round trip" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try config.addDomains("default", &.{"example.com"});
    try config.addDomains("social", &.{ "twitter.com", "reddit.com" });

    const json = try config.toJson(allocator);
    defer allocator.free(json);

    var parsed = try Config.parseFromSlice(allocator, json);
    defer parsed.deinit();

    const social = parsed.getGroup("social").?;
    try std.testing.expectEqual(@as(usize, 2), social.count());
}
