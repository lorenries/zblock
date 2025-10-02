const std = @import("std");
const fs_util = @import("fs.zig");
const dns = @import("dns.zig");
const Paths = @import("paths.zig");
const testing = std.testing;

const log = std.log;

pub const anchor_path = "/etc/pf.anchors/zblock";

const anchor_name = "com.apple/zblock";
pub const anchor_target = anchor_name;
const table_v4 = "zblock_v4";
const table_v6 = "zblock_v6";
const table_doh = "zblock_doh";

pub const PfError = error{
    CommandFailed,
};

pub const ApplyResult = struct {
    v4_count: usize,
    v6_count: usize,
    pf_was_enabled: bool,
};

pub fn ensureAnchorTemplate(allocator: std.mem.Allocator, paths: *const Paths.Paths) !void {
    try writeAnchor(allocator, paths, false);
}

pub fn applyRules(allocator: std.mem.Allocator, paths: *const Paths.Paths, targets: dns.Targets, dns_lockdown: bool) !ApplyResult {
    try writeTables(allocator, paths, targets);

    const pf_was_enabled = try ensurePfEnabled(allocator);

    try writeAnchor(allocator, paths, dns_lockdown);
    try runPfctl(allocator, &.{ "pfctl", "-a", anchor_name, "-f", anchor_path }, "load anchor");

    try replaceTable(allocator, table_v4, paths.blockedV4TablePath());
    try replaceTable(allocator, table_v6, paths.blockedV6TablePath());

    // Always replace the DoH table so it exists and reflects the desired state.
    // When dns_lockdown is disabled the table is just empty, which keeps pfctl
    // happy without requiring a flush against a possibly-missing table.
    try replaceTable(allocator, table_doh, paths.dohTablePath());

    return ApplyResult{
        .v4_count = targets.v4.len,
        .v6_count = targets.v6.len,
        .pf_was_enabled = pf_was_enabled,
    };
}

pub fn clearRules(allocator: std.mem.Allocator, paths: *const Paths.Paths, pf_was_enabled: bool) !void {
    runPfctl(allocator, &.{ "pfctl", "-t", table_v4, "-T", "flush" }, "flush IPv4 table") catch |err| {
        log.warn("failed to flush {s}: {s}", .{ table_v4, @errorName(err) });
    };
    runPfctl(allocator, &.{ "pfctl", "-t", table_v6, "-T", "flush" }, "flush IPv6 table") catch |err| {
        log.warn("failed to flush {s}: {s}", .{ table_v6, @errorName(err) });
    };
    runPfctl(allocator, &.{ "pfctl", "-t", table_doh, "-T", "flush" }, "flush DoH table") catch |err| {
        log.warn("failed to flush {s}: {s}", .{ table_doh, @errorName(err) });
    };

    fs_util.atomicWriteFileAbsolute(paths.blockedV4TablePath(), "") catch |err| {
        log.warn("failed to truncate {s}: {s}", .{ paths.blockedV4TablePath(), @errorName(err) });
    };
    fs_util.atomicWriteFileAbsolute(paths.blockedV6TablePath(), "") catch |err| {
        log.warn("failed to truncate {s}: {s}", .{ paths.blockedV6TablePath(), @errorName(err) });
    };
    fs_util.atomicWriteFileAbsolute(paths.dohTablePath(), "") catch |err| {
        log.warn("failed to truncate {s}: {s}", .{ paths.dohTablePath(), @errorName(err) });
    };

    writeAnchor(allocator, paths, false) catch |err| {
        log.warn("failed to reset anchor template: {s}", .{@errorName(err)});
    };
    runPfctl(allocator, &.{ "pfctl", "-a", anchor_name, "-f", anchor_path }, "reload anchor") catch |err| {
        log.warn("failed to reload anchor: {s}", .{@errorName(err)});
    };

    if (!pf_was_enabled) {
        runPfctl(allocator, &.{ "pfctl", "-d" }, "disable pf") catch |err| {
            log.warn("failed to disable pf: {s}", .{@errorName(err)});
        };
    }
}

test "renderAnchor emits dns lockdown rules" {
    var gpa = testing.allocator;
    var tmp = try testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(gpa, ".");
    defer gpa.free(base);

    const config_dir = try std.fs.path.join(gpa, &.{ base, "config" });
    const state_dir = try std.fs.path.join(gpa, &.{ base, "state" });
    const log_dir = try std.fs.path.join(gpa, &.{ base, "log" });
    const run_dir = try std.fs.path.join(gpa, &.{ base, "run" });
    defer gpa.free(config_dir);
    defer gpa.free(state_dir);
    defer gpa.free(log_dir);
    defer gpa.free(run_dir);

    try tmp.dir.makePath("config");
    try tmp.dir.makePath("state");
    try tmp.dir.makePath("log");
    try tmp.dir.makePath("run");

    var paths = try Paths.init(gpa, .{
        .config_dir = config_dir,
        .state_dir = state_dir,
        .log_dir = log_dir,
        .run_dir = run_dir,
    });
    defer paths.deinit();

    const anchor_contents = try renderAnchor(gpa, &paths, true);
    defer gpa.free(anchor_contents);

    try testing.expect(std.mem.indexOf(u8, anchor_contents, "block out quick proto { udp tcp } from any to any port 53") != null);
    try testing.expect(std.mem.indexOf(u8, anchor_contents, "table <zblock_v4>") != null);
}

test "writeList writes newline separated data" {
    var tmp = try testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);

    const file_path = try std.fs.path.join(testing.allocator, &.{ base, "list.txt" });
    defer testing.allocator.free(file_path);

    var entries = try testing.allocator.alloc([]u8, 2);
    defer {
        for (entries) |entry| testing.allocator.free(entry);
        testing.allocator.free(entries);
    }
    entries[0] = try testing.allocator.dupe(u8, "1.2.3.4");
    entries[1] = try testing.allocator.dupe(u8, "5.6.7.8");

    try writeList(testing.allocator, file_path, entries);

    var file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();
    const contents = try file.readToEndAlloc(testing.allocator, 1024);
    defer testing.allocator.free(contents);

    try testing.expectEqualStrings("1.2.3.4\n5.6.7.8", contents);
}

pub fn uninstallCleanup(allocator: std.mem.Allocator) void {
    runPfctl(allocator, &.{ "pfctl", "-a", anchor_name, "-F", "all" }, "flush anchor") catch |err| {
        log.warn("failed to flush zblock anchor during uninstall: {s}", .{@errorName(err)});
    };
    runPfctl(allocator, &.{ "pfctl", "-t", table_v4, "-T", "flush" }, "flush IPv4 table") catch |err| {
        log.warn("failed to flush {s} during uninstall: {s}", .{ table_v4, @errorName(err) });
    };
    runPfctl(allocator, &.{ "pfctl", "-t", table_v6, "-T", "flush" }, "flush IPv6 table") catch |err| {
        log.warn("failed to flush {s} during uninstall: {s}", .{ table_v6, @errorName(err) });
    };
    runPfctl(allocator, &.{ "pfctl", "-t", table_doh, "-T", "flush" }, "flush DoH table") catch |err| {
        log.warn("failed to flush {s} during uninstall: {s}", .{ table_doh, @errorName(err) });
    };
}

pub fn isEnabled(allocator: std.mem.Allocator) !bool {
    const result = try runPfctlCapture(allocator, &.{ "pfctl", "-s", "info" }, "pf status");
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const stdout = result.stdout;
    return std.mem.indexOf(u8, stdout, "Status: Enabled") != null;
}

fn ensurePfEnabled(allocator: std.mem.Allocator) !bool {
    const enabled = try isEnabled(allocator);
    if (enabled) return true;

    try runPfctl(allocator, &.{ "pfctl", "-E" }, "enable pf");
    return false;
}

fn replaceTable(allocator: std.mem.Allocator, name: []const u8, path: []const u8) !void {
    try runPfctl(allocator, &.{ "pfctl", "-t", name, "-T", "replace", "-f", path }, "replace table");
}

fn writeTables(allocator: std.mem.Allocator, paths: *const Paths.Paths, targets: dns.Targets) !void {
    try writeList(allocator, paths.blockedV4TablePath(), targets.v4);
    try writeList(allocator, paths.blockedV6TablePath(), targets.v6);
    try writeList(allocator, paths.dohTablePath(), &.{});
}

fn writeList(allocator: std.mem.Allocator, path: []const u8, entries: [][]u8) !void {
    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(allocator);

    for (entries, 0..) |entry, index| {
        if (index != 0) try buffer.append(allocator, '\n');
        try buffer.appendSlice(allocator, entry);
    }

    const data = try buffer.toOwnedSlice(allocator);
    defer allocator.free(data);
    try fs_util.atomicWriteFileAbsolute(path, data);
}

fn writeAnchor(allocator: std.mem.Allocator, paths: *const Paths.Paths, dns_lockdown: bool) !void {
    const contents = try renderAnchor(allocator, paths, dns_lockdown);
    defer allocator.free(contents);
    try fs_util.atomicWriteFileAbsoluteWithMode(anchor_path, contents, 0o644);
}

fn renderAnchor(allocator: std.mem.Allocator, paths: *const Paths.Paths, dns_lockdown: bool) ![]u8 {
    const dns_rules = if (dns_lockdown)
        "block out quick proto { udp tcp } from any to any port 53\n" ++
            "block out quick proto tcp from any to any port 853\n" ++
            "block out quick proto { udp tcp } from any to <zblock_doh> port { 443 853 }\n\n"
    else
        "";

    return std.fmt.allocPrint(
        allocator,
        "table <zblock_v4> persist file \"{s}\"\n" ++
            "table <zblock_v6> persist file \"{s}\"\n" ++
            "table <zblock_doh> persist file \"{s}\"\n\n" ++
            "{s}" ++
            "block out quick from any to <zblock_v4>\n" ++
            "block out quick from any to <zblock_v6>\n",
        .{ paths.blockedV4TablePath(), paths.blockedV6TablePath(), paths.dohTablePath(), dns_rules },
    );
}

fn runPfctl(allocator: std.mem.Allocator, argv: []const []const u8, description: []const u8) !void {
    var result = try std.process.Child.run(.{ .allocator = allocator, .argv = argv });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| {
            if (code == 0) return;
            log.err("pfctl {s} failed (exit code {d}): {s}", .{ description, code, result.stderr });
            return PfError.CommandFailed;
        },
        else => {
            log.err("pfctl {s} terminated unexpectedly", .{description});
            return PfError.CommandFailed;
        },
    }
}

const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,
};

fn runPfctlCapture(allocator: std.mem.Allocator, argv: []const []const u8, description: []const u8) !CommandOutput {
    var result = try std.process.Child.run(.{ .allocator = allocator, .argv = argv });

    switch (result.term) {
        .Exited => |code| {
            if (code == 0) {
                return CommandOutput{ .stdout = result.stdout, .stderr = result.stderr };
            }
            log.err("pfctl {s} failed (exit code {d}): {s}", .{ description, code, result.stderr });
            allocator.free(result.stdout);
            allocator.free(result.stderr);
            return PfError.CommandFailed;
        },
        else => {
            log.err("pfctl {s} terminated unexpectedly", .{description});
            allocator.free(result.stdout);
            allocator.free(result.stderr);
            return PfError.CommandFailed;
        },
    }
}
