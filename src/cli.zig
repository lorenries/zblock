const std = @import("std");
const posix = std.posix;
const paths_mod = @import("paths.zig");
const config_mod = @import("config.zig");
const fs_util = @import("fs.zig");
const pf = @import("pf.zig");
const ipc = @import("ipc.zig");

const InitError = error{
    MissingDaemonSource,
};

pub const RunContext = struct {
    allocator: std.mem.Allocator,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
};

fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try posix.write(fd, bytes[offset..]);
        if (written == 0) return error.ShortWrite;
        offset += written;
    }
}

fn printFmt(allocator: std.mem.Allocator, fd: posix.fd_t, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(rendered);
    try writeAll(fd, rendered);
}

pub fn run(ctx: RunContext, args: *std.process.ArgIterator) !u8 {
    _ = args.next(); // executable name

    const command = args.next() orelse {
        try printUsage(ctx.stderr_fd);
        return 1;
    };

    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try printUsage(ctx.stdout_fd);
        return 0;
    }

    if (std.mem.eql(u8, command, "add")) return handleAdd(ctx, args);
    if (std.mem.eql(u8, command, "list")) return handleList(ctx, args);
    if (std.mem.eql(u8, command, "init")) return handleInit(ctx, args);
    if (std.mem.eql(u8, command, "start")) return handleStart(ctx, args);
    if (std.mem.eql(u8, command, "status")) return handleStatus(ctx, args);
    if (std.mem.eql(u8, command, "uninstall")) return handleUninstall(ctx, args);

    try printFmt(ctx.allocator, ctx.stderr_fd, "zblock: unknown command '{s}'\n", .{command});
    try printUsage(ctx.stderr_fd);
    return 1;
}

fn handleAdd(ctx: RunContext, args: *std.process.ArgIterator) !u8 {
    const allocator = ctx.allocator;
    var domains = std.ArrayListUnmanaged([]const u8){};
    defer domains.deinit(allocator);

    var group_override: ?[]const u8 = null;
    var expect_group_name = false;
    var parsing_options = true;

    while (args.next()) |arg| {
        if (expect_group_name) {
            group_override = arg;
            expect_group_name = false;
            continue;
        }

        if (parsing_options and arg.len > 0 and arg[0] == '-') {
            if (std.mem.eql(u8, arg, "--")) {
                parsing_options = false;
                continue;
            }
            if (std.mem.eql(u8, arg, "--group")) {
                expect_group_name = true;
                continue;
            }
            if (std.mem.startsWith(u8, arg, "--group=")) {
                group_override = arg[8..];
                continue;
            }
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                try printAddHelp(ctx.stdout_fd);
                return 0;
            }
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock add: unknown option '{s}'\n", .{arg});
            return 1;
        }

        try domains.append(allocator, arg);
    }

    if (expect_group_name) {
        try writeAll(ctx.stderr_fd, "zblock add: expected group name after --group\n");
        return 1;
    }
    if (domains.items.len == 0) {
        try writeAll(ctx.stderr_fd, "zblock add: please provide at least one domain\n");
        return 1;
    }

    const group_slice = group_override orelse config_mod.Config.default_group;
    var normalized_group_buf: ?[]u8 = null;
    defer if (normalized_group_buf) |buf| allocator.free(buf);

    const group_for_config: []const u8 = if (group_override) |_| blk: {
        const buf = try config_mod.normalizeGroupNameCopy(allocator, group_slice);
        normalized_group_buf = buf;
        break :blk buf;
    } else config_mod.Config.default_group;

    var paths = try paths_mod.Paths.initFromEnv(allocator);
    defer paths.deinit();

    try paths.ensureConfigDir();
    const config_path = try paths.configFile();
    defer allocator.free(config_path);

    var config = try config_mod.Config.loadFromFile(allocator, config_path);
    defer config.deinit();

    const before_count = if (config.getGroup(group_for_config)) |grp| grp.count() else 0;
    try config.addDomains(group_for_config, domains.items);
    try config.saveToFile(config_path);

    const after_count = config.getGroup(group_for_config).?.count();
    const added = after_count - before_count;
    if (added == 0) {
        try printFmt(ctx.allocator, ctx.stdout_fd, "No new domains added; all {d} provided were already present in group '{s}'.\n", .{ domains.items.len, group_for_config });
    } else {
        try printFmt(ctx.allocator, ctx.stdout_fd, "Added {d} domain{s} to group '{s}'.\n", .{ added, if (added == 1) "" else "s", group_for_config });
    }
    return 0;
}

fn handleList(ctx: RunContext, args: *std.process.ArgIterator) !u8 {
    const allocator = ctx.allocator;
    var group_filter: ?[]const u8 = null;
    var expect_group_name = false;
    var parsing_options = true;
    var output_json = false;

    while (args.next()) |arg| {
        if (expect_group_name) {
            group_filter = arg;
            expect_group_name = false;
            continue;
        }

        if (parsing_options and arg.len > 0 and arg[0] == '-') {
            if (std.mem.eql(u8, arg, "--")) {
                parsing_options = false;
                continue;
            }
            if (std.mem.eql(u8, arg, "--group")) {
                expect_group_name = true;
                continue;
            }
            if (std.mem.startsWith(u8, arg, "--group=")) {
                group_filter = arg[8..];
                continue;
            }
            if (std.mem.eql(u8, arg, "--json")) {
                output_json = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                try printListHelp(ctx.stdout_fd);
                return 0;
            }
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock list: unknown option '{s}'\n", .{arg});
            return 1;
        } else {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock list: unexpected positional argument '{s}'\n", .{arg});
            return 1;
        }
    }

    if (expect_group_name) {
        try writeAll(ctx.stderr_fd, "zblock list: expected group name after --group\n");
        return 1;
    }

    var paths = try paths_mod.Paths.initFromEnv(allocator);
    defer paths.deinit();

    const config_path = try paths.configFile();
    defer allocator.free(config_path);

    var config = try config_mod.Config.loadFromFile(allocator, config_path);
    defer config.deinit();

    if (group_filter) |group_raw| {
        if (config.getGroup(group_raw) == null) {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock list: group '{s}' not found\n", .{group_raw});
            return 1;
        }

        const domains = try config.sortedDomains(allocator, group_raw);
        defer allocator.free(domains);

        const normalized = try config_mod.normalizeGroupNameCopy(allocator, group_raw);
        defer allocator.free(normalized);

        if (output_json) {
            var subset = config_mod.Config.init(allocator);
            defer subset.deinit();

            try subset.addDomains(group_raw, domains);
            const payload = try subset.toJson(allocator);
            defer allocator.free(payload);
            try writeAll(ctx.stdout_fd, payload);
            try writeAll(ctx.stdout_fd, "\n");
            return 0;
        }

        try printFmt(ctx.allocator, ctx.stdout_fd, "Group '{s}' ({d} domains)\n", .{ normalized, domains.len });
        if (domains.len == 0) {
            try writeAll(ctx.stdout_fd, "  (empty)\n");
        } else {
            for (domains) |domain| {
                try printFmt(ctx.allocator, ctx.stdout_fd, "  - {s}\n", .{domain});
            }
        }
        return 0;
    }

    if (output_json) {
        const payload = try config.toJson(allocator);
        defer allocator.free(payload);
        try writeAll(ctx.stdout_fd, payload);
        try writeAll(ctx.stdout_fd, "\n");
        return 0;
    }

    var group_it = config.groupsIterator();
    var first_group = true;
    while (group_it.next()) |entry| {
        if (!first_group) try writeAll(ctx.stdout_fd, "\n");
        first_group = false;

        const group_name = entry.key_ptr.*;
        const domains = try config.sortedDomains(allocator, group_name);
        defer allocator.free(domains);

        try printFmt(ctx.allocator, ctx.stdout_fd, "Group '{s}' ({d} domains)\n", .{ group_name, domains.len });
        if (domains.len == 0) {
            try writeAll(ctx.stdout_fd, "  (empty)\n");
        } else {
            for (domains) |domain| {
                try printFmt(ctx.allocator, ctx.stdout_fd, "  - {s}\n", .{domain});
            }
        }
    }

    if (first_group) {
        try writeAll(ctx.stdout_fd, "No groups configured yet.\n");
    }

    return 0;
}

fn handleInit(ctx: RunContext, args: *std.process.ArgIterator) !u8 {
    if (args.next()) |unexpected| {
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock init: unexpected argument '{s}'\n", .{unexpected});
        return 1;
    }

    var paths = try paths_mod.Paths.initFromEnv(ctx.allocator);
    defer paths.deinit();

    try paths.ensureConfigDir();
    paths.ensureStateDir() catch |err| {
        switch (err) {
            error.AccessDenied, error.PermissionDenied => return reportPrivilegeError(ctx, paths.stateDir(), err),
            else => return err,
        }
    };
    paths.ensureLogDir() catch |err| {
        switch (err) {
            error.AccessDenied, error.PermissionDenied => return reportPrivilegeError(ctx, paths.logDir(), err),
            else => return err,
        }
    };
    paths.ensureRunDir() catch |err| {
        switch (err) {
            error.AccessDenied, error.PermissionDenied => return reportPrivilegeError(ctx, paths.runDir(), err),
            else => return err,
        }
    };

    const config_path = try paths.configFile();
    defer ctx.allocator.free(config_path);

    const existing = std.fs.openFileAbsolute(config_path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (existing) |file| {
        file.close();
        try printFmt(ctx.allocator, ctx.stdout_fd, "Config already present at {s}\n", .{config_path});
    } else {
        const default_config = "{\n  \"groups\": {\n    \"default\": []\n  }\n}\n";
        try fs_util.atomicWriteFileAbsolute(config_path, default_config);
        try printFmt(ctx.allocator, ctx.stdout_fd, "Initialized default config at {s}\n", .{config_path});
    }

    installDaemonBinary(ctx.allocator) catch |err| switch (err) {
        InitError.MissingDaemonSource => {
            try writeAll(ctx.stderr_fd, "zblock init: could not locate zblockd binary. Set ZBLOCKD_SOURCE or place zblockd alongside zblock.\n");
            return 1;
        },
        error.AccessDenied, error.PermissionDenied => return reportPrivilegeError(ctx, paths_mod.Paths.daemonBinaryPath(), err),
        error.FileNotFound => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock init: destination directory missing for '{s}'. Create it and rerun with sudo.\n", .{paths_mod.Paths.daemonBinaryPath()});
            return 1;
        },
        else => return err,
    };

    try printFmt(ctx.allocator, ctx.stdout_fd, "Installed zblockd to {s}\n", .{paths_mod.Paths.daemonBinaryPath()});

    ensureLaunchdPlist(ctx.allocator, &paths) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return reportPrivilegeError(ctx, paths_mod.Paths.launchdPlistPath(), err),
        error.FileNotFound => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock init: destination directory missing for '{s}'. Create it and rerun with sudo.\n", .{paths_mod.Paths.launchdPlistPath()});
            return 1;
        },
        else => return err,
    };
    try printFmt(ctx.allocator, ctx.stdout_fd, "Launchd plist written to {s}\n", .{paths_mod.Paths.launchdPlistPath()});

    pf.ensureAnchorTemplate(ctx.allocator, &paths) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return reportPrivilegeError(ctx, pf.anchor_path, err),
        error.FileNotFound => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock init: parent directory missing for '{s}'. Create it and rerun with sudo.\n", .{pf.anchor_path});
            return 1;
        },
        else => return err,
    };
    try printFmt(ctx.allocator, ctx.stdout_fd, "pf anchor template updated at {s}\n", .{pf.anchor_path});

    const pf_result = std.process.Child.run(.{ .allocator = ctx.allocator, .argv = &.{ "pfctl", "-s", "info" } }) catch |err| switch (err) {
        error.FileNotFound => {
            try writeAll(ctx.stderr_fd, "zblock init: pfctl not found in PATH. Install Command Line Tools or adjust PATH.\n");
            return 1;
        },
        else => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock init: failed to execute pfctl ({s})\n", .{@errorName(err)});
            return 1;
        },
    };
    defer ctx.allocator.free(pf_result.stdout);
    defer ctx.allocator.free(pf_result.stderr);

    switch (pf_result.term) {
        .Exited => |code| {
            if (code != 0) {
                if (pf_result.stderr.len != 0) {
                    try printFmt(ctx.allocator, ctx.stderr_fd, "pfctl reported: {s}\n", .{pf_result.stderr});
                } else {
                    try printFmt(ctx.allocator, ctx.stderr_fd, "pfctl exited with status {d}\n", .{code});
                }
                try writeAll(ctx.stderr_fd, "Hint: run this command with sudo so pfctl can access the packet filter.\n");
                return 1;
            }
        },
        else => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "pfctl terminated unexpectedly ({s})\n", .{@tagName(pf_result.term)});
            return 1;
        },
    }
    try writeAll(ctx.stdout_fd, "pfctl reachable (pfctl -s info succeeded).\n");

    configureLaunchd(ctx) catch |err| {
        if (err != error.LaunchctlFailed) {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock init: launchctl setup failed ({s})\n", .{@errorName(err)});
        }
        return 1;
    };

    try writeAll(ctx.stdout_fd, "Initialization complete.\n");
    return 0;
}

fn handleStart(ctx: RunContext, args: *std.process.ArgIterator) !u8 {
    var duration_spec: ?[]const u8 = null;
    var group_override: ?[]const u8 = null;
    var dns_lockdown = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            try printStartHelp(ctx.stdout_fd);
            return 0;
        }
        if (std.mem.startsWith(u8, arg, "--for=")) {
            duration_spec = arg[6..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--for")) {
            duration_spec = args.next() orelse {
                try writeAll(ctx.stderr_fd, "zblock start: expected duration after --for\n");
                return 1;
            };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--group=")) {
            group_override = arg[8..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--group")) {
            group_override = args.next() orelse {
                try writeAll(ctx.stderr_fd, "zblock start: expected group after --group\n");
                return 1;
            };
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-lockdown")) {
            dns_lockdown = true;
            continue;
        }
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock start: unknown option '{s}'\n", .{arg});
        return 1;
    }

    const duration_str = duration_spec orelse {
        try writeAll(ctx.stderr_fd, "zblock start: missing --for <duration>\n");
        return 1;
    };

    const duration_seconds = parseDuration(duration_str) catch |err| {
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock start: invalid duration '{s}' ({s})\n", .{ duration_str, @errorName(err) });
        return 1;
    };

    const group_name = group_override orelse "default";
    const canonical_group = config_mod.normalizeGroupNameCopy(ctx.allocator, group_name) catch |err| {
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock start: invalid group name '{s}' ({s})\n", .{ group_name, @errorName(err) });
        return 1;
    };

    var request = ipc.Request{
        .op = .start,
        .start = ipc.StartCommand{
            .group = canonical_group,
            .duration_seconds = duration_seconds,
            .dns_lockdown = dns_lockdown,
        },
    };

    var response = sendRequest(ctx, &request) catch |err| {
        return reportDaemonUnavailable(ctx, "start", err);
    };
    defer response.deinit(ctx.allocator);

    if (!response.ok) {
        const msg = response.message orelse "request rejected";
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock start: {s}\n", .{msg});
        return 1;
    }

    if (response.message) |msg| {
        try printFmt(ctx.allocator, ctx.stdout_fd, "{s}\n", .{msg});
    } else {
        try writeAll(ctx.stdout_fd, "Session scheduled.\n");
    }
    return 0;
}

fn handleStatus(ctx: RunContext, args: *std.process.ArgIterator) !u8 {
    var output_json = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            output_json = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--help")) {
            try printStatusHelp(ctx.stdout_fd);
            return 0;
        }
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock status: unknown option '{s}'\n", .{arg});
        return 1;
    }

    var address_cfg = ipc.getAddress(ctx.allocator) catch |err| {
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock status: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer ipc.freeAddress(ctx.allocator, &address_cfg);

    var request = ipc.Request{ .op = .status, .start = null };
    const payload = ipc.encodeRequest(ctx.allocator, request) catch |err| {
        request.deinit(ctx.allocator);
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock status: encode failed ({s})\n", .{@errorName(err)});
        return 1;
    };
    defer ctx.allocator.free(payload);
    request.deinit(ctx.allocator);

    const raw_response = ipc.sendRequest(ctx.allocator, address_cfg, payload) catch |err| {
        return reportDaemonUnavailable(ctx, "status", err);
    };
    defer ctx.allocator.free(raw_response);

    if (output_json) {
        try printFmt(ctx.allocator, ctx.stdout_fd, "{s}\n", .{raw_response});
        return 0;
    }

    var response = ipc.decodeResponse(ctx.allocator, raw_response) catch |err| {
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock status: decode failed ({s})\n", .{@errorName(err)});
        return 1;
    };
    defer response.deinit(ctx.allocator);

    if (!response.ok) {
        const msg = response.message orelse "request rejected";
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock status: {s}\n", .{msg});
        return 1;
    }

    const status = response.status orelse ipc.StatusData{ .active = false };
    if (!status.active) {
        try writeAll(ctx.stdout_fd, "No active session.\n");
        return 0;
    }

    const group = status.group orelse "default";
    const until_epoch = status.until_epoch orelse 0;
    const remaining = status.remaining_seconds orelse 0;

    try printFmt(ctx.allocator, ctx.stdout_fd, "Active session for group '{s}'\n", .{group});
    try printFmt(ctx.allocator, ctx.stdout_fd, "  Ends at epoch {d} (remaining {d} seconds)\n", .{ until_epoch, remaining });
    try printFmt(ctx.allocator, ctx.stdout_fd, "  Targets: v4={d}, v6={d}, dns_lockdown={s}\n", .{ status.v4_count, status.v6_count, if (status.dns_lockdown) "true" else "false" });
    return 0;
}

fn handleUninstall(ctx: RunContext, args: *std.process.ArgIterator) !u8 {
    var purge_config = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--purge")) {
            purge_config = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--help")) {
            try printUninstallHelp(ctx.stdout_fd);
            return 0;
        }
        try printFmt(ctx.allocator, ctx.stderr_fd, "zblock uninstall: unknown option '{s}'\n", .{arg});
        return 1;
    }

    var paths = try paths_mod.Paths.initFromEnv(ctx.allocator);
    defer paths.deinit();

    if (try activeSessionExists(ctx, &paths)) {
        try writeAll(ctx.stderr_fd, "zblock uninstall: active focus session detected.\n");
        try writeAll(ctx.stderr_fd, "Wait for the session to finish before uninstalling.\n");
        return 1;
    }

    teardownLaunchd(ctx);
    pf.uninstallCleanup(ctx.allocator);

    try removeFileIfExists(paths.daemonActiveFile());
    try removeFileIfExists(paths.blockedV4TablePath());
    try removeFileIfExists(paths.blockedV6TablePath());
    try removeFileIfExists(paths.dohTablePath());
    try removeFileIfExists(paths.socketPath());
    try removeSystemFile(ctx, paths_mod.Paths.daemonBinaryPath());
    try removeSystemFile(ctx, paths_mod.Paths.launchdPlistPath());
    try removeSystemFile(ctx, pf.anchor_path);
    try removeSystemFile(ctx, paths.daemonLogFile());
    try removeSystemFile(ctx, paths.actionsLogFile());

    if (purge_config) {
        const config_path = try paths.configFile();
        defer ctx.allocator.free(config_path);
        removeFileIfExists(config_path) catch {};
    }

    removeDirIfEmpty(paths.runDir()) catch {};
    removeDirIfEmpty(paths.stateDir()) catch {};
    removeDirIfEmpty(paths.logDir()) catch {};

    try writeAll(ctx.stdout_fd, "Uninstall complete:\n");
    try writeAll(ctx.stdout_fd, "  - launchctl service system/com.zblock.daemon stopped.\n");
    try writeAll(ctx.stdout_fd, "  - Cleared pf anchor com.apple/zblock and associated tables.\n");
    try writeAll(ctx.stdout_fd, "  - Removed daemon binary, logs, and state files.\n");
    if (purge_config) try writeAll(ctx.stdout_fd, "  - Deleted user config (config.json).\n");
    return 0;
}

fn installDaemonBinary(allocator: std.mem.Allocator) !void {
    const target = paths_mod.Paths.daemonBinaryPath();
    try fs_util.ensureParentDir(target);

    const source = try findDaemonSourceBinary(allocator) orelse return InitError.MissingDaemonSource;
    defer allocator.free(source);

    try std.fs.copyFileAbsolute(source, target, .{ .override_mode = 0o755 });
}

fn fileExists(path: []const u8) !bool {
    const file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.AccessDenied, error.PermissionDenied => return true,
        else => return err,
    };
    defer file.close();
    return true;
}

fn findDaemonSourceBinary(allocator: std.mem.Allocator) !?[]u8 {
    if (std.process.getEnvVarOwned(allocator, "ZBLOCKD_SOURCE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    }) |env_path| {
        return env_path;
    }

    const exe_path = std.fs.selfExePathAlloc(allocator) catch null;
    if (exe_path) |path| {
        defer allocator.free(path);
        if (std.fs.path.dirname(path)) |dir| {
            if (try readableCandidate(allocator, &.{ dir, "zblockd" })) |candidate| return candidate;
            if (try readableCandidate(allocator, &.{ dir, "..", "zblockd" })) |candidate| return candidate;
        }
    }

    const cwd_abs = std.fs.cwd().realpathAlloc(allocator, ".") catch null;
    if (cwd_abs) |cwd_path| {
        defer allocator.free(cwd_path);
        if (try readableCandidate(allocator, &.{ cwd_path, "zig-out", "bin", "zblockd" })) |candidate| return candidate;
    }

    return null;
}

fn readableCandidate(allocator: std.mem.Allocator, parts: []const []const u8) !?[]u8 {
    const path = try std.fs.path.join(allocator, parts);
    var file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => {
            allocator.free(path);
            return null;
        },
        else => {
            allocator.free(path);
            return err;
        },
    };
    file.close();
    return path;
}

fn ensureLaunchdPlist(allocator: std.mem.Allocator, paths: *const paths_mod.Paths) !void {
    try fs_util.ensureParentDir(paths_mod.Paths.launchdPlistPath());
    removeFileIfExists(paths_mod.Paths.launchdPlistPath()) catch {};
    const contents = try renderLaunchdPlist(allocator, paths);
    defer allocator.free(contents);
    try fs_util.atomicWriteFileAbsoluteWithMode(paths_mod.Paths.launchdPlistPath(), contents, 0o644);
}

fn renderLaunchdPlist(allocator: std.mem.Allocator, paths: *const paths_mod.Paths) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" ++
            "<plist version=\"1.0\">\n" ++
            "<dict>\n" ++
            "  <key>Label</key>\n" ++
            "  <string>com.zblock.daemon</string>\n" ++
            "  <key>ProgramArguments</key>\n" ++
            "  <array>\n" ++
            "    <string>{s}</string>\n" ++
            "  </array>\n" ++
            "  <key>RunAtLoad</key>\n" ++
            "  <true/>\n" ++
            "  <key>KeepAlive</key>\n" ++
            "  <true/>\n" ++
            "  <key>ProcessType</key>\n" ++
            "  <string>Background</string>\n" ++
            "  <key>StandardOutPath</key>\n" ++
            "  <string>{s}</string>\n" ++
            "  <key>StandardErrorPath</key>\n" ++
            "  <string>{s}</string>\n" ++
            "  <key>EnvironmentVariables</key>\n" ++
            "  <dict>\n" ++
            "    <key>ZBLOCK_CONFIG_DIR</key>\n" ++
            "    <string>{s}</string>\n" ++
            "    <key>ZBLOCK_STATE_DIR</key>\n" ++
            "    <string>{s}</string>\n" ++
            "    <key>ZBLOCK_LOG_DIR</key>\n" ++
            "    <string>{s}</string>\n" ++
            "    <key>ZBLOCK_RUN_DIR</key>\n" ++
            "    <string>{s}</string>\n" ++
            "    <key>ZBLOCK_SOCKET_PATH</key>\n" ++
            "    <string>{s}</string>\n" ++
            "  </dict>\n" ++
            "</dict>\n" ++
            "</plist>\n",
        .{
            paths_mod.Paths.daemonBinaryPath(),
            paths.daemonLogFile(),
            paths.daemonLogFile(),
            paths.configDir(),
            paths.stateDir(),
            paths.logDir(),
            paths.runDir(),
            paths.socketPath(),
        },
    );
}

fn runLaunchctlCommand(ctx: RunContext, label: []const u8, argv: []const []const u8, description: []const u8, ignore_failure: bool) !void {
    var result = std.process.Child.run(.{ .allocator = ctx.allocator, .argv = argv }) catch |err| {
        try printFmt(ctx.allocator, ctx.stderr_fd, "{s}: failed to execute {s} ({s})\n", .{ label, description, @errorName(err) });
        return err;
    };
    defer ctx.allocator.free(result.stdout);
    defer ctx.allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| {
            if (code == 0 or ignore_failure) return;
            try printFmt(ctx.allocator, ctx.stderr_fd, "{s}: {s} failed (exit code {d}).\n", .{ label, description, code });
            if (result.stderr.len != 0) try printFmt(ctx.allocator, ctx.stderr_fd, "{s}\n", .{result.stderr});
            return error.LaunchctlFailed;
        },
        else => {
            if (ignore_failure) return;
            try printFmt(ctx.allocator, ctx.stderr_fd, "{s}: {s} terminated unexpectedly ({s}).\n", .{ label, description, @tagName(result.term) });
            return error.LaunchctlFailed;
        },
    }
}

fn configureLaunchd(ctx: RunContext) !void {
    const service_target = "system/com.zblock.daemon";
    const plist_path = paths_mod.Paths.launchdPlistPath();

    const label = "zblock init";
    try runLaunchctlCommand(ctx, label, &.{ "launchctl", "bootout", service_target }, "launchctl bootout", true);
    try runLaunchctlCommand(ctx, label, &.{ "launchctl", "enable", service_target }, "launchctl enable", true);
    try runLaunchctlCommand(ctx, label, &.{ "launchctl", "bootstrap", "system", plist_path }, "launchctl bootstrap", false);
    try runLaunchctlCommand(ctx, label, &.{ "launchctl", "kickstart", "-k", service_target }, "launchctl kickstart", false);

    try printFmt(ctx.allocator, ctx.stdout_fd, "Launchd service {s} running.\n", .{service_target});
}

fn teardownLaunchd(ctx: RunContext) void {
    const service_target = "system/com.zblock.daemon";
    const label = "zblock uninstall";
    runLaunchctlCommand(ctx, label, &.{ "launchctl", "bootout", service_target }, "launchctl bootout", true) catch {};
}

fn activeSessionExists(ctx: RunContext, paths: *const paths_mod.Paths) !bool {
    const path = paths.daemonActiveFile();
    var file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch |err| {
        switch (err) {
            error.FileNotFound => return false,
            else => return err,
        }
    };
    defer file.close();

    const file_size = try file.getEndPos();
    const size = std.math.cast(usize, file_size) orelse return false;
    if (size == 0) return false;
    var buffer = try ctx.allocator.alloc(u8, size);
    defer ctx.allocator.free(buffer);
    const read_len = try file.readAll(buffer);
    const data = buffer[0..read_len];

    var parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, data, .{}) catch return false;
    defer parsed.deinit();

    const root = parsed.value;
    const obj = switch (root) {
        .object => |o| o,
        else => return false,
    };

    const end_ptr = obj.getPtr("end_epoch") orelse return false;
    const end_epoch = switch (end_ptr.*) {
        .integer => |i| i,
        else => return false,
    };

    return std.time.timestamp() < end_epoch;
}

fn reportDaemonUnavailable(ctx: RunContext, command: []const u8, err: anyerror) !u8 {
    const err_name = @errorName(err);
    switch (err) {
        error.ConnectionRefused, error.ConnectionResetByPeer, error.ConnectionAborted, error.ConnectionTimedOut, error.PermissionDenied, error.FileNotFound => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock {s}: cannot reach daemon ({s}).\n", .{ command, err_name });
            try writeAll(ctx.stderr_fd, "Hint: ensure zblockd is running with sufficient privileges (e.g. run 'sudo ./zig-out/bin/zblockd') or configure ZBLOCK_SOCKET_PATH if using a custom socket.\n");
            return 1;
        },
        else => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock {s}: {s}\n", .{ command, err_name });
            return 1;
        },
    }
}

fn reportPrivilegeError(ctx: RunContext, path: []const u8, err: anyerror) !u8 {
    try printFmt(ctx.allocator, ctx.stderr_fd, "zblock init: cannot create or access '{s}' ({s}).\n", .{ path, @errorName(err) });
    try writeAll(ctx.stderr_fd, "Hint: run 'sudo zblock init' so root can prepare system directories, or override ZBLOCK_STATE_DIR/ZBLOCK_LOG_DIR/ZBLOCK_RUN_DIR for development.\n");
    return 1;
}

fn sendRequest(ctx: RunContext, request: *ipc.Request) !ipc.Response {
    var address_cfg = try ipc.getAddress(ctx.allocator);
    defer ipc.freeAddress(ctx.allocator, &address_cfg);

    const payload = try ipc.encodeRequest(ctx.allocator, request.*);
    defer ctx.allocator.free(payload);
    request.deinit(ctx.allocator);

    const raw = try ipc.sendRequest(ctx.allocator, address_cfg, payload);
    defer ctx.allocator.free(raw);

    return ipc.decodeResponse(ctx.allocator, raw);
}

fn parseDuration(spec: []const u8) !u64 {
    var idx: usize = 0;
    var total: u64 = 0;
    while (idx < spec.len) {
        const start = idx;
        while (idx < spec.len and std.ascii.isDigit(spec[idx])) idx += 1;
        if (start == idx) return error.InvalidDuration;
        const value = try std.fmt.parseUnsigned(u64, spec[start..idx], 10);
        const unit: u8 = if (idx < spec.len) blk: {
            const ch = spec[idx];
            idx += 1;
            break :blk ch;
        } else 's';
        const factor: u64 = switch (unit) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            else => return error.InvalidDuration,
        };
        const scaled = try std.math.mul(u64, value, factor);
        total = try std.math.add(u64, total, scaled);
    }
    if (total == 0) return error.InvalidDuration;
    return total;
}

fn removeFileIfExists(path: []const u8) !void {
    std.fs.deleteFileAbsolute(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

fn removeSystemFile(ctx: RunContext, path: []const u8) !void {
    removeFileIfExists(path) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => {
            try printFmt(ctx.allocator, ctx.stderr_fd, "zblock uninstall: unable to remove '{s}' ({s})\n", .{ path, @errorName(err) });
            try writeAll(ctx.stderr_fd, "Hint: run with sudo if the file is root-owned.\n");
            return;
        },
        else => return err,
    };
}

fn removeDirIfEmpty(path: []const u8) !void {
    std.fs.deleteDirAbsolute(path) catch |err| switch (err) {
        error.FileNotFound, error.DirNotEmpty => {},
        else => return err,
    };
}

fn printUsage(fd: posix.fd_t) !void {
    try writeAll(fd, "Usage: zblock <command> [options]\n\n" ++
        "Commands:\n" ++
        "  add <domains...> [--group <name>]   Add domains to a group.\n" ++
        "  list [--group <name>] [--json]      Show configured domains.\n" ++
        "  init                                 Prepare config/state directories.\n" ++
        "  start --for <duration>               Begin a focus session via the daemon.\n" ++
        "  status [--json]                      Query daemon state.\n" ++
        "  uninstall [--purge]                  Remove daemon files and pf state.\n" ++
        "\nRun 'zblock <command> --help' for details on a specific command.\n");
}

fn printAddHelp(fd: posix.fd_t) !void {
    try writeAll(fd, "Usage: zblock add [--group <name>] <domain> [domain ...]\n\n" ++
        "Adds one or more domains to the specified group.\n" ++
        "Options:\n" ++
        "  --group <name>   Target group (default: 'default').\n" ++
        "  --help           Show this help text.\n");
}

fn printListHelp(fd: posix.fd_t) !void {
    try writeAll(fd, "Usage: zblock list [--group <name>] [--json]\n\n" ++
        "Lists configured domains.\n" ++
        "Options:\n" ++
        "  --group <name>   Limit output to a single group.\n" ++
        "  --json           Emit machine-readable JSON.\n" ++
        "  --help           Show this help text.\n");
}

fn printStartHelp(fd: posix.fd_t) !void {
    try writeAll(fd, "Usage: zblock start --for <duration> [--group <name>] [--dns-lockdown]\n\n" ++
        "Duration accepts integers with optional suffix (s, m, h).\n" ++
        "Example: zblock start --for 45m --group social --dns-lockdown\n");
}

fn printStatusHelp(fd: posix.fd_t) !void {
    try writeAll(fd, "Usage: zblock status [--json]\n\n" ++
        "Displays the daemon's session status.\n");
}

fn printUninstallHelp(fd: posix.fd_t) !void {
    try writeAll(fd, "Usage: zblock uninstall [--purge]\n\n" ++
        "Stops the launchd service, clears pf rules, and removes generated files.\n" ++
        "  --purge   Remove config.json as well.\n");
}
