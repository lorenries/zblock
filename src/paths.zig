const std = @import("std");
const fs_util = @import("fs.zig");

pub const Error = error{
    MissingHomeDirectory,
};

pub const Options = struct {
    config_dir: ?[]const u8 = null,
    xdg_config_home: ?[]const u8 = null,
    home_dir: ?[]const u8 = null,
    state_dir: ?[]const u8 = null,
    log_dir: ?[]const u8 = null,
    run_dir: ?[]const u8 = null,
    socket_path: ?[]const u8 = null,
};

pub const Paths = struct {
    allocator: std.mem.Allocator,
    config_dir: []u8,
    state_dir: []u8,
    log_dir: []u8,
    run_dir: []u8,
    socket_path: []u8,
    blocked_v4_table_path: []u8,
    blocked_v6_table_path: []u8,
    doh_table_path: []u8,
    active_file_path: []u8,
    daemon_log_file_path: []u8,
    actions_log_file_path: []u8,

    pub fn init(allocator: std.mem.Allocator, options: Options) !Paths {
        const config_dir_buf = try resolveConfigDir(allocator, options);
        errdefer allocator.free(config_dir_buf);

        const state_dir_buf = try dupOrDefault(allocator, options.state_dir, "/var/db/zblock");
        errdefer allocator.free(state_dir_buf);
        const log_dir_buf = try dupOrDefault(allocator, options.log_dir, "/var/log/zblock");
        errdefer allocator.free(log_dir_buf);
        const run_dir_buf = try dupOrDefault(allocator, options.run_dir, "/var/run/zblock");
        errdefer allocator.free(run_dir_buf);

        const socket_path_buf = try resolveSocketPath(allocator, run_dir_buf, options.socket_path);
        errdefer allocator.free(socket_path_buf);

        const blocked_v4 = try std.fs.path.join(allocator, &.{ state_dir_buf, "blocked_v4.table" });
        errdefer allocator.free(blocked_v4);
        const blocked_v6 = try std.fs.path.join(allocator, &.{ state_dir_buf, "blocked_v6.table" });
        errdefer allocator.free(blocked_v6);
        const doh_table = try std.fs.path.join(allocator, &.{ state_dir_buf, "doh.table" });
        errdefer allocator.free(doh_table);
        const active_file = try std.fs.path.join(allocator, &.{ state_dir_buf, "active.json" });
        errdefer allocator.free(active_file);

        const daemon_log = try std.fs.path.join(allocator, &.{ log_dir_buf, "daemon.log" });
        errdefer allocator.free(daemon_log);
        const actions_log = try std.fs.path.join(allocator, &.{ log_dir_buf, "actions.log" });
        errdefer allocator.free(actions_log);

        return Paths{
            .allocator = allocator,
            .config_dir = config_dir_buf,
            .state_dir = state_dir_buf,
            .log_dir = log_dir_buf,
            .run_dir = run_dir_buf,
            .socket_path = socket_path_buf,
            .blocked_v4_table_path = blocked_v4,
            .blocked_v6_table_path = blocked_v6,
            .doh_table_path = doh_table,
            .active_file_path = active_file,
            .daemon_log_file_path = daemon_log,
            .actions_log_file_path = actions_log,
        };
    }

    pub fn initFromEnv(allocator: std.mem.Allocator) !Paths {
        const config_dir_env = try getEnvOwned(allocator, "ZBLOCK_CONFIG_DIR");
        defer if (config_dir_env) |value| allocator.free(value);

        const xdg_home_env = try getEnvOwned(allocator, "XDG_CONFIG_HOME");
        defer if (xdg_home_env) |value| allocator.free(value);

        var home_env: ?[]u8 = null;
        if (xdg_home_env == null) {
            home_env = try getEnvOwned(allocator, "HOME");
        }
        defer if (home_env) |value| allocator.free(value);

        const state_dir_env = try getEnvOwned(allocator, "ZBLOCK_STATE_DIR");
        defer if (state_dir_env) |value| allocator.free(value);

        const log_dir_env = try getEnvOwned(allocator, "ZBLOCK_LOG_DIR");
        defer if (log_dir_env) |value| allocator.free(value);

        const run_dir_env = try getEnvOwned(allocator, "ZBLOCK_RUN_DIR");
        defer if (run_dir_env) |value| allocator.free(value);

        const socket_env = try getEnvOwned(allocator, "ZBLOCK_SOCKET_PATH");
        defer if (socket_env) |value| allocator.free(value);

        return Paths.init(allocator, .{
            .config_dir = if (config_dir_env) |value| value else null,
            .xdg_config_home = if (xdg_home_env) |value| value else null,
            .home_dir = if (home_env) |value| value else null,
            .state_dir = if (state_dir_env) |value| value else null,
            .log_dir = if (log_dir_env) |value| value else null,
            .run_dir = if (run_dir_env) |value| value else null,
            .socket_path = if (socket_env) |value| value else null,
        });
    }

    pub fn deinit(self: *Paths) void {
        self.allocator.free(self.config_dir);
        self.allocator.free(self.state_dir);
        self.allocator.free(self.log_dir);
        self.allocator.free(self.run_dir);
        self.allocator.free(self.socket_path);
        self.allocator.free(self.blocked_v4_table_path);
        self.allocator.free(self.blocked_v6_table_path);
        self.allocator.free(self.doh_table_path);
        self.allocator.free(self.active_file_path);
        self.allocator.free(self.daemon_log_file_path);
        self.allocator.free(self.actions_log_file_path);
        self.* = undefined;
    }

    pub fn configDir(self: *const Paths) []const u8 {
        return self.config_dir;
    }

    pub fn stateDir(self: *const Paths) []const u8 {
        return self.state_dir;
    }

    pub fn logDir(self: *const Paths) []const u8 {
        return self.log_dir;
    }

    pub fn runDir(self: *const Paths) []const u8 {
        return self.run_dir;
    }

    pub fn socketPath(self: *const Paths) []const u8 {
        return self.socket_path;
    }

    pub fn blockedV4TablePath(self: *const Paths) []const u8 {
        return self.blocked_v4_table_path;
    }

    pub fn blockedV6TablePath(self: *const Paths) []const u8 {
        return self.blocked_v6_table_path;
    }

    pub fn dohTablePath(self: *const Paths) []const u8 {
        return self.doh_table_path;
    }

    pub fn daemonStateDir(self: *const Paths) []const u8 {
        return self.state_dir;
    }

    pub fn daemonActiveFile(self: *const Paths) []const u8 {
        return self.active_file_path;
    }

    pub fn daemonLogFile(self: *const Paths) []const u8 {
        return self.daemon_log_file_path;
    }

    pub fn actionsLogFile(self: *const Paths) []const u8 {
        return self.actions_log_file_path;
    }

    pub fn configFile(self: *const Paths) ![]u8 {
        return std.fs.path.join(self.allocator, &.{ self.config_dir, "config.json" });
    }

    pub fn ensureConfigDir(self: *const Paths) !void {
        try fs_util.ensureAbsoluteDir(self.config_dir);
    }

    pub fn ensureStateDir(self: *const Paths) !void {
        try fs_util.ensureAbsoluteDir(self.state_dir);
    }

    pub fn ensureLogDir(self: *const Paths) !void {
        try fs_util.ensureAbsoluteDir(self.log_dir);
    }

    pub fn ensureRunDir(self: *const Paths) !void {
        try fs_util.ensureAbsoluteDir(self.run_dir);
        std.posix.fchmodat(std.posix.AT.FDCWD, self.run_dir, 0o755, 0) catch {};
    }

    pub fn daemonBinaryPath() []const u8 {
        return "/usr/local/libexec/zblockd";
    }

    pub fn launchdPlistPath() []const u8 {
        return "/Library/LaunchDaemons/com.zblock.daemon.plist";
    }
};

fn resolveConfigDir(allocator: std.mem.Allocator, options: Options) ![]u8 {
    if (options.config_dir) |explicit| {
        return allocator.dupe(u8, explicit);
    }

    var config_home_buf: ?[]u8 = null;
    defer if (config_home_buf) |buf| allocator.free(buf);

    const config_home = if (options.xdg_config_home) |xdg| xdg else blk: {
        const home = options.home_dir orelse return Error.MissingHomeDirectory;
        const joined = try std.fs.path.join(allocator, &.{ home, ".config" });
        config_home_buf = joined;
        break :blk joined;
    };

    return std.fs.path.join(allocator, &.{ config_home, "zblock" });
}

fn dupOrDefault(allocator: std.mem.Allocator, maybe_value: ?[]const u8, default_value: []const u8) ![]u8 {
    return allocator.dupe(u8, maybe_value orelse default_value);
}

fn resolveSocketPath(allocator: std.mem.Allocator, run_dir: []const u8, override: ?[]const u8) ![]u8 {
    if (override) |path| {
        return allocator.dupe(u8, path);
    }
    return std.fs.path.join(allocator, &.{ run_dir, "zblockd.sock" });
}

fn getEnvOwned(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => err,
    };
}

// ------------------------- Tests -------------------------

test "init with explicit config dir" {
    const allocator = std.testing.allocator;
    var paths = try Paths.init(allocator, .{
        .config_dir = "/tmp/zblock-config",
        .state_dir = "/tmp/zblock-state",
        .log_dir = "/tmp/zblock-log",
        .run_dir = "/tmp/zblock-run",
    });
    defer paths.deinit();

    try std.testing.expect(std.mem.eql(u8, paths.configDir(), "/tmp/zblock-config"));
    try std.testing.expect(std.mem.eql(u8, paths.stateDir(), "/tmp/zblock-state"));
    try std.testing.expect(std.mem.eql(u8, paths.logDir(), "/tmp/zblock-log"));
    try std.testing.expect(std.mem.eql(u8, paths.runDir(), "/tmp/zblock-run"));
}

test "init with xdg config home" {
    const allocator = std.testing.allocator;
    const xdg_home = "/Users/me/.config";
    var paths = try Paths.init(allocator, .{
        .xdg_config_home = xdg_home,
        .state_dir = "/tmp/state",
        .log_dir = "/tmp/log",
        .run_dir = "/tmp/run",
    });
    defer paths.deinit();

    const expected = try std.fs.path.join(allocator, &.{ xdg_home, "zblock" });
    defer allocator.free(expected);

    try std.testing.expect(std.mem.eql(u8, paths.configDir(), expected));
}

test "init with home fallback" {
    const allocator = std.testing.allocator;
    const home_dir = "/Users/focus";
    var paths = try Paths.init(allocator, .{
        .home_dir = home_dir,
        .state_dir = "/tmp/state",
        .log_dir = "/tmp/log",
        .run_dir = "/tmp/run",
    });
    defer paths.deinit();

    const expected = try std.fs.path.join(allocator, &.{ home_dir, ".config", "zblock" });
    defer allocator.free(expected);

    try std.testing.expect(std.mem.eql(u8, paths.configDir(), expected));
}

test "config file path generation" {
    const allocator = std.testing.allocator;
    var paths = try Paths.init(allocator, .{
        .config_dir = "/tmp/zblock-config",
        .state_dir = "/tmp/state",
        .log_dir = "/tmp/log",
        .run_dir = "/tmp/run",
    });
    defer paths.deinit();

    const config_file = try paths.configFile();
    defer allocator.free(config_file);

    try std.testing.expect(std.mem.eql(u8, config_file, "/tmp/zblock-config/config.json"));
}

test "ensureConfigDir creates directories" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    const base = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    const nested = try std.fs.path.join(allocator, &.{ base, "nested", "zblock" });
    defer allocator.free(nested);

    const state_dir = try std.fs.path.join(allocator, &.{ base, "state" });
    defer allocator.free(state_dir);
    const log_dir = try std.fs.path.join(allocator, &.{ base, "log" });
    defer allocator.free(log_dir);
    const run_dir = try std.fs.path.join(allocator, &.{ base, "run" });
    defer allocator.free(run_dir);

    var paths = try Paths.init(allocator, .{
        .config_dir = nested,
        .state_dir = state_dir,
        .log_dir = log_dir,
        .run_dir = run_dir,
    });
    defer paths.deinit();

    try paths.ensureConfigDir();

    var dir = try std.fs.openDirAbsolute(paths.configDir(), .{});
    defer dir.close();
}
