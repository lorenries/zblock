const std = @import("std");
const atomic = std.atomic;
const paths_mod = @import("paths.zig");
const config_mod = @import("config.zig");
const dns = @import("dns.zig");
const pf = @import("pf.zig");
const ipc = @import("ipc.zig");
const fs_util = @import("fs.zig");

const WATCHDOG_INTERVAL_NS: u64 = 5 * std.time.ns_per_s;
const REFRESH_INTERVAL_SEC: i64 = 600;

const Session = struct {
    group: []u8,
    start_epoch: i64,
    end_epoch: i64,
    dns_lockdown: bool,
    v4_count: usize,
    v6_count: usize,
    pf_was_enabled: bool,
    next_refresh_epoch: i64,

    fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        allocator.free(self.group);
        self.* = undefined;
    }
};

const Daemon = struct {
    allocator: std.mem.Allocator,
    paths: paths_mod.Paths,
    session: ?Session = null,
    mutex: std.Thread.Mutex.Recursive = std.Thread.Mutex.Recursive.init,
    watchdog_thread: ?std.Thread = null,
    watchdog_stop: atomic.Value(bool) = atomic.Value(bool).init(true),

    pub fn init(allocator: std.mem.Allocator) !Daemon {
        var paths = try paths_mod.Paths.initFromEnv(allocator);
        errdefer paths.deinit();

        try paths.ensureConfigDir();
        try paths.ensureStateDir();
        try paths.ensureLogDir();
        try paths.ensureRunDir();

        var daemon = Daemon{
            .allocator = allocator,
            .paths = paths,
            .session = null,
            .mutex = std.Thread.Mutex.Recursive.init,
            .watchdog_thread = null,
            .watchdog_stop = atomic.Value(bool).init(true),
        };

        try daemon.loadActiveSession();

        daemon.mutex.lock();
        defer daemon.mutex.unlock();
        if (daemon.session) |*session| {
            std.log.info("Restoring active session for group '{s}'", .{session.group});
            daemon.refreshSessionLocked(session) catch |err| {
                std.log.err("failed to restore session: {s}", .{@errorName(err)});
                _ = daemon.teardownSessionLocked(false) catch {};
            };
            if (daemon.session != null) {
                try daemon.startWatchdogLocked();
            }
        }

        return daemon;
    }

    pub fn deinit(self: *Daemon) void {
        self.stopWatchdog();
        if (self.session != null) {
            _ = self.teardownSessionLocked(false) catch {};
        }
        self.paths.deinit();
        self.* = undefined;
    }

    fn startWatchdogLocked(self: *Daemon) !void {
        if (self.session == null) return;
        if (self.watchdog_thread != null) return;

        self.watchdog_stop.store(false, .release);
        self.watchdog_thread = try std.Thread.spawn(.{}, watchdogMain, .{self});
    }

    fn startWatchdog(self: *Daemon) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.startWatchdogLocked();
    }

    fn stopWatchdog(self: *Daemon) void {
        if (self.watchdog_thread) |thread| {
            self.watchdog_stop.store(true, .release);
            thread.join();
            self.watchdog_thread = null;
        } else {
            self.watchdog_stop.store(true, .release);
        }
    }

    fn schedulePfClear(self: *Daemon, pf_was_enabled: bool) void {
        const thread = std.Thread.spawn(.{}, pfClearRunner, .{ self, pf_was_enabled }) catch {
            runPfClearSync(self, pf_was_enabled);
            return;
        };
        thread.detach();
    }

    fn watchdogMain(self: *Daemon) void {
        defer {
            self.watchdog_stop.store(true, .release);
            self.mutex.lock();
            self.watchdog_thread = null;
            self.mutex.unlock();
        }

        while (!self.watchdog_stop.load(.acquire)) {
            std.Thread.sleep(WATCHDOG_INTERVAL_NS);

            if (self.watchdog_stop.load(.acquire)) break;

            self.mutex.lock();
            if (self.session) |*session| {
                const now = std.time.timestamp();
                if (now >= session.end_epoch) {
                    _ = self.teardownSessionLocked(true) catch |err| {
                        std.log.err("failed to teardown session in watchdog: {s}", .{@errorName(err)});
                    };
                    self.mutex.unlock();
                    break;
                }

                if (now >= session.next_refresh_epoch) {
                    self.refreshSessionLocked(session) catch |err| {
                        std.log.err("session refresh failed: {s}", .{@errorName(err)});
                    };
                }

                self.mutex.unlock();

                const pf_enabled = pf.isEnabled(self.allocator) catch false;
                if (!pf_enabled) {
                    self.mutex.lock();
                    if (self.session) |*active_session| {
                        self.reapplySessionLocked(active_session) catch |err| {
                            std.log.err("failed to re-apply pf rules: {s}", .{@errorName(err)});
                        };
                    }
                    self.mutex.unlock();
                }
            } else {
                self.mutex.unlock();
                break;
            }
        }
    }

    fn handleRequest(self: *Daemon, req: ipc.Request) !ipc.Response {
        switch (req.op) {
            .start => {
                const start_cmd = req.start orelse return makeErrorResponse(self.allocator, "missing start payload");
                return self.handleStart(start_cmd);
            },
            .status => return self.handleStatus(),
            .ping => return makeOkResponse(self.allocator, null),
        }
    }

    fn handleStart(self: *Daemon, start_cmd: ipc.StartCommand) !ipc.Response {
        std.log.debug("handleStart: acquiring mutex", .{});
        self.mutex.lock();
        var locked = true;
        defer if (locked) self.mutex.unlock();

        const now = std.time.timestamp();
        try self.ensureSessionFreshnessLocked(now);

        if (self.session) |session| {
            if (now < session.end_epoch) {
                return makeErrorResponse(self.allocator, "session already active");
            }
            _ = try self.teardownSessionLocked(false);
        }

        const canonical_group = try config_mod.normalizeGroupNameCopy(self.allocator, start_cmd.group);
        var free_group = true;
        defer if (free_group) self.allocator.free(canonical_group);

        const config_path = try self.paths.configFile();
        defer self.allocator.free(config_path);

        var config = try config_mod.Config.loadFromFile(self.allocator, config_path);
        defer config.deinit();

        if (config.getGroup(canonical_group) == null) {
            std.log.debug("handleStart: group not found", .{});
            return makeErrorResponse(self.allocator, "group not found");
        }

        const domains = try config.sortedDomains(self.allocator, canonical_group);
        defer self.allocator.free(domains);

        var targets = try dns.resolveDomains(self.allocator, domains);
        defer targets.deinit(self.allocator);

        const duration_seconds = start_cmd.duration_seconds;
        if (duration_seconds == 0) {
            return makeErrorResponse(self.allocator, "duration must be greater than zero");
        }
        if (duration_seconds > @as(u64, @intCast(std.math.maxInt(i64)))) {
            return makeErrorResponse(self.allocator, "duration too large");
        }

        const apply_result = try pf.applyRules(self.allocator, &self.paths, targets, start_cmd.dns_lockdown);

        const end_epoch = now + @as(i64, @intCast(duration_seconds));
        const new_session = Session{
            .group = canonical_group,
            .start_epoch = now,
            .end_epoch = end_epoch,
            .dns_lockdown = start_cmd.dns_lockdown,
            .v4_count = apply_result.v4_count,
            .v6_count = apply_result.v6_count,
            .pf_was_enabled = apply_result.pf_was_enabled,
            .next_refresh_epoch = now + REFRESH_INTERVAL_SEC,
        };

        std.log.debug("handleStart: session prepared, releasing lock", .{});
        self.session = new_session;
        free_group = false;
        try self.persistSession();

        locked = false;
        self.mutex.unlock();
        std.log.debug("handleStart: mutex released", .{});

        try self.startWatchdog();
        std.log.debug("handleStart: watchdog started", .{});

        const message = try std.fmt.allocPrint(self.allocator, "Blocking until {d}", .{end_epoch});
        defer self.allocator.free(message);
        return makeOkResponse(self.allocator, message);
    }

    fn handleStatus(self: *Daemon) !ipc.Response {
        self.mutex.lock();

        const now = std.time.timestamp();
        try self.ensureSessionFreshnessLocked(now);
        var status = ipc.StatusData{ .active = false, .dns_lockdown = false, .v4_count = 0, .v6_count = 0 };

        if (self.session) |session| {
            status.active = true;
            status.dns_lockdown = session.dns_lockdown;
            status.v4_count = session.v4_count;
            status.v6_count = session.v6_count;
            status.until_epoch = session.end_epoch;
            if (session.end_epoch > now) {
                status.remaining_seconds = @as(u64, @intCast(session.end_epoch - now));
            } else {
                status.remaining_seconds = 0;
            }
            status.group = try self.allocator.dupe(u8, session.group);
        }

        self.mutex.unlock();

        std.log.info("status request processed (active={s})", .{if (status.active) "true" else "false"});

        return ipc.Response{ .ok = true, .message = null, .status = status };
    }

    fn ensureSessionFreshnessLocked(self: *Daemon, now: i64) !void {
        if (self.session) |session| {
            if (now >= session.end_epoch) {
                _ = try self.teardownSessionLocked(false);
            }
        }
    }

    fn teardownSessionLocked(self: *Daemon, called_from_watchdog: bool) !bool {
        if (self.session) |*session| {
            defer session.deinit(self.allocator);
            const pf_was_enabled = session.pf_was_enabled;
            self.session = null;
            self.watchdog_stop.store(true, .release);

            if (!called_from_watchdog) {
                if (self.watchdog_thread) |thread| {
                    thread.detach();
                    self.watchdog_thread = null;
                }
            }

            self.deleteActiveFile();
            self.schedulePfClear(pf_was_enabled);
            return false;
        }
        return false;
    }

    fn refreshSessionLocked(self: *Daemon, session: *Session) !void {
        const config_path = try self.paths.configFile();
        defer self.allocator.free(config_path);

        var config = try config_mod.Config.loadFromFile(self.allocator, config_path);
        defer config.deinit();

        if (config.getGroup(session.group) == null) {
            std.log.warn("group '{s}' removed; keeping session active with existing targets", .{session.group});
            return;
        }

        const domains = try config.sortedDomains(self.allocator, session.group);
        defer self.allocator.free(domains);

        var targets = try dns.resolveDomains(self.allocator, domains);
        defer targets.deinit(self.allocator);

        const apply_result = try pf.applyRules(self.allocator, &self.paths, targets, session.dns_lockdown);
        if (session.pf_was_enabled) {
            session.pf_was_enabled = apply_result.pf_was_enabled;
        }
        session.v4_count = apply_result.v4_count;
        session.v6_count = apply_result.v6_count;
        session.next_refresh_epoch = std.time.timestamp() + REFRESH_INTERVAL_SEC;
        try self.persistSession();
    }

    fn reapplySessionLocked(self: *Daemon, session: *Session) !void {
        const config_path = try self.paths.configFile();
        defer self.allocator.free(config_path);

        var config = try config_mod.Config.loadFromFile(self.allocator, config_path);
        defer config.deinit();

        if (config.getGroup(session.group) == null) {
            std.log.warn("group '{s}' removed while reapplying; keeping existing tables", .{session.group});
            return;
        }

        const domains = try config.sortedDomains(self.allocator, session.group);
        defer self.allocator.free(domains);

        var targets = try dns.resolveDomains(self.allocator, domains);
        defer targets.deinit(self.allocator);

        const apply_result = try pf.applyRules(self.allocator, &self.paths, targets, session.dns_lockdown);
        if (session.pf_was_enabled) {
            session.pf_was_enabled = apply_result.pf_was_enabled;
        }
        session.v4_count = apply_result.v4_count;
        session.v6_count = apply_result.v6_count;
        try self.persistSession();
    }

    fn loadActiveSession(self: *Daemon) !void {
        const path = self.paths.daemonActiveFile();
        var file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close();

        const file_size = try file.getEndPos();
        const size = std.math.cast(usize, file_size) orelse return;
        var buffer = try self.allocator.alloc(u8, size);
        defer self.allocator.free(buffer);
        const read_len = try file.readAll(buffer);
        const bytes = buffer[0..read_len];

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, bytes, .{});
        defer parsed.deinit();

        const root = parsed.value;
        const obj = switch (root) {
            .object => |o| o,
            else => return,
        };

        const group_value_ptr = obj.getPtr("group") orelse return;
        const group_str = switch (group_value_ptr.*) {
            .string => |s| s,
            else => return,
        };
        const group_copy = try self.allocator.dupe(u8, group_str);

        const start_value_ptr = obj.getPtr("start_epoch") orelse return;
        const end_value_ptr = obj.getPtr("end_epoch") orelse return;

        const start_epoch = switch (start_value_ptr.*) {
            .integer => |i| i,
            else => return,
        };
        const end_epoch = switch (end_value_ptr.*) {
            .integer => |i| i,
            else => return,
        };
        const dns_lockdown = blk: {
            if (obj.getPtr("dns_lockdown")) |dns_ptr| {
                break :blk switch (dns_ptr.*) {
                    .bool => |b| b,
                    else => false,
                };
            } else {
                break :blk false;
            }
        };

        const v4_count = if (obj.getPtr("v4_count")) |v4| switch (v4.*) {
            .integer => |i| if (i < 0) 0 else @as(usize, @intCast(i)),
            else => 0,
        } else 0;
        const v6_count = if (obj.getPtr("v6_count")) |v6| switch (v6.*) {
            .integer => |i| if (i < 0) 0 else @as(usize, @intCast(i)),
            else => 0,
        } else 0;
        const pf_was_enabled = blk: {
            if (obj.getPtr("pf_was_enabled")) |pf_ptr| {
                break :blk switch (pf_ptr.*) {
                    .bool => |b| b,
                    else => true,
                };
            } else break :blk true;
        };

        self.session = Session{
            .group = group_copy,
            .start_epoch = start_epoch,
            .end_epoch = end_epoch,
            .dns_lockdown = dns_lockdown,
            .v4_count = v4_count,
            .v6_count = v6_count,
            .pf_was_enabled = pf_was_enabled,
            .next_refresh_epoch = std.time.timestamp() + REFRESH_INTERVAL_SEC,
        };
    }

    fn persistSession(self: *Daemon) !void {
        if (self.session) |session| {
            var buffer = std.ArrayListUnmanaged(u8){};
            defer buffer.deinit(self.allocator);

            try buffer.appendSlice(self.allocator, "{\n  \"group\": ");
            try appendJsonString(&buffer, self.allocator, session.group);
            try buffer.appendSlice(self.allocator, ",\n  \"start_epoch\": ");
            try appendSigned(&buffer, self.allocator, session.start_epoch);
            try buffer.appendSlice(self.allocator, ",\n  \"end_epoch\": ");
            try appendSigned(&buffer, self.allocator, session.end_epoch);
            try buffer.appendSlice(self.allocator, ",\n  \"dns_lockdown\": ");
            try buffer.appendSlice(self.allocator, if (session.dns_lockdown) "true" else "false");
            try buffer.appendSlice(self.allocator, ",\n  \"v4_count\": ");
            try appendUnsigned(&buffer, self.allocator, session.v4_count);
            try buffer.appendSlice(self.allocator, ",\n  \"v6_count\": ");
            try appendUnsigned(&buffer, self.allocator, session.v6_count);
            try buffer.appendSlice(self.allocator, ",\n  \"pf_was_enabled\": ");
            try buffer.appendSlice(self.allocator, if (session.pf_was_enabled) "true" else "false");
            try buffer.appendSlice(self.allocator, "\n}\n");

            const data = try buffer.toOwnedSlice(self.allocator);
            defer self.allocator.free(data);
            try fs_util.atomicWriteFileAbsolute(self.paths.daemonActiveFile(), data);
        } else {
            self.deleteActiveFile();
        }
    }

    fn deleteActiveFile(self: *Daemon) void {
        std.fs.deleteFileAbsolute(self.paths.daemonActiveFile()) catch {};
    }
};

fn makeOkResponse(allocator: std.mem.Allocator, message: ?[]const u8) !ipc.Response {
    var response = ipc.Response{ .ok = true, .message = null, .status = null };
    if (message) |msg| {
        response.message = try allocator.dupe(u8, msg);
    }
    return response;
}

fn makeErrorResponse(allocator: std.mem.Allocator, message: []const u8) !ipc.Response {
    const response = ipc.Response{ .ok = false, .message = try allocator.dupe(u8, message), .status = null };
    return response;
}

fn pfClearRunner(self: *Daemon, pf_was_enabled: bool) void {
    runPfClearSync(self, pf_was_enabled);
}

fn runPfClearSync(self: *Daemon, pf_was_enabled: bool) void {
    pf.clearRules(self.allocator, &self.paths, pf_was_enabled) catch |err| {
        std.log.err("failed to clear pf rules: {s}", .{@errorName(err)});
    };
}

pub fn run(allocator: std.mem.Allocator) !void {
    var daemon = try Daemon.init(allocator);
    defer daemon.deinit();

    var address_cfg = try ipc.getAddress(allocator);
    defer {
        std.fs.deleteFileAbsolute(address_cfg.path) catch {};
        ipc.freeAddress(allocator, &address_cfg);
    }

    std.fs.deleteFileAbsolute(address_cfg.path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    const bind_addr = try std.net.Address.initUnix(address_cfg.path);
    var server = try std.net.Address.listen(bind_addr, .{ .reuse_address = true });
    defer server.deinit();

    std.posix.fchmodat(std.posix.AT.FDCWD, address_cfg.path, 0o666, 0) catch |err| {
        std.log.warn("failed to set socket permissions: {s}", .{@errorName(err)});
    };

    std.log.info("zblockd listening on {s}", .{address_cfg.path});

    while (true) {
        var connection = server.accept() catch |err| {
            std.log.err("accept failed: {s}", .{@errorName(err)});
            continue;
        };
        defer connection.stream.close();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const request_bytes = ipc.readRequest(arena.allocator(), &connection.stream) catch |err| {
            std.log.err("failed to read request: {s}", .{@errorName(err)});
            continue;
        };

        var request = ipc.decodeRequest(arena.allocator(), request_bytes) catch |err| {
            std.log.err("invalid request payload: {s}", .{@errorName(err)});
            var response = try makeErrorResponse(allocator, "invalid request");
            defer response.deinit(allocator);
            const encoded = try ipc.encodeResponse(arena.allocator(), response);
            defer arena.allocator().free(encoded);
            _ = ipc.writeResponse(&connection.stream, encoded) catch {};
            continue;
        };
        defer request.deinit(arena.allocator());

        var response = daemon.handleRequest(request) catch |err| {
            std.log.err("error handling request: {s}", .{@errorName(err)});
            var error_response = try makeErrorResponse(allocator, "internal error");
            defer error_response.deinit(allocator);
            const encoded_error = try ipc.encodeResponse(arena.allocator(), error_response);
            defer arena.allocator().free(encoded_error);
            _ = ipc.writeResponse(&connection.stream, encoded_error) catch {};
            continue;
        };
        defer response.deinit(allocator);

        const encoded = try ipc.encodeResponse(arena.allocator(), response);
        defer arena.allocator().free(encoded);
        _ = ipc.writeResponse(&connection.stream, encoded) catch |err| {
            std.log.err("failed writing response: {s}", .{@errorName(err)});
        };
    }
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
