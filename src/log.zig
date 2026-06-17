//! A small structured logger: `LEVEL [HH:MM:SS.mmm] message key=val …`, leveled
//! (INFO/WARN/EROR), timestamped (UTC, from the Io clock), and colorized when
//! stderr is a terminal. Call `init(io)` once at startup so timestamps work.

const std = @import("std");
const Io = std.Io;

var log_io: ?Io = null;
var use_color: bool = false;

pub fn init(io: Io) void {
    log_io = io;
    use_color = false; // TODO: colorize when stderr is a tty (Io.File.isTty)
}

pub const Level = enum {
    info,
    warn,
    err,
    fn tag(l: Level) []const u8 {
        return switch (l) {
            .info => "INFO",
            .warn => "WARN",
            .err => "EROR",
        };
    }
    fn color(l: Level) []const u8 {
        return switch (l) {
            .info => "\x1b[32m", // green
            .warn => "\x1b[33m", // yellow
            .err => "\x1b[31m", // red
        };
    }
};

pub fn info(comptime fmt: []const u8, args: anytype) void {
    emit(.info, fmt, args);
}
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    emit(.warn, fmt, args);
}
pub fn err(comptime fmt: []const u8, args: anytype) void {
    emit(.err, fmt, args);
}

fn emit(level: Level, comptime fmt: []const u8, args: anytype) void {
    var tb: [13]u8 = undefined;
    const ts = timeString(&tb);
    if (use_color) {
        std.debug.print("{s}{s}\x1b[0m [{s}] " ++ fmt ++ "\n", .{ level.color(), level.tag(), ts } ++ args);
    } else {
        std.debug.print("{s} [{s}] " ++ fmt ++ "\n", .{ level.tag(), ts } ++ args);
    }
}

/// UTC wall-clock as HH:MM:SS.mmm (best-effort; "--:--:--.---" before init).
fn timeString(buf: *[13]u8) []const u8 {
    const io = log_io orelse return "--:--:--.---";
    const ns: i128 = Io.Clock.real.now(io).toNanoseconds();
    if (ns <= 0) return "--:--:--.---";
    const total_ms: u64 = @intCast(@divFloor(ns, 1_000_000));
    const ms = total_ms % 1000;
    const sod = (total_ms / 1000) % 86400;
    const h = sod / 3600;
    const m = (sod % 3600) / 60;
    const s = sod % 60;
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{ h, m, s, ms }) catch "??:??:??.???";
}
