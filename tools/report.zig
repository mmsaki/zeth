//! Shared conformance reporting for the statetest/blocktest runners. Renders a
//! pytest-style row of ✓/✗ marks as tests run (live to the terminal — no pipe,
//! so no buffering games), buffers the verbose failure detail, and prints it
//! after the graph along with a summary. Also walks a directory for fixtures.

const std = @import("std");

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";

pub const Reporter = struct {
    alloc: std.mem.Allocator,
    color: bool = true,
    width: usize = 100,
    pass: usize = 0,
    fail: usize = 0,
    skip: usize = 0,
    col: usize = 0,
    fails: std.ArrayList(u8) = .empty, // buffered verbose failure text

    fn c(self: *const Reporter, comptime code: []const u8) []const u8 {
        return if (self.color) code else "";
    }

    /// Emit one ✔/✘ mark, wrapping the row at the terminal width.
    fn mark(self: *Reporter, ok: bool) void {
        const glyph = if (ok) "✔" else "✘";
        std.debug.print("{s}{s}{s}", .{ if (ok) self.c(GREEN) else self.c(RED), glyph, self.c(RESET) });
        self.col += 1;
        if (self.col % (self.width -| 2) == 0) std.debug.print("\n  ", .{});
    }

    pub fn passed(self: *Reporter) void {
        self.pass += 1;
        self.mark(true);
    }

    pub fn failed(self: *Reporter) void {
        self.fail += 1;
        self.mark(false);
    }

    pub fn skipped(self: *Reporter) void {
        self.skip += 1;
    }

    /// Append a line to the buffered failure detail (printed after the graph).
    pub fn failLine(self: *Reporter, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.allocPrint(self.alloc, fmt, args) catch return;
        defer self.alloc.free(s);
        self.fails.appendSlice(self.alloc, s) catch {};
    }

    /// Print the buffered failures and the final summary. Returns true if all
    /// executed tests passed.
    pub fn finish(self: *Reporter, label: []const u8) bool {
        if (self.fails.items.len > 0) {
            std.debug.print("\n\n{s}── failures ──{s}\n{s}", .{ self.c(BOLD), self.c(RESET), self.fails.items });
        }
        const ok = self.fail == 0;
        // The passed count is always green; only the failed count goes red.
        std.debug.print("\n{s}{s} {s}{d} passed{s}, {s}{d} failed{s}, {s}{d} skipped{s}\n", .{
            self.c(BOLD),   label,
            self.c(GREEN),  self.pass,
            self.c(RESET),  if (self.fail == 0) self.c(DIM) else self.c(RED),
            self.fail,      self.c(RESET),
            self.c(YELLOW), self.skip,
            self.c(RESET),
        });
        return ok;
    }
};

/// Expand `paths` (files or directories) into a sorted list of `*.json`
/// fixtures, skipping EEST `.meta` sidecars. Directories are walked recursively.
pub fn collectJson(alloc: std.mem.Allocator, io: std.Io, paths: []const []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    const cwd = std.Io.Dir.cwd();
    for (paths) |p| {
        var dir = cwd.openDir(io, p, .{ .iterate = true }) catch {
            // Not a directory — treat as a single file.
            try list.append(alloc, try alloc.dupe(u8, p));
            continue;
        };
        defer dir.close(io);
        var walker = try dir.walk(alloc);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.path, ".json")) continue;
            if (std.mem.indexOf(u8, entry.path, ".meta") != null) continue;
            const full = try std.fs.path.join(alloc, &.{ p, entry.path });
            try list.append(alloc, full);
        }
    }
    std.mem.sort([]const u8, list.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    return list.items;
}
