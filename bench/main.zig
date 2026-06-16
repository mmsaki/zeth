//! A `poop`-style statistical benchmark comparison for the EVM core.
//!
//! Inspired by https://github.com/andrewrk/poop. poop itself is Linux-only —
//! it reads hardware counters (cpu_cycles, instructions, cache/branch-misses)
//! via the `perf_event_open` syscall, which doesn't exist on macOS. This
//! harness implements the portable half: it runs each benchmark for many
//! samples and reports mean ± σ, min … max, and a colored A/B delta against
//! the first benchmark — measuring wall-time, CPU-time (via getrusage), and our
//! exact domain metrics (opcodes, gas, throughput).
//!
//! On Linux this is where perf_event_open counters would slot in as extra rows.

const std = @import("std");
const zeth = @import("zeth");

const Clock = std.Io.Clock;

const SAMPLES = 30;
const WARMUP = 2;
const LOOP_COUNT: u24 = 250_000;

var g_io: std.Io = undefined;
var g_color = true;

// ANSI styling (suppressed when NO_COLOR is set or output isn't wanted).
fn c(comptime code: []const u8) []const u8 {
    return if (g_color) code else "";
}
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";

// --- Benchmark workloads: a loop with a stack-neutral body ---

/// Emit `PUSH3 count, JUMPDEST, <body>, decrement, JUMPI back` — a loop that
/// runs `body` `count` times. `body` must leave the loop counter on top.
fn buildLoop(arena: std.mem.Allocator, body: []const u8, count: u24) ![]u8 {
    var p: std.ArrayList(u8) = .empty;
    try p.appendSlice(arena, &.{
        0x62, @intCast((count >> 16) & 0xFF), @intCast((count >> 8) & 0xFF), @intCast(count & 0xFF), // PUSH3 count
        0x5B, // JUMPDEST  (loop start, offset 4)
    });
    try p.appendSlice(arena, body);
    try p.appendSlice(arena, &.{
        0x60, 0x01, 0x90, 0x03, // PUSH1 1 SWAP1 SUB   (counter -= 1)
        0x80, 0x60, 0x04, 0x57, // DUP1 PUSH1 4 JUMPI  (loop while != 0)
    });
    return p.items;
}

const Workload = struct { name: []const u8, body: []const u8 };

const workloads = [_]Workload{
    .{ .name = "arithmetic", .body = &.{ 0x80, 0x80, 0x02, 0x60, 0x07, 0x01, 0x50 } }, // DUP1 DUP1 MUL PUSH1 7 ADD POP
    .{ .name = "keccak256", .body = &.{ 0x60, 0x20, 0x60, 0x00, 0x20, 0x50 } }, // PUSH1 32 PUSH1 0 KECCAK POP
    .{ .name = "codecopy", .body = &.{ 0x60, 0x20, 0x60, 0x00, 0x60, 0x00, 0x39 } }, // PUSH1 32 PUSH1 0 PUSH1 0 CODECOPY
    .{ .name = "sstore", .body = &.{ 0x60, 0x01, 0x60, 0x00, 0x55 } }, // PUSH1 1 PUSH1 0 SSTORE
};

// --- Measurement ---

const Sample = struct { wall_ns: f64, cpu_ns: f64 };

fn tvNs(tv: anytype) f64 {
    return @as(f64, @floatFromInt(tv.sec)) * 1e9 + @as(f64, @floatFromInt(tv.usec)) * 1e3;
}

fn runOnce(allocator: std.mem.Allocator, code: []const u8, ops: *u64, gas: *u64) Sample {
    const ru0 = std.posix.getrusage(0);
    const t0 = Clock.now(.awake, g_io);

    var evm = zeth.Evm.init(allocator, code, std.math.maxInt(u64)) catch @panic("oom");
    evm.run();
    ops.* = evm.op_count;
    gas.* = std.math.maxInt(u64) - evm.gas_left;
    evm.deinit();

    const t1 = Clock.now(.awake, g_io);
    const ru1 = std.posix.getrusage(0);
    const cpu = (tvNs(ru1.utime) - tvNs(ru0.utime)) + (tvNs(ru1.stime) - tvNs(ru0.stime));
    return .{ .wall_ns = @floatFromInt(t0.durationTo(t1).nanoseconds), .cpu_ns = cpu };
}

// --- Statistics ---

const Stats = struct {
    mean: f64,
    sd: f64,
    min: f64,
    max: f64,

    fn of(xs: []const f64) Stats {
        var sum: f64 = 0;
        var lo = xs[0];
        var hi = xs[0];
        for (xs) |x| {
            sum += x;
            lo = @min(lo, x);
            hi = @max(hi, x);
        }
        const mean = sum / @as(f64, @floatFromInt(xs.len));
        var v: f64 = 0;
        for (xs) |x| v += (x - mean) * (x - mean);
        const sd = if (xs.len > 1) @sqrt(v / @as(f64, @floatFromInt(xs.len - 1))) else 0;
        return .{ .mean = mean, .sd = sd, .min = lo, .max = hi };
    }
};

const Result = struct {
    name: []const u8,
    ops: u64,
    gas: u64,
    wall: Stats,
    cpu: Stats,
    thr: Stats, // Mopcodes/s
};

// --- Formatting ---

fn fmtTime(buf: []u8, ns: f64) []const u8 {
    if (ns < 1e3) return std.fmt.bufPrint(buf, "{d:.1}ns", .{ns}) catch buf[0..0];
    if (ns < 1e6) return std.fmt.bufPrint(buf, "{d:.2}us", .{ns / 1e3}) catch buf[0..0];
    if (ns < 1e9) return std.fmt.bufPrint(buf, "{d:.2}ms", .{ns / 1e6}) catch buf[0..0];
    return std.fmt.bufPrint(buf, "{d:.2}s", .{ns / 1e9}) catch buf[0..0];
}

/// Print one "mean ± σ   min … max   [Δ]" row. When `green_value` is set the
/// mean ± σ cell is shown in green to flag the best result.
fn printRow(label: []const u8, s: Stats, comptime time: bool, base: ?Stats, higher_better: bool, green_value: bool) void {
    var b1: [32]u8 = undefined;
    var b2: [32]u8 = undefined;
    var b3: [32]u8 = undefined;
    var b4: [32]u8 = undefined;
    const mean = if (time) fmtTime(&b1, s.mean) else std.fmt.bufPrint(&b1, "{d:.1}", .{s.mean}) catch "";
    const sd = if (time) fmtTime(&b2, s.sd) else std.fmt.bufPrint(&b2, "{d:.1}", .{s.sd}) catch "";
    const lo = if (time) fmtTime(&b3, s.min) else std.fmt.bufPrint(&b3, "{d:.1}", .{s.min}) catch "";
    const hi = if (time) fmtTime(&b4, s.max) else std.fmt.bufPrint(&b4, "{d:.1}", .{s.max}) catch "";

    var mean_sd: [80]u8 = undefined;
    const ms = std.fmt.bufPrint(&mean_sd, "{s} ± {s}", .{ mean, sd }) catch "";
    var range: [80]u8 = undefined;
    const rg = std.fmt.bufPrint(&range, "{s} … {s}", .{ lo, hi }) catch "";

    const vcol = if (green_value) c(GREEN) else "";
    const vrst = if (green_value) c(RESET) else "";
    std.debug.print("  {s: <12}{s}{s: <26}{s}{s: <26}", .{ label, vcol, ms, vrst, rg });

    if (base) |base_stats| {
        const pct = (s.mean - base_stats.mean) / base_stats.mean * 100.0;
        // Combined relative uncertainty of the two means.
        const rel = @sqrt(rsq(s.sd, s.mean) + rsq(base_stats.sd, base_stats.mean)) * 100.0;
        const good = if (higher_better) pct > 0 else pct < 0;
        const color = if (@abs(pct) < 1.0) c(DIM) else if (good) c(GREEN) else c(RED);
        const arrow = if (pct > 0) "+" else "";
        std.debug.print("{s}{s}{d:.1}% ± {d:.1}%{s}", .{ color, arrow, pct, rel, c(RESET) });
    }
    std.debug.print("\n", .{});
}

fn rsq(sd: f64, mean: f64) f64 {
    if (mean == 0) return 0;
    const r = sd / mean;
    return r * r;
}

pub fn main(init: std.process.Init) !void {
    g_io = init.io;
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    // NO_COLOR disables color only when present AND non-empty (no-color.org).
    const no_color = init.environ_map.get("NO_COLOR");
    g_color = no_color == null or no_color.?.len == 0;

    var results: [workloads.len]Result = undefined;
    var wall_s: [SAMPLES]f64 = undefined;
    var cpu_s: [SAMPLES]f64 = undefined;
    var thr_s: [SAMPLES]f64 = undefined;

    for (workloads, 0..) |w, wi| {
        const code = try buildLoop(arena, w.body, LOOP_COUNT);
        var ops: u64 = 0;
        var gas: u64 = 0;

        var i: usize = 0;
        while (i < WARMUP) : (i += 1) _ = runOnce(gpa, code, &ops, &gas);

        i = 0;
        while (i < SAMPLES) : (i += 1) {
            const s = runOnce(gpa, code, &ops, &gas);
            wall_s[i] = s.wall_ns;
            cpu_s[i] = s.cpu_ns;
            thr_s[i] = @as(f64, @floatFromInt(ops)) / (s.wall_ns / 1e9) / 1e6;
        }

        results[wi] = .{
            .name = w.name,
            .ops = ops,
            .gas = gas,
            .wall = Stats.of(&wall_s),
            .cpu = Stats.of(&cpu_s),
            .thr = Stats.of(&thr_s),
        };
    }

    // The fastest workload's throughput is flagged green as "good".
    var best_thr: f64 = 0;
    for (results) |r| best_thr = @max(best_thr, r.thr.mean);

    std.debug.print("\n{s}zeth EVM — poop-style comparison{s}  ({d} samples, loop x{d})\n\n", .{ c(BOLD), c(RESET), SAMPLES, LOOP_COUNT });

    for (results, 0..) |r, ri| {
        const base = if (ri == 0) null else results[0];
        std.debug.print("{s}Benchmark {d}{s} ({d} runs): {s}{s}{s}\n", .{ c(BOLD), ri + 1, c(RESET), SAMPLES, c(CYAN), r.name, c(RESET) });
        std.debug.print("  {s}{d} opcodes, {d} gas{s}\n", .{ c(DIM), r.ops, r.gas, c(RESET) });
        std.debug.print("  {s}{s: <12}{s: <26}{s: <26}{s}{s}\n", .{ c(DIM), "measurement", "mean ± σ", "min … max", if (base == null) "" else "vs benchmark 1", c(RESET) });
        printRow("wall_time", r.wall, true, if (base) |b| b.wall else null, false, false);
        printRow("cpu_time", r.cpu, true, if (base) |b| b.cpu else null, false, false);
        printRow("throughput", r.thr, false, if (base) |b| b.thr else null, true, r.thr.mean == best_thr);
        std.debug.print("  {s}(throughput in Mopcodes/s){s}\n\n", .{ c(DIM), c(RESET) });
    }

    std.debug.print("{s}note: hardware counters (cycles, instructions, cache/branch-misses) require\n      Linux perf_event_open and are not available on this platform.{s}\n", .{ c(DIM), c(RESET) });
}
