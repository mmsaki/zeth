//! `make eels` conformance runner: executes official ethereum/tests fixtures
//! against zeth and checks the result by 32-byte root — the same oracle a real
//! node is held to.
//!
//! This first stage runs the **TrieTests** suite (root-checked) against our
//! Merkle-Patricia Trie. State-test (full EVM) conformance is the next layer
//! and reuses the same trie/state-root machinery.
//!
//!   eels <secured:0|1> <fixture.json> [more.json ...]

const std = @import("std");
const zeth = @import("zeth");

var g_color = true;
fn clr(comptime code: []const u8) []const u8 {
    return if (g_color) code else "";
}
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";

const Tally = struct { pass: usize = 0, total: usize = 0 };

/// `0x`-prefixed strings are hex; everything else is raw bytes (the convention
/// used throughout ethereum/tests fixtures).
fn decode(a: std.mem.Allocator, s: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, s, "0x")) return s;
    const out = a.alloc(u8, (s.len - 2) / 2) catch @panic("oom");
    _ = std.fmt.hexToBytes(out, s[2..]) catch return &.{};
    return out;
}

fn runFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8, secured: bool) Tally {
    var t = Tally{};
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited) catch |e| {
        std.debug.print("  cannot read {s}: {s}\n", .{ path, @errorName(e) });
        return t;
    };
    defer gpa.free(content);

    var parsed = std.json.parseFromSlice(std.json.Value, gpa, content, .{}) catch |e| {
        std.debug.print("  bad json {s}: {s}\n", .{ path, @errorName(e) });
        return t;
    };
    defer parsed.deinit();

    const suite = path; // full path so the fixture source is visible
    const count = parsed.value.object.count();
    std.debug.print("{s}{s}{s}{s}{s}{s}\n", .{
        clr(CYAN), suite, clr(RESET), clr(DIM), if (secured) " (secured)" else "", clr(RESET),
    });

    var idx: usize = 0;
    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const test_obj = entry.value_ptr.object;
        idx += 1;
        t.total += 1;

        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();

        // Apply the insert/delete ops to get the final key→value map. The "in"
        // field is a list of [k,v] pairs (trietest) or a {k:v} object
        // (trieanyorder); v == null deletes.
        var keys = std.ArrayList([]const u8).empty;
        var vals = std.ArrayList([]const u8).empty;
        const apply = struct {
            fn op(al: std.mem.Allocator, ks: *std.ArrayList([]const u8), vs: *std.ArrayList([]const u8), raw_k: []const u8, v: std.json.Value) void {
                const k = decode(al, raw_k);
                var i: usize = 0;
                while (i < ks.items.len) : (i += 1) {
                    if (std.mem.eql(u8, ks.items[i], k)) {
                        _ = ks.orderedRemove(i);
                        _ = vs.orderedRemove(i);
                        break;
                    }
                }
                if (v != .null) {
                    ks.append(al, k) catch @panic("oom");
                    vs.append(al, decode(al, v.string)) catch @panic("oom");
                }
            }
        }.op;

        switch (test_obj.get("in").?) {
            .array => |arr| for (arr.items) |pair| apply(a, &keys, &vals, pair.array.items[0].string, pair.array.items[1]),
            .object => |obj| {
                var oit = obj.iterator();
                while (oit.next()) |e| apply(a, &keys, &vals, e.key_ptr.*, e.value_ptr.*);
            },
            else => continue,
        }

        var pairs = a.alloc(zeth.trie.KV, keys.items.len) catch @panic("oom");
        for (keys.items, vals.items, 0..) |k, v, i| pairs[i] = .{ .key = k, .value = v };
        const got = zeth.trie.computeRoot(a, pairs, secured);

        var expected: [32]u8 = undefined;
        const root_hex = test_obj.get("root").?.string;
        _ = std.fmt.hexToBytes(&expected, root_hex[2..]) catch {};

        const ok = std.mem.eql(u8, &got, &expected);
        if (ok) t.pass += 1;
        std.debug.print("  {s}{d}/{d}{s} TrieTests.{s}...{s}{s}{s}\n", .{
            clr(DIM),                 idx,        count,
            clr(RESET),               name,       if (ok) clr(GREEN) else clr(RED),
            if (ok) "OK" else "FAIL", clr(RESET),
        });
        if (!ok) std.debug.print("      {s}got {x}\n      want {s}{s}\n", .{ clr(DIM), &got, root_hex, clr(RESET) });
    }
    return t;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const nc = init.environ_map.get("NO_COLOR");
    g_color = nc == null or nc.?.len == 0;

    if (args.len < 3) {
        std.debug.print("usage: eels <secured:0|1> <fixture.json> ...\n", .{});
        return error.MissingArgument;
    }
    const secured = std.mem.eql(u8, args[1], "1");

    var total: usize = 0;
    var passed: usize = 0;
    for (args[2..]) |path| {
        const t = runFile(gpa, init.io, path, secured);
        total += t.total;
        passed += t.pass;
    }

    const all_ok = passed == total;
    std.debug.print("\n{s}{s}{d}/{d} passed{s}\n", .{
        clr(BOLD), if (all_ok) clr(GREEN) else clr(RED), passed, total, clr(RESET),
    });
    if (!all_ok) return error.ConformanceFailed;
}
