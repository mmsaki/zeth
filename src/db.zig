//! A minimal durable key-value store: a single append-only log with an
//! in-memory index rebuilt on `open`. Last write wins; deletes are tombstones.
//!
//! This is the storage primitive the node persistence layer (and, later, sync)
//! is built on. It favors simplicity and crash-safety over write amplification:
//! every put/del appends a record, so a power loss can at worst lose records
//! that were never flushed, and a torn final record is detected by bounds-
//! checking during the open scan and dropped (the log is truncated back to the
//! last intact record). Compaction (rewriting the log without dead records) is
//! left for a later milestone.
//!
//! Record layout (little-endian framing):
//!   [key_len: u32][val_len: u32][key bytes][val bytes]
//! A delete is encoded with `val_len == TOMBSTONE` and no value bytes.
//!
//! File I/O goes through `std.Io` (positional reads/writes), so an `io` handle
//! is threaded through every operation, matching the rest of the node.

const std = @import("std");
const Io = std.Io;

pub const Db = struct {
    allocator: std.mem.Allocator,
    io: Io,
    file: Io.File,
    /// Owned key bytes → location of the live value in the log.
    index: std.StringHashMapUnmanaged(Entry) = .{},
    /// Offset at which the next record is appended (end of the intact log).
    end: u64 = 0,

    const Entry = struct { off: u64, len: u32 };
    const TOMBSTONE: u32 = 0xFFFF_FFFF;
    const FILE_NAME = "zeth.db";

    /// Open (creating if absent) the database under `dir_path`, replaying the
    /// log to rebuild the in-memory index. A torn tail record is dropped and the
    /// file truncated back to the last intact record.
    pub fn open(allocator: std.mem.Allocator, io: Io, dir_path: []const u8) !Db {
        try Io.Dir.cwd().createDirPath(io, dir_path);
        var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
        defer dir.close(io);
        const file = try dir.createFile(io, FILE_NAME, .{ .read = true, .truncate = false });

        var db = Db{ .allocator = allocator, .io = io, .file = file };
        errdefer db.deinitIndex();
        try db.replay();
        return db;
    }

    pub fn close(self: *Db) void {
        self.file.sync(self.io) catch {};
        self.file.close(self.io);
        self.deinitIndex();
    }

    fn deinitIndex(self: *Db) void {
        var it = self.index.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.index.deinit(self.allocator);
    }

    /// Scan the whole log front-to-back, applying each record to the index.
    fn replay(self: *Db) !void {
        const size = try self.file.length(self.io);
        var pos: u64 = 0;
        var hdr: [8]u8 = undefined;
        while (pos + 8 <= size) {
            if ((try self.file.readPositionalAll(self.io, &hdr, pos)) != 8) break;
            const klen = std.mem.readInt(u32, hdr[0..4], .little);
            const vlen = std.mem.readInt(u32, hdr[4..8], .little);
            const is_tomb = vlen == TOMBSTONE;
            const body: u64 = @as(u64, klen) + (if (is_tomb) 0 else @as(u64, vlen));
            if (pos + 8 + body > size) break; // torn tail record — stop here

            const key = try self.allocator.alloc(u8, klen);
            defer self.allocator.free(key);
            if ((try self.file.readPositionalAll(self.io, key, pos + 8)) != klen) break;

            if (is_tomb) {
                self.removeKey(key);
            } else {
                try self.setIndex(key, .{ .off = pos + 8 + klen, .len = vlen });
            }
            pos += 8 + body;
        }
        self.end = pos;
        // Drop any torn tail so the next append starts at an intact boundary.
        if (pos != size) try self.file.setLength(self.io, pos);
    }

    fn removeKey(self: *Db, key: []const u8) void {
        if (self.index.fetchRemove(key)) |kv| self.allocator.free(kv.key);
    }

    /// Point the index at a value, owning a copy of the key (reusing the
    /// existing key allocation on overwrite).
    fn setIndex(self: *Db, key: []const u8, entry: Entry) !void {
        const gop = try self.index.getOrPut(self.allocator, key);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
        }
        gop.value_ptr.* = entry;
    }

    /// Append `val` for `key`, making it the live value.
    pub fn put(self: *Db, key: []const u8, val: []const u8) !void {
        std.debug.assert(val.len < TOMBSTONE);
        var hdr: [8]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], @intCast(key.len), .little);
        std.mem.writeInt(u32, hdr[4..8], @intCast(val.len), .little);
        try self.file.writePositionalAll(self.io, &hdr, self.end);
        try self.file.writePositionalAll(self.io, key, self.end + 8);
        try self.file.writePositionalAll(self.io, val, self.end + 8 + key.len);
        try self.setIndex(key, .{ .off = self.end + 8 + key.len, .len = @intCast(val.len) });
        self.end += 8 + key.len + val.len;
    }

    /// Fetch the live value for `key` (caller owns the returned slice), or null.
    pub fn get(self: *Db, allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
        const entry = self.index.get(key) orelse return null;
        const buf = try allocator.alloc(u8, entry.len);
        errdefer allocator.free(buf);
        if ((try self.file.readPositionalAll(self.io, buf, entry.off)) != entry.len) return error.ShortRead;
        return buf;
    }

    pub fn has(self: *const Db, key: []const u8) bool {
        return self.index.contains(key);
    }

    /// Append a tombstone, removing `key` from the live set.
    pub fn del(self: *Db, key: []const u8) !void {
        if (!self.index.contains(key)) return;
        var hdr: [8]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], @intCast(key.len), .little);
        std.mem.writeInt(u32, hdr[4..8], TOMBSTONE, .little);
        try self.file.writePositionalAll(self.io, &hdr, self.end);
        try self.file.writePositionalAll(self.io, key, self.end + 8);
        self.end += 8 + key.len;
        self.removeKey(key);
    }

    /// Flush buffered writes to stable storage.
    pub fn flush(self: *Db) !void {
        try self.file.sync(self.io);
    }

    /// Iterate the live keys (order unspecified). Keys are borrowed from the
    /// index — valid until the next put/del. Fetch values with `get`.
    pub const KeyIterator = struct {
        inner: std.StringHashMapUnmanaged(Entry).KeyIterator,
        pub fn next(self: *KeyIterator) ?[]const u8 {
            return if (self.inner.next()) |k| k.* else null;
        }
    };
    pub fn keys(self: *const Db) KeyIterator {
        return .{ .inner = self.index.keyIterator() };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

fn testIo(threaded: *Io.Threaded) Io {
    threaded.* = Io.Threaded.init(testing.allocator, .{});
    return threaded.io();
}

test "db put/get/overwrite/delete" {
    var threaded: Io.Threaded = undefined;
    const io = testIo(&threaded);
    defer threaded.deinit();
    const dir = "zeth-db-test-basic";
    defer Io.Dir.cwd().deleteTree(io, dir) catch {};

    var db = try Db.open(testing.allocator, io, dir);
    defer db.close();

    try db.put("alpha", "one");
    try db.put("beta", "two");
    {
        const v = (try db.get(testing.allocator, "alpha")).?;
        defer testing.allocator.free(v);
        try testing.expectEqualStrings("one", v);
    }
    try db.put("alpha", "uno"); // overwrite
    {
        const v = (try db.get(testing.allocator, "alpha")).?;
        defer testing.allocator.free(v);
        try testing.expectEqualStrings("uno", v);
    }
    try db.del("beta");
    try testing.expect((try db.get(testing.allocator, "beta")) == null);
    try testing.expect((try db.get(testing.allocator, "missing")) == null);
}

test "db durability across reopen" {
    var threaded: Io.Threaded = undefined;
    const io = testIo(&threaded);
    defer threaded.deinit();
    const dir = "zeth-db-test-reopen";
    defer Io.Dir.cwd().deleteTree(io, dir) catch {};

    {
        var db = try Db.open(testing.allocator, io, dir);
        try db.put("k1", "v1");
        try db.put("k2", "v2");
        try db.put("k1", "v1-updated");
        try db.del("k2");
        const big = try testing.allocator.alloc(u8, 1000);
        defer testing.allocator.free(big);
        @memset(big, 0);
        try db.put("k3", big);
        try db.flush();
        db.close();
    }
    {
        var db = try Db.open(testing.allocator, io, dir);
        defer db.close();
        const v1 = (try db.get(testing.allocator, "k1")).?;
        defer testing.allocator.free(v1);
        try testing.expectEqualStrings("v1-updated", v1);
        try testing.expect((try db.get(testing.allocator, "k2")) == null); // tombstoned
        const v3 = (try db.get(testing.allocator, "k3")).?;
        defer testing.allocator.free(v3);
        try testing.expectEqual(@as(usize, 1000), v3.len);
    }
}

test "db tolerates a torn tail record" {
    var threaded: Io.Threaded = undefined;
    const io = testIo(&threaded);
    defer threaded.deinit();
    const dir = "zeth-db-test-torn";
    defer Io.Dir.cwd().deleteTree(io, dir) catch {};

    {
        var db = try Db.open(testing.allocator, io, dir);
        try db.put("good", "value");
        db.close();
    }
    // Append a partial record: the header claims a 100-byte value but only the
    // 3-byte key follows.
    {
        var d = try Io.Dir.cwd().openDir(io, dir, .{});
        defer d.close(io);
        var f = try d.openFile(io, Db.FILE_NAME, .{ .mode = .read_write });
        defer f.close(io);
        const at = try f.length(io);
        var hdr: [8]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], 3, .little); // key_len = 3
        std.mem.writeInt(u32, hdr[4..8], 100, .little); // val_len = 100 (but we write less)
        try f.writePositionalAll(io, &hdr, at);
        try f.writePositionalAll(io, "bad", at + 8); // key, then nothing — torn
    }
    {
        var db = try Db.open(testing.allocator, io, dir);
        defer db.close();
        const v = (try db.get(testing.allocator, "good")).?;
        defer testing.allocator.free(v);
        try testing.expectEqualStrings("value", v); // the intact record survives
        try testing.expect((try db.get(testing.allocator, "bad")) == null); // torn dropped
    }
}
