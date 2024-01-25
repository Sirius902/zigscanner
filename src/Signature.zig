const std = @import("std");
const log = @import("log.zig");
const testing = std.testing;
const fmt = @import("fmt.zig");
const Allocator = std.mem.Allocator;

pattern: []const PatternByte,

const Self = @This();

const suggested_vec_len = std.simd.suggestVectorLength(u8);

/// Scans for a signature within `data`. Returns the index of the start of the
/// signature.
pub const scan = if (suggested_vec_len) |_| simdScan else linearScan;

pub fn parse(comptime pattern: []const u8) Self {
    if (!@inComptime()) @compileError("Expected parse to be called in comptime");
    if (pattern.len == 0) @compileError("Expected pattern to be non-empty");

    var pattern_bytes: []const PatternByte = &.{};

    var i: usize = 0;
    while (i < pattern.len) {
        if (pattern.len - i < 2) @compileError("Expected pattern byte");

        const byte = PatternByte.parse(pattern[i .. i + 2]) catch @compileError("Expected valid pattern byte");
        i += 2;
        pattern_bytes = pattern_bytes ++ &[_]PatternByte{byte};

        if (i >= pattern.len) break;
        if (pattern[i] != ' ') @compileError("Expected \" \" after pattern byte");
        i += 1;
        if (i >= pattern.len) @compileError("Unexpected end of input");
    }

    return .{ .pattern = pattern_bytes };
}

pub fn parseAlloc(pattern: []const u8, allocator: Allocator) (ParseError || Allocator.Error)!Self {
    if (pattern.len == 0) return error.InvalidPattern;

    var pattern_bytes = std.ArrayList(PatternByte).init(allocator);
    errdefer pattern_bytes.deinit();

    var i: usize = 0;
    while (i < pattern.len) {
        if (pattern.len - i < 2) return error.InvalidPattern;

        const byte = try PatternByte.parse(pattern[i .. i + 2]);
        i += 2;
        try pattern_bytes.append(byte);

        if (i >= pattern.len) break;
        if (pattern[i] != ' ') return error.InvalidPattern;
        i += 1;
        if (i >= pattern.len) return error.InvalidPattern;
    }

    return .{ .pattern = try pattern_bytes.toOwnedSlice() };
}

/// Only call if this signature was parsed using an allocator.
pub fn deinit(self: Self, allocator: Allocator) void {
    allocator.free(self.pattern);
}

/// Scans for a signature in the range [`begin`, `end`). Returns a pointer to
/// the start of the signature.
pub fn scanPtr(self: Self, begin: anytype, end: @TypeOf(begin)) ?@TypeOf(begin) {
    if (@typeInfo(@TypeOf(begin)).Pointer.child != u8) {
        @compileError("Expected u8 pointer");
    }

    const len = @intFromPtr(end) - @intFromPtr(begin);
    const off = self.scan(begin[0..len]) orelse return null;
    return @as(@TypeOf(begin), @ptrFromInt(@intFromPtr(begin) + off));
}

/// Scans linearly for the signature within `data`. Returns the index of the
/// start of the signature.
///
/// Prefer using `scan` instead as it will use an implementation suited to the
/// target CPU.
pub fn linearScan(self: Self, data: []const u8) ?usize {
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        if (self.isMatch(data[i..])) return i;
    }

    return null;
}

pub fn isMatch(self: Self, bytes: []const u8) bool {
    if (bytes.len < self.pattern.len) return false;

    for (self.pattern, 0..) |pb, i| {
        if (!pb.isMatch(bytes[i])) return false;
    }

    return true;
}

fn simdScan(self: Self, data: []const u8) ?usize {
    const chunk_len = suggested_vec_len orelse unreachable;

    const true_vec: @Vector(chunk_len, bool) = @splat(true);
    var pattern_vec: @Vector(chunk_len, u8) = @splat(0);
    var any_select: @Vector(chunk_len, bool) = @splat(true);

    for (self.pattern, 0..) |pb, i| {
        switch (pb) {
            .Byte => |b| {
                pattern_vec[i] = b;
                any_select[i] = false;
            },
            else => {},
        }
    }

    var anchor_byte: u8 = undefined;
    var anchor_off: usize = undefined;
    for (self.pattern, 0..) |pb, i| {
        switch (pb) {
            .Byte => |b| {
                anchor_byte = b;
                anchor_off = i;
                break;
            },
            else => {},
        }
    } else {
        std.debug.panic(
            "Expected pattern to contain at least one Byte, but got: {X:0>2}",
            .{fmt.fmtSignature(self)},
        );
    }

    const anchor_vec: @Vector(chunk_len, u8) = @splat(anchor_byte);
    const false_vec: @Vector(chunk_len, bool) = @splat(false);

    var chunk: @Vector(chunk_len, u8) = undefined;
    var i: usize = 0;
    while (i + chunk_len <= data.len) {
        @memcpy(@as([*]u8, @ptrCast(&chunk)), data[i .. i + chunk_len]);

        const is_match = @reduce(.And, @select(bool, any_select, true_vec, chunk == pattern_vec));
        if (is_match) return i;

        var anchors = chunk == anchor_vec;
        anchors[0] = false;

        var anchor_in_bounds: @Vector(chunk_len, bool) = @splat(true);
        if (i < anchor_off) {
            for (0..anchor_off - i) |j| {
                anchor_in_bounds[j] = false;
            }
        }

        const valid_anchors = @select(bool, anchor_in_bounds, anchors, false_vec);

        // TODO: Make sure candidate's start isn't before the start of data.
        if (std.simd.firstTrue(valid_anchors)) |anchor_idx| {
            i += anchor_idx - anchor_off;
            continue;
        } else {
            i += chunk_len;
        }
    }

    return self.linearScan(data[i..]);
}

pub const ParseError = error{
    InvalidPattern,
};

pub const PatternByte = union(enum) {
    Any,
    Byte: u8,

    pub fn parse(str: []const u8) ParseError!PatternByte {
        if (str.len != 2) return error.InvalidPattern;
        if (std.mem.eql(u8, str, "??")) return .Any;
        return .{ .Byte = std.fmt.parseInt(u8, str, 16) catch return error.InvalidPattern };
    }

    pub fn isMatch(self: PatternByte, b: u8) bool {
        return switch (self) {
            .Any => true,
            .Byte => |bb| bb == b,
        };
    }
};

test "Signature.parse" {
    inline for (.{
        .{ "34 ?? AB 48 ?? ??", &[_]PatternByte{ .{ .Byte = 0x34 }, .Any, .{ .Byte = 0xAB }, .{ .Byte = 0x48 }, .Any, .Any } },
    }) |case| {
        const sig = case.@"0";
        const expected = case.@"1";

        const sig_alloc = try Self.parseAlloc(sig, testing.allocator);
        defer sig_alloc.deinit(testing.allocator);

        try testing.expectEqualSlices(PatternByte, expected, (comptime Self.parse(sig)).pattern);
        try testing.expectEqualSlices(PatternByte, expected, sig_alloc.pattern);
    }

    inline for (.{
        .{ "", error.InvalidPattern },
        .{ " ", error.InvalidPattern },
        .{ " 34", error.InvalidPattern },
        .{ "34 ", error.InvalidPattern },
        .{ "xy", error.InvalidPattern },
    }) |case| {
        const sig = case.@"0";
        const expected = case.@"1";

        const result = Self.parseAlloc(sig, testing.allocator);
        defer if (result) |sig_alloc| sig_alloc.deinit(testing.allocator) else |_| {};

        try testing.expectError(expected, result);
    }
}
