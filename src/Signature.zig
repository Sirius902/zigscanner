const std = @import("std");
const log = @import("log.zig");
const testing = std.testing;
const Allocator = std.mem.Allocator;

pattern: []const PatternByte,

const Self = @This();

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
