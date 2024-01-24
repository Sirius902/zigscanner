const std = @import("std");
const testing = std.testing;
const Signature = @import("Signature.zig");
const PatternByte = Signature.PatternByte;

pub fn formatSignature(sig: Signature, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    try formatPatternByte(sig.pattern[0], fmt, options, writer);
    for (sig.pattern[1..]) |pb| {
        try writer.writeByte(' ');
        try formatPatternByte(pb, fmt, options, writer);
    }
}

pub fn fmtSignature(sig: Signature) std.fmt.Formatter(formatSignature) {
    return .{ .data = sig };
}

pub fn formatPatternByte(pb: PatternByte, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    switch (pb) {
        .Any => try writer.writeAll("??"),
        .Byte => |b| try std.fmt.formatIntValue(b, fmt, options, writer),
    }
}

pub fn fmtPatternByte(pb: PatternByte) std.fmt.Formatter(formatPatternByte) {
    return .{ .data = pb };
}

test "fmtSignature" {
    const sig_str = "E8 ?? ?? 34 89 00";
    const sig = comptime Signature.parse(sig_str);

    try testing.expectEqualStrings("232 ?? ?? 52 137 0", std.fmt.comptimePrint("{}", .{comptime fmtSignature(sig)}));
    try testing.expectEqualStrings(sig_str, std.fmt.comptimePrint("{X:0>2}", .{comptime fmtSignature(sig)}));
}
