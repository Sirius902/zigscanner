const std = @import("std");
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
