const std = @import("std");
const zs = @import("zigscanner");

pub fn main() !void {
    const sig = comptime zs.Signature.parse("E8 ?? 48 83 ?? ?? 00");
    std.log.info("{X:0>2}", .{zs.fmt.fmtSignature(sig)});
}
