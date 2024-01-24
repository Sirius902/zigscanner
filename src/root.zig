const std = @import("std");
const zigscanner = @import("zigscanner.zig");

comptime {
    _ = std.testing.refAllDeclsRecursive(zigscanner);
}
