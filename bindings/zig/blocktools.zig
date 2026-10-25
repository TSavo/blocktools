//! Thin Zig wrapper over libblocktools_c (secrets-off).
const std = @import("std");

const c = struct {
    extern fn bt_version() [*:0]const u8;
    extern fn bt_chain_table() ?[*:0]u8;
    extern fn bt_envelope(json_utf8: [*:0]const u8) ?[*:0]u8;
    extern fn bt_free(p: ?[*:0]u8) void;
};

pub fn version() []const u8 {
    return std.mem.span(c.bt_version());
}

pub fn chainTableJson(allocator: std.mem.Allocator) ![]u8 {
    const p = c.bt_chain_table() orelse return error.Null;
    defer c.bt_free(p);
    return try allocator.dupe(u8, std.mem.span(p));
}

pub fn envelopeJson(allocator: std.mem.Allocator, req: [:0]const u8) ![]u8 {
    const p = c.bt_envelope(req.ptr) orelse return error.Null;
    defer c.bt_free(p);
    return try allocator.dupe(u8, std.mem.span(p));
}

test "version and table" {
    const v = version();
    try std.testing.expect(v.len > 0 and v[0] >= '0' and v[0] <= '9');
    const table = try chainTableJson(std.testing.allocator);
    defer std.testing.allocator.free(table);
    try std.testing.expect(std.mem.indexOf(u8, table, "\"name\":\"btc\"") != null);
}
