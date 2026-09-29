//! binfmt_misc-compatible command line: interpreter executable [arguments...].
const std = @import("std");
const user = @import("mirage-jit").user;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2 or std.mem.eql(u8, args[1], "--help")) {
        std.debug.print("usage: mirage-aarch64 PROGRAM [ARGUMENT...]\nLinux AArch64 user-mode execution through Vulcan (scalar instructions only).\n", .{});
        std.process.exit(if (args.len < 2) 1 else 0);
    }
    const env = try allocator.alloc([]const u8, init.environ_map.count());
    var iterator = init.environ_map.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) {
        env[index] = try std.fmt.allocPrint(allocator, "{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    const status = user.run(init.gpa, init.io, args[1], args[1..], env) catch |err| {
        std.debug.print("mirage-aarch64: {s}: {s}\n", .{ args[1], @errorName(err) });
        std.process.exit(1);
    };
    std.process.exit(status);
}
