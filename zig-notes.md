# Notes regarding zig coding for personal reference

```zig
// a scratch buffer as a fixed length array of u8 values.
var buf: [1024]u8 = @splat(0);

// @min is the mathematical minimum function
const length = @min(64, file_size);

// for dumping output, use std.debug.print
std.debug.print("File data: {s}\n", .{buffer});

// use @memset to set all elements in an array to some u8
@memset(&buf, 0);
```
