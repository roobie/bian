
default:
  just --list

dev:
  watchexec just run

run:
  zig build test
  zig build run -- arg1 arg2
