#!/usr/bin/env bash

rustc example_exe.rs --target x86_64-pc-windows-msvc -Cpanic=abort -Clinker=lld-link -Clink-arg=/entry:my_main -Clink-arg=/NODEFAULTLIB -Cdebuginfo=0
