SHELL = bash
RUSTC = rustc --target x86_64-pc-windows-msvc -Cpanic=abort -Clinker=lld-link -Clink-arg=/NODEFAULTLIB -Clink-arg=/debug:none -Cdebuginfo=0

build: empty_exe.exe one_dll.exe

empty_exe.exe: empty_exe.rs
	$(RUSTC) empty_exe.rs

one_dll.exe: one_dll.rs small_dll.dll
	$(RUSTC) one_dll.rs

small_dll.dll: small_dll.rs
	$(RUSTC) small_dll.rs

.PHONY: clean
clean:
	shopt -s nullglob
	rm *.exe *.pdb *.dll *.lib
