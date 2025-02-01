SHELL = bash
RUSTC = rustc --target x86_64-pc-windows-msvc -Copt-level=3 -Cpanic=abort -Clinker=lld-link -Clink-arg=/NODEFAULTLIB -Clink-arg=/debug:none -Cdebuginfo=0

build: empty_exe.exe one_dll.exe two_dll.exe constant_data.exe

empty_exe.exe: empty_exe.rs
	$(RUSTC) empty_exe.rs

constant_data.exe: constant_data.rs
	$(RUSTC) constant_data.rs

one_dll.exe: one_dll.rs small_dll.dll
	$(RUSTC) one_dll.rs

small_dll.dll: small_dll.rs
	$(RUSTC) small_dll.rs

ordinal_dll.dll: ordinal_dll.rs ordinal_dll.def
	$(RUSTC) -Clink-arg=/def:ordinal_dll.def ordinal_dll.rs

two_dll.exe: small_dll.dll ordinal_dll.dll
	$(RUSTC) two_dll.rs

.PHONY: clean
clean:
	shopt -s nullglob
	rm *.exe *.pdb *.dll *.lib
