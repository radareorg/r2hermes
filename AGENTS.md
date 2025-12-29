# Project Description

This repo contains a zero-dependency C11 implementation of a Hermes HBC (Hermes Bytecode) disassembler/decompiler, a thin public library API, a CLI, and optional radare2 integration.

Use this guide to navigate the code, extend features, and avoid common pitfalls when changing the codebase.

**Repo Layout**
- `src/lib` C sources for the library
- `src/r2/` radare2 plugin sources (optional)
- `src/tool/` source code of the libhbctool program
- `include/` public and internal headers
- `bin/` where the libhbctool CLI program is compiled
- `build/` static library and objects
- `tests/` testsuite based on `r2r` tool

**Build & Run**
- Build library + libhbctool cli tool: `make` (no debug messages)
- Build with address sanitizer checks: `make asan`
- Build library + radare2 plugins + user-install: `make r2`
- Format the source with `make fmt` (requires `clang-format-radare2`)
- Clean: `make clean`
- Run CLI: `./bin/libhbctool <command> <input> [output]`

**Public API**
- Primary header: `include/hbc/hbc.h`
- **Main interface**: HBC (short for HBCDataProvider, flexible data sources: files, buffers, r2)
  - Factories: `hbc_new_file()`, `hbc_new_buf()`, `hbc_new_r2()`
  - Query: `hbc_hdr()`, `hbc_func_info()`, `hbc_str()`, `hbc_bytecode()`, etc.
  - Decompilation: `hbc_decomp_fn()`, `hbc_decomp_all()`
  - Type aliases: `HBCFunc`, `HBCDisOptions`, `HBCDecompOptions`, `HBCInsns`, `HBCStrs`, etc.

**Coding Conventions**
- C11, compiled with `-Wall -Wextra -Werror -std=c11 -pedantic`.
- Use `clang-format-radare2` tool to indent the source
- Error handling uses `Result` helpers.
- Constant size allocations does not require null checks.
- Prefer explicit sizes and check allocations/reads.
- Keep memory ownership clear.
- Avoid unused code/params.
- Naming functions in `snake_case` and struct/enum in `CamelCase`.

**Testing**
- Use `make test` for basic tests.

This file applies to the entire repo. When editing, stay focused and minimal: prefer surgical changes and preserve the current structure.
