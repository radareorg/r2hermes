# Project Description

This repo contains a zero-dependency C11 implementation of a Hermes HBC (Hermes Bytecode) disassembler/decompiler, a thin public library API, a CLI, and optional radare2 integration. It also embeds the original Python reference for parity checks.

Use this guide to navigate the code, extend features, and avoid common pitfalls when changing the codebase.

**Repo Layout**
- `src/` C sources
- `include/` public and internal headers
- `bin/` CLI output
- `build/` static library and objects
- `r2/` radare2 plugin sources (optional)
- `hbctool/` Python reference implementation
- `tests/` placeholder for tests

**Build & Run**
- Build library + CLI: `make`
- Debug build: `make debug`
- Clean: `make clean`
- Run CLI: `./bin/hbctool <command> <input> [output]`

**Public API**
- Header: `include/hermesdec/hermesdec.h`
- Functions for opening/closing files, introspection, disassembly, decompilation, and utilities.

**Coding Conventions**
- C11, compiled with `-Wall -Wextra -Werror -std=c11 -pedantic`.
- Error handling uses `Result` helpers.
- Prefer explicit sizes and check allocations/reads.
- Keep memory ownership clear.
- Avoid unused code/params.
- Naming: snake_case for functions, PascalCase for structs/enums.

**Testing**
- Use `make test` for basic tests.
- Compare with Python reference for validation.

**Key Modules**
- `src/lib/decompilation/translator.c` - Instruction-to-token translation with operand validation
  - All register operands checked via `reg_l_safe()` / `reg_r_safe()` helpers
  - Operand types validated via `is_operand_register()` before use
  - Register bounds checked via `is_valid_register()` against function frameSize
  - See TRANSLATION_FIX.md for implementation details

This file applies to the entire repo. When editing, stay focused and minimal: prefer surgical changes and preserve the current structure.
