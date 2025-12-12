# Project Description

This repo contains a zero‑dependency C11 implementation of a Hermes HBC (Hermes Bytecode) disassembler/decompiler, a thin public library API, a CLI, and optional radare2 integration. It also embeds the original Python reference (hbctool/) for parity checks.

Use this guide to navigate the code, extend features, and avoid common pitfalls when changing the codebase.

**Repo Layout**
- `src/` C sources
  - `lib/` public API glue (`hermesdec.c`)
  - `parsers/` file + bytecode parsing (HBC reader, instruction decode)
  - `disassembly/` textual disassembler
  - `decompilation/` pseudo‑JS decompiler + formatting helpers
  - `opcodes/` opcode tables and operand metadata
  - `utils/` small infrastructure: `BufferReader`, `StringBuffer`
- `include/` public and internal headers; mirrors `src/` layout
  - Public API root: `include/hermesdec/hermesdec.h`
- `bin/` CLI output (`hbctool`)
- `build/` static library and objects (`libhermesdec.a`)
- `r2/` radare2 plugin sources (optional)
- `hbctool/` Python reference implementation and assets (no runtime dependency)
- `tests/` placeholder for future C tests; some assets live at repo root

**Build & Run**
- Build library + CLI: `make`
- Debug build: `make debug` (adds `-g -DDEBUG`)
- Clean: `make clean`
- Run CLI: `./bin/hbctool <command> <input> [output]`

Common CLI commands (see `src/main.c` for the full set):
- `disassemble|dis|d` — disassemble file
- `decompile|dec|c` — decompile to pseudo‑JS
- `asm` — decode raw bytes string (rasm2‑like)
- `header|h` — show header only
- `validate|v` — basic format validation report
- `r2script|r2|r` — generate radare2 script with function flags
- `funcs` — dump first N function headers
- `cmp, cmpfunc, str, findstr, strmeta` — utilities for cross‑checks and string lookup

Options shared across disassembly:
- `--verbose|-v`, `--json|-j`, `--bytecode|-b`, `--debug|-d`, `--asmsyntax`
- Decompiler knobs: `--pretty-literals|-P`, `--no-pretty-literals|-N`, `--no-comments|-C`

radare2 plugins (optional):
- Build + user‑install: `make -C r2 && make -C r2 user-install` or `make r2`

**Public API (Stable)**
- Header: `include/hermesdec/hermesdec.h`
- Open/close: `hermesdec_open`, `hermesdec_open_from_memory`, `hermesdec_close`
- Introspection: `hermesdec_get_header`, `hermesdec_function_count`, `hermesdec_string_count`, `hermesdec_get_function_info`, `hermesdec_get_string`, `hermesdec_get_string_meta`, `hermesdec_get_function_source`
- Bytecode access: `hermesdec_get_function_bytecode`
- Disasm: `hermesdec_disassemble_function_to_buffer`, `hermesdec_disassemble_all_to_buffer`, `hermesdec_decode_function_instructions` (+ `hermesdec_free_instructions`)
- Decompilation: `hermesdec_decompile_all_to_buffer`, `hermesdec_decompile_function_to_buffer`, `hermesdec_decompile_file`
- Utilities: `hermesdec_validate_basic`, `hermesdec_generate_r2_script`
- Minimal single‑instruction decode: `hermesdec_decode_single_instruction`
- Encoding (assembler): `hermesdec_encode_instruction`, `hermesdec_encode_instructions`

Lifetimes and ownership:
- `HermesDec*` owns all parsed state. Pointers returned by getters (e.g., strings) remain valid until `hermesdec_close`.
- Arrays returned (e.g., `HermesInstruction*`) must be freed via the matching free function.
- `StringBuffer` must be initialized and freed by the caller.

**Internal Architecture**
- HBC Reader (`include/parsers/hbc_file_parser.h`, `src/parsers/hbc_file_parser.c`)
  - Parses the file header → function headers → string tables → literals/regex → modules → debug.
  - Robust path: `hbc_reader_read_whole_file()` orchestrates; `hbc_reader_read_functions_robust()` caps counts and guards memory.
  - Safety: bounds‑checked reads via `BufferReader`; aligns where needed.
- Bytecode parser (`include/parsers/hbc_bytecode_parser.h`, `src/parsers/hbc_bytecode_parser.c`)
  - Uses the opcode table to parse instructions into `ParsedInstruction` lists.
  - Handles special forms like `SwitchImm` jump tables conservatively.
- Opcode tables (`include/opcodes/*.h`, `src/opcodes/*.c`)
  - `get_instruction_set_v96()` returns a 256‑entry table. Many opcodes are defined; unknowns default to size 1 with name "Unknown".
  - Operand type/meaning drive disassembly formatting and encode/decode.
- Disassembler (`include/disassembly/*`, `src/disassembly/*`)
  - Renders either structured listing or `--asmsyntax` mnemonic form with absolute addresses.
- Decompiler (`include/decompilation/*`, `src/decompilation/*`)
  - Multi‑pass structure reconstruction. Formatting controls in `literals.h`:
    - `set_literals_pretty_policy()`, `set_decompile_suppress_comments()`.
- Encoder (`include/hermes_encoder.h`, `src/hermes_encoder.c`)
  - Minimal assembler for common mnemonics; used by radare2 plugin.

**Coding Conventions**
- C11, compiled with `-Wall -Wextra -Werror -std=c11 -pedantic`.
- Error handling uses `Result` and helpers in `include/common.h`:
  - `SUCCESS_RESULT()`, `ERROR_RESULT(...)`, `RETURN_IF_ERROR(...)`.
- Prefer explicit sizes (`u8/u16/u32/u64`), and check all allocations/reads.
- Keep memory ownership clear; free everything in `hbc_reader_cleanup`/`hermesdec_close`.
- Avoid unused code/params (breaks `-Werror`). Remove dead code or `#if 0` rather than leaving stubs.
- Match existing naming: snake_case for functions, PascalCase for public structs/enums, `HBC*`/`Hermes*` prefixes where relevant.

**Extending Opcodes/Versions**
- Add or refine opcode definitions in `src/opcodes/hermes_opcodes.c` (and update `include/opcodes/hermes_opcodes.h` if needed).
  - Define mnemonic, operand types, meanings, and total size.
  - The parser/disassembler will pick them up via `get_instruction_set_v96()`.
- Versions >96 currently reuse v96 with warnings. If needed, add a new table and select it in `src/parsers/hbc_bytecode_parser.c`.
- When adding new operand meanings, ensure disassembler formatting and encoder support are updated accordingly.

**Typical Workflows**
- Quick sanity on a bundle: `./bin/hbctool header main.jsbundle`
- Inspect functions: `./bin/hbctool funcs main.jsbundle`
- Disassemble with asm syntax: `./bin/hbctool d main.jsbundle -v --asmsyntax > out.hasm`
- Decompile: `./bin/hbctool dec main.jsbundle > out.js`
- Compare with Python: `./bin/hbctool cmp main.jsbundle hbctool/tests/sample.hermes_dec_hdec`

**radare2 Integration Tips**
- After `make r2`, r2 will have a Hermes arch/bin plugin (see `r2/*.c`). The encoder backs assembling simple mnemonics.
- Generate flags script for r2: `./bin/hbctool r2 main.jsbundle out.r2` and `r2 -qi out.r2 main.jsbundle`.

**Testing**
- Minimal test hooks exist in `Makefile`:
  - `make test` runs a short disassembly on `../main.jsbundle` (adjust path as needed).
  - `make otest` builds a test runner if `tests/*.c` are added.
- Use the Python reference under `hbctool/` and the `cmp*` CLI commands for cross‑validation.

**Large Assets**
- Sample bundles (`main.jsbundle`, `amazon.jsbundle`) are present for local experimentation. Avoid modifying or relying on them in tests by default.

**When Adding Public API**
- Edit `include/hermesdec/hermesdec.h` and implement in `src/lib/hermesdec.c`.
- Keep string/array lifetimes consistent and document ownership.
- Update `README.md` usage snippets if behavior changes.

**Gotchas**
- Many reads are guarded; avoid bypassing `BufferReader` helpers.
- `--asmsyntax` changes operand rendering (addresses become file‑absolute, strings resolve to storage addresses). Keep both modes consistent.
- Some opcodes are placeholders; the disassembler will print "Unknown" with size 1. Add definitions rather than ad‑hoc decoding.
- The encoder is intentionally minimal; if you expand mnemonics, ensure size/operand encoding matches the disassembler’s view.

This file applies to the entire repo. When editing, stay focused and minimal: prefer surgical changes and preserve the current structure.

