# Hermes Decompiler (C Implementation)

This is a C implementation of the Hermes HBC (Hermes Bytecode) disassembler and decompiler with zero external dependencies. It can be used to analyze React Native files compiled into the Hermes VM bytecode format.

## Features

- Disassembles Hermes bytecode to readable assembly
- Decompiles Hermes bytecode to JavaScript-like pseudo-code
- Supports multiple bytecode versions (72-96)
- Zero external dependencies
- Fast and efficient implementation

## Build Instructions

To build the project, simply run:

```
make
```

For a debug build with additional debugging information:

```
make debug
```

To clean the build:

```
make clean
```

### Library build

The build produces a static library at `build/libhermesdec.a` and a CLI tool at `bin/hermes-dec`. Public headers live in `include/`, with the high-level API at `include/hermesdec/hermesdec.h`.

Linking example (GCC):

```
gcc -Iinclude your_app.c -Lbuild -lhermesdec -o your_app
```

### Public API quick start

```
#include "hermesdec/hermesdec.h"

int main() {
    HermesDec* hd = NULL;
    Result r = hermesdec_open("path/to/file.hbc", &hd);
    if (r.code != RESULT_SUCCESS) return 1;

    u32 n = hermesdec_function_count(hd);
    for (u32 i = 0; i < n; i++) {
        const char* name; u32 off, size, argc;
        if (hermesdec_get_function_info(hd, i, &name, &off, &size, &argc).code == RESULT_SUCCESS) {
            printf("fn %u @0x%x size=%u name=%s\n", i, off, size, name);
        }
    }

    DisassemblyOptions opt = {0};
    opt.verbose = true;
    StringBuffer sb; string_buffer_init(&sb, 4096);
    hermesdec_disassemble_function_to_buffer(hd, 0, opt, &sb);
    puts(sb.data);
    string_buffer_free(&sb);

    hermesdec_close(hd);
    return 0;
}
```

## Usage

```
./bin/hermes-dec <command> <input_file> [output_file]
```

### Commands

- `disassemble` (or `dis`, `d`): Disassemble a Hermes bytecode file
- `decompile` (or `dec`, `c`): Decompile a Hermes bytecode file
- `header` (or `h`): Display header information only

### Options

- `--verbose` (`-v`): Show detailed metadata
- `--json` (`-j`): Output in JSON format (disassembler only)
- `--bytecode` (`-b`): Show raw bytecode bytes (disassembler only)
- `--debug` (`-d`): Show debug information (disassembler only)

If no output file is specified, output will be written to stdout.

## Examples

Disassemble a bytecode file:

```
./bin/hermes-dec disassemble assets/index.android.bundle output.hasm
```

Decompile a bytecode file:

```
./bin/hermes-dec decompile assets/index.android.bundle output.js
```

Display bytecode header information:

```
./bin/hermes-dec header assets/index.android.bundle
```

## License

This project is licensed under the BSD license, the same as the original Hermes implementation.
