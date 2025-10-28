# Hermes Decompiler (C Implementation)

This is a C implementation of the Hermes HBC (Hermes Bytecode) disassembler and
decompiler with zero external dependencies. It can be used to analyze React
Native files compiled into the Hermes VM bytecode format.

## Features

- Disassembles Hermes bytecode to readable assembly
- Decompiles Hermes bytecode to JavaScript-like pseudo-code (WIP)
- Supports multiple bytecode versions (72-96)
- Zero external dependencies (only libc)
- Fast and efficient implementation

## Build Instructions

To build the project, simply run:

```bash
make
make user-install
```

To clean the build:

```bash
make clean
```

### Library build

The build produces a static library:

* `build/libhermesdec.a` and a CLI tool at `bin/hermes-dec`.

Public headers live in `include/`, with the high-level API at:

* `include/hermesdec/hermesdec.h`.

Linking example (GCC):

```bash
gcc -Iinclude your_app.c -Lbuild -lhermesdec -o your_app
```

### Public API quick start

```c
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

## License

This project is licensed under the BSD license, the same as the original Hermes implementation.
