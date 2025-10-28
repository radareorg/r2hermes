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

Read the `src/main.c` as an example about how to use this library.

## License

This project is licensed under the BSD license, the same as the original Hermes implementation.
