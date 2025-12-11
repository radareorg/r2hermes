# HBCLIB - Hermes Library and Radare2 Plugin

This is a library to work with Hermes binaries and VM Bytecode (v90-v96) for:

- Assemble Bytecode
- Disassemble Bytecode
- Decompile Functions in JS pseudocode
- Parse Binary Headers

The library is implemented in plain C with no external dependencies and comes with the plugins for radare2.

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

## License

This project is licensed under the BSD license.
