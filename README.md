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