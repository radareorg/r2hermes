# r2hermes

![CI](https://github.com/radareorg/r2hermes/actions/workflows/ci.yml/badge.svg)
![Meson](https://github.com/radareorg/r2hermes/actions/workflows/meson.yml/badge.svg)
![Windows](https://github.com/radareorg/r2hermes/actions/workflows/windows.yml/badge.svg)

Meta's React Native Hermes bytecode assembler, disassembler, decompiler, and compation radare2 plugins.

<center>
<img width="250px" height="500px" src="r2hermes500.png" />
</center>

## Features

- Disassemble Hermes bytecode (v51 .. v96)
- Decompile to JavaScript pseudocode
- Assemble instructions
- Parse binary headers
- Verify and fix footer hash (for binary patching)
- Full radare2 integration

## Installing

### From r2pm (recommended)

```bash
r2pm -ci r2hermes
```

### From source

```bash
git clone https://github.com/radareorg/r2hermes
cd r2hermes
make
make user-install
```

## Building

### Make (default)

```bash
make              # Build library and CLI
make user-install # Install r2 plugins to ~/.local/share/radare2/plugins
```

### Meson

```bash
meson setup build
ninja -C build
ninja -C build install
```

### Debug build

```bash
make debug
```

### AddressSanitizer build

```bash
make asan
```

## Usage

Open a Hermes bytecode file:

```bash
r2 index.android.bundle
```

### Commands

```
[0x00000000]> pd:h?
Usage: pd:h[subcommand]
  pd:h           - Decompile function at current offset (or all if not in function)
  pd:hc [id]     - Decompile function by id
  pd:ha          - Decompile all functions
  pd:hf          - List all functions
  pd:hi          - Show file information and hash status
  pd:hj [id]     - JSON output for function
  pd:ho [id]     - Decompile with offsets (addresses) per statement
  pd:hoa         - Decompile all with offsets
  pd:h?          - Show this help
  .(fix-hbc)     - Fix/update footer hash (for binary patching)
```

### Examples

```bash
# Decompile function at current address
[0x00001234]> pd:h

# Decompile function by ID
[0x00000000]> pd:hc 42

# Decompile all functions
[0x00000000]> pd:ha

# List all functions
[0x00000000]> pd:hf

# Show file info and hash status
[0x00000000]> pd:hi

# Fix footer hash (for binary patching)
[0x00000000]> .(fix-hbc)
```

### Footer Hash Patching

Hermes validates a SHA1 footer hash at runtime. When patching binaries:

```bash
# Check hash status
r2 file.hbc -qc 'pd:hi'

# Fix/add footer hash (works with or without existing footer)
r2 -wqc '.(fix-hbc)' file.hbc
```

## Configuration (radare2)

```bash
# Pretty-print literals (objects, arrays)
e hbc.pretty_literals=true

# Suppress comments in output
e hbc.suppress_comments=false

# Show bytecode offsets per statement
e hbc.show_offsets=false

# Skip decompiler passes (for debugging)
e hbc.skip_pass1=false  # Metadata collection
e hbc.skip_pass2=false  # Code transformation
e hbc.skip_pass3=false  # For-in loop parsing
e hbc.skip_pass4=false  # Closure variable naming
```

## Dependencies

- C11 compiler (gcc, clang)
- radare2 (for plugins, optional)

## License

This project is licensed under the BSD license.
