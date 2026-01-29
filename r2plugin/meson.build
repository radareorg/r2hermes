# Version
# XXX reuse from parent meson.build or wtf
version = '1.0.0'

# Version extraction
version_parts = version.split('.')
version_major = version_parts[0]
version_minor = version_parts.length() > 1 ? version_parts[1] : '0'
version_patch = version_parts.length() > 2 ? version_parts[2] : '0'

# Generate version.h
configure_file(
  input: '../include/hbc/version.h.in',
  output: 'version.h',
  configuration: {
    'VERSION': version,
    'VERSION_MAJOR': version_major,
    'VERSION_MINOR': version_minor,
    'VERSION_PATCH': version_patch,
  },
  install_dir: 'libr/hbc',
  install: true,
)

# Include directories (relative to this meson.build file location)
include_dirs = include_directories(join_paths('..', 'include'))
r_core_additional_inc += include_dirs

# Library source files
lib_utils_src = files(
  '../src/lib/utils/string_buffer.c',
  '../src/lib/utils/buffer_reader.c',
)

lib_parsers_src = files(
  '../src/lib/parsers/hbc_file_parser.c',
  '../src/lib/parsers/hbc_bytecode_parser.c',
)

lib_disasm_src = []  # Disassembly sources (if any)

lib_decompile_src = files(
  '../src/lib/decompilation/translator.c',
  '../src/lib/decompilation/token.c',
  '../src/lib/decompilation/literals.c',
  '../src/lib/decompilation/decompiler.c',
)

lib_opcodes_src = files(
  '../src/lib/opcodes/isa.c',
  '../src/lib/opcodes/encoder.c',
  '../src/lib/opcodes/decoder.c',
)

lib_core_src = files(
  '../src/lib/hbc.c',
  '../src/lib/r2.c',
  '../src/r2/core_hbc_one.c',
)

lib_src = lib_utils_src + lib_parsers_src + lib_disasm_src + lib_decompile_src + lib_opcodes_src + lib_core_src

r_core_additional_sources += lib_src
