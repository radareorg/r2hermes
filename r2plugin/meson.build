# r2hermes XPS integration for radare2.
# Included from libr/xps/meson.build when r2hermes sources live under
# libr/xps/p/r2hermes/. Appends sources and include paths to the r_core
# aggregate so the static plugin is linked into libr_core.

core_plugins += ['r2hermes']

r_core_additional_inc += include_directories(join_paths('..', 'include'))

r_core_additional_sources += files(
  '../src/lib/utils/string_buffer.c',
  '../src/lib/utils/buffer_reader.c',
  '../src/lib/parsers/hbc_file_parser.c',
  '../src/lib/parsers/hbc_bytecode_parser.c',
  '../src/lib/decompilation/translator.c',
  '../src/lib/decompilation/token.c',
  '../src/lib/decompilation/literals.c',
  '../src/lib/decompilation/decompiler.c',
  '../src/lib/opcodes/isa.c',
  '../src/lib/opcodes/encoder.c',
  '../src/lib/opcodes/decoder.c',
  '../src/lib/hbc.c',
  '../src/lib/literals_api.c',
  '../src/lib/r2.c',
  '../src/r2/core_hbc_one.c',
)
