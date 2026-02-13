project(
  'r2hermes',
  'c',
  version: '1.2.1',
  license: 'MIT',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'werror=false',
  ],
)

# Compiler flags
add_project_arguments([
  '-D_POSIX_C_SOURCE=200809L',
  '-fPIC',
], language: 'c')

# Version extraction
version_parts = meson.project_version().split('.')
version_major = version_parts[0]
version_minor = version_parts.length() > 1 ? version_parts[1] : '0'
version_patch = version_parts.length() > 2 ? version_parts[2] : '0'

# Generate version.h
configure_file(
  input: 'include/hbc/version.h.in',
  output: 'version.h',
  configuration: {
    'VERSION': meson.project_version(),
    'VERSION_MAJOR': version_major,
    'VERSION_MINOR': version_minor,
    'VERSION_PATCH': version_patch,
  },
  install_dir: 'include/hbc',
  install: true,
)

# Include directories
include_dirs = include_directories('include')

# Library source files
lib_utils_src = files(
  'src/lib/utils/string_buffer.c',
  'src/lib/utils/buffer_reader.c',
)

lib_parsers_src = files(
  'src/lib/parsers/hbc_file_parser.c',
  'src/lib/parsers/hbc_bytecode_parser.c',
)

lib_disasm_src = []  # Disassembly sources (if any)

lib_decompile_src = files(
  'src/lib/decompilation/translator.c',
  'src/lib/decompilation/token.c',
  'src/lib/decompilation/literals.c',
  'src/lib/decompilation/decompiler.c',
)

lib_opcodes_src = files(
  'src/lib/opcodes/isa.c',
  'src/lib/opcodes/encoder.c',
  'src/lib/opcodes/decoder.c',
)

lib_core_src = files(
  'src/lib/hbc.c',
  'src/lib/r2.c'
)

lib_src = lib_core_src + lib_utils_src + lib_parsers_src + lib_disasm_src + lib_decompile_src + lib_opcodes_src

# Build the library
libhbc = static_library(
  'hbc',
  lib_src,
  include_directories: include_dirs,
  c_args: ['-pedantic'],
  install: true,
)

# Public library dependency
libhbc_dep = declare_dependency(
  link_with: libhbc,
  include_directories: include_dirs,
)

# Install library headers
install_subdir('include/hbc',
  install_dir: 'include',
)

# libhbctool CLI
libhbctool_src = files('src/tool/libhbctool.c')

executable(
  'libhbctool',
  libhbctool_src,
  link_with: libhbc,
  include_directories: include_dirs,
  c_args: ['-pedantic'],
  install: true,
)

# radare2 plugins
r2_core = dependency('r_core', required: false)

if r2_core.found()
  # Get radare2 plugin directory
  r2_found = run_command('which', 'r2', check: false).returncode() == 0
  if r2_found
    r2_plugdir = run_command('r2', '-H', 'R2_USER_PLUGINS', check: false).stdout().strip()
    r2_prefix = run_command('r2', '-H', 'R2_PREFIX', check: false).stdout().strip()
  else
    r2_plugdir = get_option('r2_plugdir')
    r2_prefix = get_option('r2_prefix')
  endif

  # Check if only core_hbc_one should be built
  r2_oneplug = get_option('r2_oneplug')

  if r2_oneplug
    # NOTE: arch_hbc, bin_hbc, and asm_hbc plugins are built into
    # core_hbc_one to avoid duplicate symbols and simplify the build process

    # core_hbc plugin with plugin registration enabled (r2one)
    shared_library(
      'core_hbc',
      'src/r2/core_hbc_one.c',
      link_with: libhbc,
      include_directories: include_dirs,
      dependencies: r2_core,
      override_options: ['werror=false'],
      install: true,
      install_dir: r2_plugdir,
    )

    message('Building only core_hbc_one plugin (r2_oneplug enabled)')
  else
    # NOTE: arch_hbc, bin_hbc, and asm_hbc plugins are now built into
    # core_hbc_one to avoid duplicate symbols and simplify the build process

    # core_hbc plugin with plugin registration enabled (r2one)
    shared_library(
      'core_hbc',
      'src/r2/core_hbc_one.c',
      link_with: libhbc,
      include_directories: include_dirs,
      dependencies: r2_core,
      override_options: ['werror=false'],
      install: true,
      install_dir: r2_plugdir,
    )

    message('Building core_hbc_one plugin (individual plugins disabled)')
  endif

  message('radare2 plugins enabled')
  message('Plugin directory: ' + r2_plugdir)
else
  message('radare2 not found, skipping plugin build')
endif

# Tests
if get_option('tests')
  subdir('tests')
endif

# Summary
message('r2hermes build summary:')
message('  Library: libhbc')
message('  CLI: libhbctool')
if r2_core.found()
  message('  radare2 plugins: core_hbc (includes arch, bin, asm)')
  message('  Plugin install path: ' + r2_plugdir)
else
  message('  radare2 plugins: disabled (radare2 not found)')
endif
