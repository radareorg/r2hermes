# asm_hbc plugin (pseudo decompiler)
shared_library(
  'asm_hbc',
  '../src/r2/asm_hbc.c',
  include_directories: include_dirs,
  dependencies: r2_core,
  override_options: ['werror=false'],
  install: true,
  install_dir: r2_plugdir,
)