shared_library(
  'core_hbc',
  '../src/r2/core_hbc_one.c',
  link_with: libhbc,
  include_directories: ['../include', include_dirs],
  dependencies: r2_core,
  override_options: ['werror=false'],
  install: true,
  install_dir: r2_plugdir,
)
