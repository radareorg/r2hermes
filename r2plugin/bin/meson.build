# bin_hbc plugin
shared_library(
  'bin_hbc',
  '../src/r2/bin_hbc.c',
  link_with: libhbc,
  include_directories: include_dirs,
  dependencies: r2_core,
  override_options: ['werror=false'],
  install: true,
  install_dir: r2_plugdir,
)