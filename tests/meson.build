test_src = files(
  'test_debug_info.c',
)

if test_src.length() > 0
  run_tests = executable(
    'run_tests',
    test_src,
    link_with: libhbc,
    include_directories: include_dirs,
    install: false,
  )
  test('debug-info', run_tests, args: [meson.project_source_root()])
endif
