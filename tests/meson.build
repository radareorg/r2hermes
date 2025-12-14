test_src = files(
  # Add test files here as needed
)

if test_src.length() > 0
  executable(
    'run_tests',
    test_src,
    link_with: libhbc,
    include_directories: include_dirs,
    install: false,
  )
endif
