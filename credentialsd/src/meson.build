if get_option('profile') == 'default'
  cargo_options += ['--release']
  rust_profile = 'release'
  message('Building in release mode')
else
  rust_profile = 'debug'
  message('Building in debug mode')
endif

cargo_env = ['CARGO_HOME=' + cargo_home]
message('@0@'.format(cargo_options))

custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: backend_executable_name,
  console: true,
  install: true,
  install_dir: bindir,
  command: [
    'env',
    cargo_env,
    cargo,
    'build',
    cargo_options,
    '&&',
    'cp',
    cargo_target_dir / rust_profile / backend_executable_name,
    '@OUTPUT@',
  ],
)

test(
  'credentialsd cargo-unit-tests',
  cargo,
  env: [cargo_env],
  args: [
    'test',
    '--bins',
    '--no-fail-fast', cargo_options,
    '--',
    '--nocapture',
  ],
  protocol: 'exitcode',
)