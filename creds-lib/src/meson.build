cargo_options = [
  '--manifest-path', meson.project_source_root() / meson.current_source_dir() / '..' / 'Cargo.toml',
]
cargo_options += ['--target-dir', meson.project_build_root() / meson.current_build_dir()]

if get_option('profile') == 'default'
  cargo_options += ['--release']
  rust_target = 'release'
  message('Building in release mode')
else
  rust_target = 'debug'
  message('Building in debug mode')
endif

cargo_env = ['CARGO_HOME=' + meson.project_build_root() / 'cargo-home']

custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: common_lib_name,
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
    common_lib_name / 'src' / rust_target / common_lib_name,
    '@OUTPUT@',
  ],
)
