global_conf = configuration_data()
global_conf.set_quoted('APP_ID', application_id)
if (get_option('profile') == 'development')
  global_conf.set_quoted('PKGDATADIR', meson.project_build_root() / backend_executable_name / 'data' / 'resources')
else
  global_conf.set_quoted('PKGDATADIR', pkgdatadir)
endif
global_conf.set_quoted('PROFILE', profile)
global_conf.set_quoted('VERSION', version + version_suffix)
global_conf.set_quoted('GETTEXT_PACKAGE', gettext_package)
global_conf.set_quoted('LOCALEDIR', localedir)
config = configure_file(
  input: 'config.rs.in',
  output: 'config.rs',
  configuration: global_conf
)

# Copy the config.rs output to the source directory.
run_command(
  'cp',
  meson.project_build_root() / backend_executable_name / 'src' / 'config.rs',
  meson.project_source_root() / backend_executable_name / 'src' / 'config.rs',
  check: true
)

cargo_options = [ '--manifest-path', meson.project_source_root() / backend_executable_name / 'Cargo.toml' ]
cargo_options += [ '--target-dir', meson.project_build_root() / backend_executable_name / 'src' ]

if get_option('profile') == 'default'
  cargo_options += [ '--release' ]
  rust_target = 'release'
  message('Building in release mode')
else
  rust_target = 'debug'
  message('Building in debug mode')
endif

cargo_env = [ 'CARGO_HOME=' + meson.project_build_root() / 'cargo-home' ]

cargo_build = custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: backend_executable_name,
  console: true,
  install: true,
  install_dir: bindir,
  depends: resources,
  command: [
    'env',
    cargo_env,
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', backend_executable_name / 'src' / rust_target / backend_executable_name, '@OUTPUT@',
  ]
)

test(
  'cargo-unit-tests',
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
