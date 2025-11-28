global_conf = configuration_data()
global_conf.set_quoted('APP_ID', application_id)
if (get_option('profile') == 'development')
  global_conf.set_quoted(
    'PKGDATADIR',
    meson.project_build_root() / gui_build_dir / 'data' / 'resources',
  )
else
  global_conf.set_quoted('PKGDATADIR', pkgdatadir)
endif
if (get_option('profile') == 'development')
  global_conf.set_quoted(
    'LOCALEDIR',
    meson.project_build_root() / gui_build_dir / 'po',
  )
else
  global_conf.set_quoted('LOCALEDIR', localedir)
endif
global_conf.set_quoted('PROFILE', profile)
global_conf.set_quoted('VERSION', version + version_suffix)
global_conf.set_quoted('GETTEXT_PACKAGE', gettext_package)
configure_file(input: 'config.rs.in', output: 'config.rs', configuration: global_conf)

# Copy the config.rs output to the source directory.
run_command(
  'cp',
  meson.project_build_root() / meson.current_build_dir() / 'config.rs',
  meson.project_source_root() / meson.current_source_dir() / 'config.rs',
  check: true,
)

if get_option('profile') == 'default'
  cargo_options += ['--release']
  rust_target = 'release'
  message('Building in release mode')
else
  rust_target = 'debug'
  message('Building in debug mode')
endif

cargo_env = ['CARGO_HOME=' + cargo_home]

custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: gui_executable_name,
  console: true,
  install: true,
  install_dir: bindir,
  depends: resources,
  command: [
    'env',
    cargo_env,
    cargo,
    'build',
    cargo_options,
    '&&',
    'cp',
    gui_build_dir / 'target' / rust_target / gui_executable_name,
    '@OUTPUT@',
  ],
)

test(
  'credentials-ui cargo-unit-tests',
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
