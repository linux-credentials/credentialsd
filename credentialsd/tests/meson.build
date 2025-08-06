test_config = configuration_data()
test_config.set_quoted(
  'SERVICE_DIR',
  meson.project_build_root() / meson.current_build_dir(),
)
test_config.set(
  'DBUS_EXECUTABLE',
  meson.project_build_root() / backend_build_dir / 'target' / rust_target / backend_executable_name,
)
configure_file(
  input: 'config' / 'mod.rs.in',
  output: 'config.rs',
  configuration: test_config,
)

# Copy the config output to the source directory.
run_command(
  'cp',
  meson.project_build_root() / meson.current_build_dir() / 'config.rs',
  meson.project_source_root() / meson.current_source_dir() / 'config' / 'mod.rs',
  check: true,
)

configure_file(
  input: 'services' / 'xyz.iinuwa.credentialsd.Credentials.service.in',
  output: 'xyz.iinuwa.credentialsd.Credentials.service',
  configuration: test_config,
)

test(
  'dbus',
  cargo,
  env: [cargo_env],
  args: [
    'test',
    '--test', 'dbus',
    '--no-fail-fast', cargo_options,
    '--',
    '--nocapture',
  ],
  protocol: 'exitcode',
  verbose: true,
)