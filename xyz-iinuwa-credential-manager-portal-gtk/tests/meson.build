test_config = configuration_data()
test_config.set_quoted(
  'SERVICE_DIR',
  meson.project_build_root() / backend_executable_name / 'tests',
)
test_config.set(
  'DBUS_EXECUTABLE',
  meson.project_build_root() / backend_executable_name / 'src' / backend_executable_name,
)
configure_file(
  input: 'config' / 'mod.rs.in',
  output: 'config.rs',
  configuration: test_config,
)

# Copy the config output to the source directory.
run_command(
  'cp',
  meson.project_build_root() / backend_executable_name / 'tests' / 'config.rs',
  meson.project_source_root() / backend_executable_name / 'tests' / 'config' / 'mod.rs',
  check: true,
)

configure_file(
  input: 'services' / 'xyz.iinuwa.CredentialManagerUi.service.in',
  output: 'xyz.iinuwa.CredentialManagerUi.service',
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
