dbus_config = configuration_data()
dbus_service_dir = datadir / 'dbus-1' / 'services'
dbus_config.set('DAEMON_EXECUTABLE', bindir / backend_executable_name)
dbus_config.set(
  'UI_EXECUTABLE',
  bindir / gui_executable_name,
)
configure_file(
  input: 'xyz.iinuwa.credentialsd.Credentials.service.in',
  install_dir: dbus_service_dir,
  output: 'xyz.iinuwa.credentialsd.Credentials.service',
  configuration: dbus_config,
)
configure_file(
  input: 'xyz.iinuwa.credentialsd.FlowControl.service.in',
  install_dir: dbus_service_dir,
  output: 'xyz.iinuwa.credentialsd.FlowControl.service',
  configuration: dbus_config,
)
configure_file(
  input: 'xyz.iinuwa.credentialsd.UiControl.service.in',
  install_dir: dbus_service_dir,
  output: 'xyz.iinuwa.credentialsd.UiControl.service',
  configuration: dbus_config,
)