dbus_service_dir = datadir / 'dbus-1' / 'services'

if daemon_feat.allowed()
  dbus_daemon_config = configuration_data()
  dbus_daemon_config.set('DAEMON_EXECUTABLE', bindir / backend_executable_name)

  configure_file(
    input: 'xyz.iinuwa.credentialsd.Credentials.service.in',
    install_dir: dbus_service_dir,
    output: 'xyz.iinuwa.credentialsd.Credentials.service',
    configuration: dbus_daemon_config,
  )
endif

if gui_feat.allowed()
  dbus_ui_config = configuration_data()
  dbus_ui_config.set(
    'UI_EXECUTABLE',
    bindir / gui_executable_name,
  )

  configure_file(
    input: 'xyz.iinuwa.credentialsd.UiControl.service.in',
    install_dir: dbus_service_dir,
    output: 'xyz.iinuwa.credentialsd.UiControl.service',
    configuration: dbus_ui_config,
  )
endif
