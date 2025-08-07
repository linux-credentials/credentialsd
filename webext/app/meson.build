addon_app_executable_name = 'credentialsd-firefox-helper'
addon_app_config = configuration_data()
addon_app_config.set('SHIM_SCRIPT', bindir / addon_app_executable_name)
addon_app_config.set(
  'DBUS_DOC_FILE',
  datadir / 'credentialsd' / 'xyz.iinuwa.credentialsd.Credentials.xml',
)

native_messaging_manifest_dir = libdir / 'mozilla' / 'native-messaging-hosts'

configure_file(
  input: 'credential_manager_shim.json.in',
  install_dir: native_messaging_manifest_dir,
  output: 'xyz.iinuwa.credentialsd_helper.json',
  configuration: addon_app_config,
)

configure_file(
  input: 'credential_manager_shim.py',
  install_dir: bindir,
  output: addon_app_executable_name,
  configuration: addon_app_config,
)