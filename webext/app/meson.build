addon_app_executable_name = 'credentialsd-firefox-helper'
addon_app_config = configuration_data()
addon_app_config.set('SHIM_SCRIPT', bindir / addon_app_executable_name)

addon_app_config.set('APP_ID', 'org.mozilla.firefox')
native_messaging_manifest_dir = libdir / 'mozilla' / 'native-messaging-hosts'

configure_file(
  input: 'credential_manager_shim.json.in',
  install_dir: native_messaging_manifest_dir,
  output: 'xyz.iinuwa.credentialsd_helper.json',
  configuration: addon_app_config,
)

configured_file = configure_file(
  input: 'credential_manager_shim.py',
  install_dir: bindir,
  output: '__main__.py',
  configuration: addon_app_config,
)

custom_target(
  'webext-app-zipapp',
  build_by_default: true,
  input: [
    configured_file,
    './__init__.py',
    './credentialsd_manager.py',
    './xdg_portal_utils.py',
    './xdg_portal_v1.py',
    './xdg_portal_v2.py',
  ],
  output: addon_app_executable_name,
  command: [
    './build.py',
    '@CURRENT_SOURCE_DIR@',
    '@PRIVATE_DIR@',
    '@OUTPUT@',
    '@INPUT@',
  ],
  install: true,
  install_dir: bindir,
)