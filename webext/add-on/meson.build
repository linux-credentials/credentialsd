zip = find_program('zip')

addon_dir = datadir / 'credentialsd'

# Shared JavaScript files used by both Firefox and Chromium builds
shared_js = ['background.js', 'content-bridge.js', 'content-main.js']

# Firefox XPI
firefox_files = ['manifest.firefox.json'] + shared_js + ['icons' / 'logo.svg']
custom_target(
  'xpi',
  output: 'credentialsd-firefox-helper.xpi',
  input: firefox_files,
  command: [
    'pwd',
    '&&',
    'cd',
    '@CURRENT_SOURCE_DIR@',
    '&&',
    zip,
    '-r',
    '-FS', meson.project_build_root() / '@OUTPUT@',
    firefox_files,
    '--exclude', 'icons/LICENSE',
  ],
  install: true,
  install_dir: addon_dir,
)

# TODO: Add Chromium build target using manifest.chromium.json