zip = find_program('zip')

addon_dir = datadir / 'credentialsd'

# Shared files used by both Firefox and Chromium builds
shared_addon_files = ['icons' / 'logo.svg', 'background.js', 'content-bridge.js', 'content-main.js']

# Firefox XPI
firefox_addon_files = ['manifest.firefox.json'] + shared_addon_files
custom_target(
  'xpi',
  output: 'credentialsd-firefox-helper.xpi',
  input: firefox_addon_files,
  command: [
    'cp', '-r', '@INPUT@', '@PRIVATE_DIR@',
    '&&',
    'cd',
    '@PRIVATE_DIR@',
    '&&',
    'mv', '@PLAINNAME0@', 'manifest.json',
    '&&',
    'mkdir', '-p', 'icons',
    '&&',
    'mv', '@PLAINNAME1@', 'icons/',
    '&&',
    zip,
    '-r',
    '-FS', meson.project_build_root() / '@OUTPUT@',
    '.',
  ],
  install: true,
  install_dir: addon_dir,
)

# Chromium extension (unsigned)
# TODO: Wrap this in a self-signed CRX in CI
chromium_addon_files = ['manifest.chromium.json'] + shared_addon_files
custom_target(
  'chromium-extension',
  output: 'credentialsd-chromium-helper.zip',
  input: chromium_addon_files,
  command: [
    'cp', '-r', '@INPUT@', '@PRIVATE_DIR@',
    '&&',
    'cd',
    '@PRIVATE_DIR@',
    '&&',
    'mv', '@PLAINNAME0@', 'manifest.json',
    '&&',
    'mkdir', '-p', 'icons',
    '&&',
    'mv', '@PLAINNAME1@', 'icons/',
    '&&',
    zip,
    '-r',
    '-FS', meson.project_build_root() / '@OUTPUT@',
    '.',
  ],
  install: true,
  install_dir: addon_dir,
)
