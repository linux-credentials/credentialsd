fs = import('fs')
zip = find_program('zip')

addon_dir = datadir / 'credentialsd'
xpi_files = ['manifest.json', 'background.js', 'content.js', 'icons' / 'logo.svg']
custom_target(
  'xpi',
  output: 'credentialsd-firefox-helper.xpi',
  input: xpi_files,
  command: [
    'pwd',
    '&&',
    'cd',
    '@CURRENT_SOURCE_DIR@',
    '&&',
    zip,
    '-r',
    '-FS', meson.project_build_root() / '@OUTPUT@',
    xpi_files,
    '--exclude', 'icons/LICENSE',
  ],
  install: true,
  install_dir: addon_dir,
)
