dependency('dbus-1', version: '>= 1.6')
dependency('glib-2.0', version: '>= 2.66')
dependency('gio-2.0', version: '>= 2.66')
dependency('gtk4', version: '>= 4.6.2')

glib_compile_resources = find_program('glib-compile-resources', required: true)

demo_blueprints = custom_target(
  'demo-blueprints',
  input: files('window.blp'),
  output: 'ui',
  command: [
    find_program('blueprint-compiler', required: false),
    'batch-compile',
    '@OUTPUT@',
    '@CURRENT_SOURCE_DIR@',
    '@INPUT@',
  ],
)

demo_resources = custom_target(
  'demo-resource',
  input: files('resources.gresource.xml'),
  depend_files: files('style.css'),
  depfile: 'gresource.deps',
  output: 'resources.gresource',
  command: [
    glib_compile_resources,
    '--target=@OUTPUT@',
    '--dependency-file=@DEPFILE@',
    '--sourcedir=@CURRENT_SOURCE_DIR@',
    '--sourcedir', demo_blueprints[0],
    '@INPUT@',
  ],
)

gui_sources = files(
  '../doc/xyz.iinuwa.credentialsd.Credentials.xml',
  'cbor.py',
  'gui.py',
  'main.py',
  'util.py',
  'webauthn.py',
)

custom_target(
  'demo-gui',
  input: [gui_sources],
  build_by_default: false,
  output: '.',
  depends: [demo_resources],
  command: ['cp', '@INPUT@', '@OUTPUT@'],
)
