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

custom_target(
  'demo-resource',
  input: files('resources.gresource.xml'),
  depend_files: files('style.css'),
  depends: demo_blueprints,
  depfile: 'gresource.deps',
  output: 'resources.gresource',
  command: [glib_compile_resources, '--target=@OUTPUT@', '--dependency-file=@DEPFILE@', '--sourcedir=@CURRENT_SOURCE_DIR@', '--sourcedir', demo_blueprints[0], '@INPUT@'],
)

fs = import('fs')
gui_script = fs.copyfile('gui.py')
fs.copyfile('cbor.py')
fs.copyfile('main.py')
fs.copyfile('util.py')
fs.copyfile('webauthn.py')

fs.copyfile('../doc/xyz.iinuwa.credentialsd.Credentials.xml')
