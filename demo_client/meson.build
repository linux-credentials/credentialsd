dependency('dbus-1', version: '>= 1.6')
dependency('glib-2.0', version: '>= 2.66')
dependency('gio-2.0', version: '>= 2.66')
dependency('gtk4', version: '>= 4.6.2')

glib_compile_resources = find_program('glib-compile-resources', required: true)

demo_blueprints = custom_target(
  'demo-blueprints',
  input: files('window.blp'),
  output: '.',
  command: [
    find_program('blueprint-compiler'),
    'batch-compile',
    '--minify', '@OUTPUT@',
    '@CURRENT_SOURCE_DIR@',
    '@INPUT@',
  ],
)

# custom_target(
#   'demo-resource',
#   input: files('resources.gresource.xml'),
#   depend_files: files('style.css'),
#   depends: demo_blueprints,
#   output: '.',
#   command: [glib_compile_resources, '--sourcedir', '@INPUT@'],
# )
