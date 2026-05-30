blueprint_compiler = find_program('blueprint-compiler', version: '>= 0.20.4')

blueprint_templates = custom_target(
  'blueprints',
  input: files('window.blp'),
  output: '.',
  command: [
    blueprint_compiler,
    'batch-compile',
    '@OUTPUT@',
    '@CURRENT_SOURCE_DIR@',
    '@INPUT@',
  ],
)