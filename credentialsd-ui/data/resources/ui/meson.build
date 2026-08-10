blueprint_compiler = find_program('blueprint-compiler', version: '>= 0.20.4')

blueprint_templates = custom_target(
  'blueprints',
  input: files('window.blp'),
  output: 'window.ui',
  command: [
    blueprint_compiler,
    'compile',
    '--minify',
    '--output', '@OUTPUT@',
    '@INPUT@',
  ],
)