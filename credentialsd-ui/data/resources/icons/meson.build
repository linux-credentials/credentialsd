install_data(
  '@0@.svg'.format(application_id),
  install_dir: iconsdir / 'hicolor' / 'scalable' / 'apps',
)

install_data(
  '@0@-symbolic.svg'.format(base_id),
  install_dir: iconsdir / 'hicolor' / 'symbolic' / 'apps',
  rename: '@0@-symbolic.svg'.format(application_id),
)

copy_icons = find_program('copy-icons.py')
icons = custom_target(
  command: [copy_icons, '@CURRENT_SOURCE_DIR@', '@OUTDIR@', '@INPUT@'],
  input: files(
    'scalable/emblems/passkey-logo.svg',
    'symbolic/status/check-round-outline-symbolic.svg',
  ),
  output: 'icons-copied',
)