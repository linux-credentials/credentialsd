project(
  'xyz-iinuwa-credential-manager-portal-gtk',
  'rust',
  version: '0.1.0',
  meson_version: '>= 1.5.0',
  license: 'LGPL-3.0-only',
)

version = meson.project_version()

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
localedir = prefix / get_option('localedir')

meson.add_dist_script(
  'build-aux/dist-vendor.sh',
  meson.project_build_root() / 'meson-dist' / meson.project_name()
  + '-'
  + version,
  meson.project_source_root(),
)

subdir('creds-lib')
subdir('credsd')
subdir('creds-ui')
