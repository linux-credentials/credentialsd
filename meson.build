project(
  'xyz-iinuwa-credential-manager-portal-gtk',
  'rust',
  version: '0.1.0',
  meson_version: '>= 1.5.0',
  # license: 'MIT',
)

version = meson.project_version()

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
localedir = prefix / get_option('localedir')

meson.add_dist_script(
  'build-aux/dist-vendor.sh',
  meson.project_build_root() / 'meson-dist' / meson.project_name() + '-' + version,
  meson.project_source_root()
)

subdir('xyz-iinuwa-credential-manager-portal-gtk')
