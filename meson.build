project(
  'credentialsd',
  'rust',
  version: '0.2.0',
  meson_version: '>= 1.5.0',
  license: 'LGPL-3.0-only',
)

version = meson.project_version()

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
datadir = prefix / get_option('datadir')
libdir = prefix / get_option('libdir')
localedir = prefix / get_option('localedir')

cargo_home = get_option('cargo_home')
if cargo_home == ''
  cargo_home = meson.project_build_root() / 'cargo-home'
endif

cargo_target_dir = meson.project_build_root() / 'target'

meson.add_dist_script(
  'build-aux/dist-vendor.sh',
  meson.project_build_root() / 'meson-dist' / meson.project_name()
  + '-'
  + version,
  meson.project_source_root(),
)
# Features
demo_client_feat = get_option('feature_demo_client')
gui_feat = get_option('feature_gui')
webext_feat = get_option('feature_web_extension')

# Dependencies
dbus_dep = dependency('dbus-1', version: '>= 1.6', required: true)

# Programs
cargo = find_program('cargo', required: true)

if gui_feat.allowed() or demo_client_feat.allowed()
  glib_compile_resources = find_program('glib-compile-resources', required: true)
endif

if gui_feat.allowed() or demo_client_feat.allowed()
  blueprint_compiler = find_program('blueprint-compiler', version: '>= 0.20.4', required: true)
endif

# Libs and executables
subdir('credentialsd-common')
subdir('credentialsd')
if gui_feat.allowed()
  subdir('credentialsd-ui')
endif

# Data files
subdir('doc')
subdir('dbus')
if gui_feat.allowed()
  subdir('portal')
endif
subdir('systemd')
if webext_feat.allowed()
  subdir('webext')
endif

if demo_client_feat.allowed()
  subdir('demo_client')
endif
