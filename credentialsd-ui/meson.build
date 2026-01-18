i18n = import('i18n')
gnome = import('gnome')

gui_executable_name = 'credentialsd-ui'
gui_build_dir = meson.current_build_dir()
gui_source_dir = meson.current_source_dir()
base_id = 'xyz.iinuwa.credentialsd.CredentialsUi'

dependency('dbus-1', version: '>= 1.6')
dependency('glib-2.0', version: '>= 2.66')
dependency('gio-2.0', version: '>= 2.66')
dependency('gtk4', version: '>= 4.6.2')

glib_compile_resources = find_program('glib-compile-resources', required: true)
glib_compile_schemas = find_program('glib-compile-schemas', required: true)
# Usually provided by gettext package
msgfmt = find_program('msgfmt', required: false)
xmllint = find_program('xmllint', required: false)

desktop_file_validate = find_program('desktop-file-validate', required: false)
appstreamcli = find_program('appstreamcli', required: false)

cargo = find_program('cargo', required: true)

version = meson.project_version()

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
localedir = prefix / get_option('localedir')

datadir = prefix / get_option('datadir')
pkgdatadir = datadir / gui_executable_name
iconsdir = datadir / 'icons'

if get_option('profile') == 'development'
  profile = 'Devel'
  vcs_tag = run_command('git', 'rev-parse', '--short', 'HEAD', check: false).stdout().strip()
  if vcs_tag == ''
    version_suffix = '-devel'
  else
    version_suffix = '-@0@'.format(vcs_tag)
  endif
  application_id = '@0@.@1@'.format(base_id, profile)
else
  profile = ''
  version_suffix = ''
  application_id = base_id
endif

meson.add_dist_script(
  meson.project_source_root() / 'build-aux/dist-vendor.sh',
  meson.project_build_root() / 'meson-dist' / gui_executable_name
  + '-'
  + version,
  meson.project_source_root(),
)

if get_option('profile') == 'development'
  # Setup pre-commit hook for ensuring coding style is always consistent
  message('Setting up git pre-commit hook..')
  run_command('cp', '-f', 'hooks/pre-commit.hook', '.git/hooks/pre-commit', check: false)
endif

cargo_options = [
  '--manifest-path', meson.project_source_root() / gui_source_dir / 'Cargo.toml',
]
cargo_options += ['--target-dir', cargo_target_dir]
if get_option('cargo_offline') == true
  cargo_options += ['--offline']
endif

# Localization setup
podir = meson.project_source_root() / meson.current_source_dir() / 'po'
gettext_package = gui_executable_name

subdir('data')
subdir('po')
subdir('src')

gnome.post_install(
  gtk_update_icon_cache: true,
  glib_compile_schemas: true,
  update_desktop_database: true,
)