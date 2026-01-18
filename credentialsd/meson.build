backend_executable_name = 'credentialsd'
backend_build_dir = meson.current_build_dir()
base_id = 'xyz.iinuwa.credentialsd.Credentialsd'

dependency('dbus-1', version: '>= 1.6')
dependency('glib-2.0', version: '>= 2.66')
dependency('gio-2.0', version: '>= 2.66')
dependency('gtk4', version: '>= 4.6.2')
dependency('ssl', 'openssl', version: '>= 3.0')
dependency('udev', version: '>= 249')

cargo = find_program('cargo', required: true)

version = meson.project_version()

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
  meson.project_build_root() / 'meson-dist' / backend_executable_name
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
  '--manifest-path', meson.project_source_root() / meson.current_source_dir() / 'Cargo.toml',
]
cargo_options += [
  '--target-dir', cargo_target_dir,
]
if get_option('cargo_offline') == true
  cargo_options += ['--offline']
endif

subdir('src')
subdir('tests')