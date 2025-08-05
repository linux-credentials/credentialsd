# Currently, we're not building this with meson and just letting cargo path dependencies for the other projects build this lib.
# Not efficient, since the UI and daemon projects will build it separately, but leaving it this way for now.

# common_lib_name = 'xyzii-credman-portal-gtk'
# base_id = 'xyz.iinuwa.CredentialManagerUi'
#
# cargo = find_program('cargo', required: true)
#
# version = meson.project_version()
#
# if get_option('profile') == 'development'
#   profile = 'Devel'
#   vcs_tag = run_command('git', 'rev-parse', '--short', 'HEAD', check: false).stdout().strip()
#   if vcs_tag == ''
#     version_suffix = '-devel'
#   else
#     version_suffix = '-@0@'.format(vcs_tag)
#   endif
#   application_id = '@0@.@1@'.format(base_id, profile)
# else
#   profile = ''
#   version_suffix = ''
#   application_id = base_id
# endif
#
# meson.add_dist_script(
#   meson.project_source_root() / 'build-aux/dist-vendor.sh',
#   meson.project_build_root() / 'meson-dist' / common_lib_name + '-' + version,
#   meson.project_source_root(),
# )
#
# cargo_options = [
#   '--manifest-path', meson.project_source_root() / meson.current_source_dir() / 'Cargo.toml',
# ]
# cargo_options += [
#   '--target-dir', meson.project_build_root() / meson.current_build_dir() / 'target',
# ]
#
# subdir('src')
