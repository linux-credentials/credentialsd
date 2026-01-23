# Currently, we're not building this with meson and just letting cargo path dependencies for the other projects build this lib.
# Not efficient, since the UI and daemon projects will build it separately, but leaving it this way for now.

common_lib_name = 'credentialsd-common'
cargo = find_program('cargo', required: true)

cargo_options = [
  '--manifest-path', meson.project_source_root() / meson.current_source_dir() / 'Cargo.toml',
]
cargo_options += ['--target-dir', cargo_target_dir]
if get_option('cargo_locked') == true
  cargo_options += '--locked'
endif
if get_option('cargo_offline') == true
  cargo_options += ['--offline']
endif

subdir('src')