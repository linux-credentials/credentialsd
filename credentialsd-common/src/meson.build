# Currently, we're not building this with meson and just letting cargo path dependencies for the other projects build this lib.
# Not efficient, since the UI and daemon projects will build it separately, but leaving it this way for now.

# if get_option('profile') == 'default'
#   cargo_options += ['--release']
#   rust_target = 'release'
#   message('Building in release mode')
# else
#   rust_target = 'debug'
#   message('Building in debug mode')
# endif
#
# cargo_env = ['CARGO_HOME=' + cargo_home]
#
# custom_target(
#   'cargo-build',
#   build_by_default: true,
#   build_always_stale: true,
#   output: common_lib_name,
#   console: true,
#   install: true,
#   install_dir: bindir,
#   command: [
#     'env',
#     cargo_env,
#     cargo,
#     'build',
#     cargo_options,
#     '&&',
#     'cp',
#     common_lib_name / 'src' / rust_target / common_lib_name,
#     '@OUTPUT@',
#   ],
# )