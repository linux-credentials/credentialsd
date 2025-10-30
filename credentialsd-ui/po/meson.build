i18n = import('i18n')

# This creates build targets: 'credentialsd-ui-pot', 'credentialsd-ui-update-po', etc.
i18n.gettext(gettext_package,
  args: ['--directory=' + meson.project_source_root() / 'credentialsd-ui',
         '--from-code=UTF-8',
         '--copyright-holder="The Credentials for Linux Project"',
         '--msgid-bugs-address="https://github.com/linux-credentials/credentialsd/issues"',
         '--add-comments=TRANSLATORS:'
           ],
)
