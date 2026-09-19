import Config

# Optional local settings (gitignored). Create config/config.secret.exs with:
#
#     import Config
#
#     config :exldap, :settings,
#       server: "ldap.example.com",
#       base: "DC=example,DC=com",
#       port: 636,
#       ssl: true,
#       user_dn: "CN=user,OU=Accounts,DC=example,DC=com",
#       password: "secret",
#       search_timeout: 1000
#
if config_env() == :test do
  import_config "test.exs"
end

# Loaded last so it overrides the defaults above.
if File.exists?(Path.join(__DIR__, "config.secret.exs")) do
  import_config "config.secret.exs"
end
