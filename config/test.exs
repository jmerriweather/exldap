import Config

# Settings for the integration tests against the Samba AD container
# started with `docker compose up -d --wait` (see docker-compose.yml and
# test/ad/10-provision-test-users.sh). Override in config/config.secret.exs
# to run against a real directory.
config :exldap, :settings,
  server: "localhost",
  base: "DC=samdom,DC=example,DC=com",
  port: 636,
  ssl: true,
  # The container uses a self-signed certificate.
  sslopts: [verify: :verify_none],
  user_dn: "CN=Administrator,CN=Users,DC=samdom,DC=example,DC=com",
  password: "Passw0rd",
  search_timeout: 5000

config :exldap, :test,
  non_ssl_port: 389,
  passwordchange_dn: "CN=pwchange,OU=Accounts,DC=samdom,DC=example,DC=com",
  passwordchange_password: "Passw0rd",
  passwordchange_new: "N3wPassw0rd"
