# Exldap

Playing with eldap from Elixir

## Installation

The package can be installed as:

  1. Add exldap to your list of dependencies in `mix.exs`:

        def deps do
          [{:exldap, git: "https://github.com/jmerriweather/exldap.git"}]
        end

  2. Ensure exldap is started before your application:

        def application do
          [applications: [:exldap]]
        end

  3. Add 'config\config.secret.exs' file with:

        use Mix.Config

        config :exldap, :settings,
          server: <server address>,
          base: "DC=example,DC=com",
          port: 636,
          ssl: true,
          user_dn: <user distinguished name>,
          password: <password>
