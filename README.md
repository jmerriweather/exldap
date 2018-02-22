# Exldap

A module for working with LDAP from Elixir

## Installation

The package can be installed as:

  1. Add exldap to your list of dependencies in `mix.exs`:
```elixir
        def deps do
          [{:exldap, "~> 0.4"}]
        end
```
  2. Ensure exldap is started before your application:
```elixir
        def application do
          [applications: [:exldap]]
        end
```
  3. Optionally add 'config\config.secret.exs' file with:
```elixir
        use Mix.Config

        config :exldap, :settings,
          server: <server address>,
          base: "DC=example,DC=com",
          port: 636,
          ssl: true,
          user_dn: <user distinguished name>,
          password: <password>,
          search_timeout: 1000 # optionally set a search timeout in milliseconds, default is infinity
```
### Usage with configuration set in config.exs

```elixir
# the default_timeout is infinity

{:ok, connection} = Exldap.connect(TIMEOUT \\ default_timeout) # optionally set the maximum time in milliseconds that each server request may take

{:ok, search_results} = Exldap.search_field(connection, "cn", "test123")

{:ok, first_result} = search_results |> Enum.fetch(0)

result = Exldap.search_attributes(first_result, "displayName")


```

### Usage without configuration

```elixir
# the default_timeout is infinity

{:ok, connection} = Exldap.connect("SERVERADDRESS", 636, true, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD", TIMEOUT \\ default_timeout)

{:ok, search_results} = Exldap.search_field(connection, "OU=Accounts,DC=example,DC=com", "cn", "useraccount")

{:ok, first_result} = search_results |> Enum.fetch(0)

result = Exldap.search_attributes(first_result, "displayName")

```

### Verify credentials with configuration set in config.exs

```elixir
# the default_timeout is infinity

{:ok, connection} = Exldap.open(TIMEOUT \\ default_timeout) # optionally set the maximum time in milliseconds that each server request may take

case Exldap.verify_credentials(connection, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD") do
  :ok -> IO.puts "Successfully connected"
  _ -> IO.puts "Failed to connect"
end

```

### Verify credentials without configuration

```elixir

# the default_timeout is infinity

{:ok, connection} = Exldap.open("SERVERADDRESS", 636, true, TIMEOUT \\ default_timeout)

case Exldap.verify_credentials(connection, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD") do
  :ok -> IO.puts "Successfully connected"
  _ -> IO.puts "Failed to connect"
end

```

### Use SSL, validating certificates, from configuration

```elixir 
        use Mix.Config

        config :exldap, :settings,
          server: <server address>,
          base: "DC=example,DC=com",
          port: 636,
          ssl: true,
          sslopts: [cacertfile: 'path/to/ca.pem', verify: verify_peer]
          user_dn: <user distinguished name>,
          password: <password>,
          search_timeout: 1000
```

### Use SSL, validating certificates, from configuration

```elixir 
        sslopts=[cacertfile: 'path/to/ca.pem', verify: verify_peer]
        {:ok, connection} = Exldap.connect("SERVERADDRESS", 636, true, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD", timeout, sslopts)
        ...

```
