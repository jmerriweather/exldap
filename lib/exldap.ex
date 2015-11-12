defmodule Exldap do

  def open_connection do
    settings = Application.get_env :exldap, :settings

    server = settings |> Dict.get(:server)
    port = settings |> Dict.get(:port)
    ssl = settings |> Dict.get(:ssl)
    user_dn = settings |> Dict.get(:user_dn)
    password = settings |> Dict.get(:password)

    connect(server, port, ssl, user_dn, password)
  end


  def connect(server, port, ssl, user_dn, password) when is_binary(server) do
    connect :erlang.binary_to_list(server), port, ssl, user_dn, password
  end

  def connect(server, port, ssl, user_dn, password) do
    {:ok, connection} = :eldap.open([server], [{:port, port},{:ssl, ssl}])

    bind_connection(connection, user_dn, password)

    {:ok, connection}
  end

  defp bind_connection(connection, dn, password) when is_binary(dn) and is_binary(password) do
    bind_connection connection, :erlang.binary_to_list(dn), :erlang.binary_to_list(password)
  end


  defp bind_connection(connection, dn, password) do
    :eldap.simple_bind(connection, dn, password)
  end

  def search_field(connection, field, name) when is_list(name) do
    search_field connection, field, :erlang.list_to_binary name
  end


  def search_field(connection, field, name) do
    settings = Application.get_env :exldap, :settings
    base_config = settings |> Dict.get(:base)

    filter = {:filter, :eldap.equalityMatch(field, name)}
    base = {:base, base_config}
    scope = {:scope, :eldap.wholeSubtree()}
    search = [base, scope, filter]

    {:ok, result} = :eldap.search(connection, search)
    result = Exldap.SearchResult.from_record(result)


    results = result.entries |> Enum.map(fn(x) -> Exldap.Entry.from_record(x) end)

    {:ok, first} = Enum.fetch(results, 0)

    first.attributes |> Enum.into(Map.new)
  end
end
