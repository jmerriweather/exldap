defmodule ExldapTest do
  use ExUnit.Case
  doctest Exldap

  test "connect to LDAP and get test123 cn attribute" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, "cn", "test123")

    {:ok, first_result} = search_result |> Enum.fetch(0)

    object_sid = first_result.attributes['cn']

    assert object_sid == ['test123']
  end

  test "open LDAP connect and attempt authentication" do
    {:ok, connection} = Exldap.open

    result = Exldap.verify_credentials(connection, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD")

    assert result == {:error, :invalidCredentials}
  end
end
