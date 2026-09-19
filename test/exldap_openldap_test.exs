defmodule ExldapOpenldapTest do
  @moduledoc """
  RFC 3062 password modify tests against the OpenLDAP container
  (see docker-compose.yml and config/test.exs, key :openldap).
  """
  use ExUnit.Case

  defp settings, do: Application.get_env(:exldap, :openldap)

  defp connect_as(user_dn, password) do
    s = settings()
    Exldap.connect([server: s[:server], port: s[:port], ssl: s[:ssl], sslopts: s[:sslopts], user_dn: user_dn, password: password], 3000)
  end

  test "modify_password/3 as admin resets a user's password" do
    s = settings()
    {:ok, admin} = connect_as(s[:user_dn], s[:password])

    assert :ok == Exldap.modify_password(admin, s[:passwordchange_dn], s[:passwordchange_new])
    assert {:ok, user} = connect_as(s[:passwordchange_dn], s[:passwordchange_new])
    Exldap.close(user)

    assert :ok == Exldap.modify_password(admin, s[:passwordchange_dn], s[:passwordchange_password])
    Exldap.close(admin)
  end

  test "modify_password/4 as the user changes their own password" do
    s = settings()
    {:ok, user} = connect_as(s[:passwordchange_dn], s[:passwordchange_password])

    assert :ok == Exldap.modify_password(user, s[:passwordchange_dn], s[:passwordchange_password], s[:passwordchange_new])
    Exldap.close(user)

    {:ok, user} = connect_as(s[:passwordchange_dn], s[:passwordchange_new])
    assert :ok == Exldap.modify_password(user, s[:passwordchange_dn], s[:passwordchange_new], s[:passwordchange_password])
    Exldap.close(user)
  end

  test "modify_password/4 with the wrong old password is refused" do
    s = settings()
    {:ok, user} = connect_as(s[:passwordchange_dn], s[:passwordchange_password])

    assert {:error, {:response, :unwillingToPerform}} ==
             Exldap.modify_password(user, s[:passwordchange_dn], "not-the-password", s[:passwordchange_new])

    Exldap.close(user)
  end
end
