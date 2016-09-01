defmodule ExldapTest do
  use ExUnit.Case

  # The tests in this file rely on having correct LDAP details set in config/config.secure.exs
  # and on have a 'test123' user account with a 'samAccountName' attribute of 'test123' and a 'cn' attribute of 'test123'
  # the test123 account should also be a member of multiple groups and NOT be disabled
  # test123 account also has a objectSid of S-1-5-21-3173687960-2960108146-1059612393-9004

  test "connect should connect with correct details and timeout set" do    
    settings = Application.get_env :exldap, :settings
    server = settings |> Dict.get(:server)
    port = settings |> Dict.get(:port)
    ssl = settings |> Dict.get(:ssl)
    user_dn = settings |> Dict.get(:user_dn)
    password = settings |> Dict.get(:password)

    {result, _} = Exldap.connect(server, port, ssl, user_dn, password, 1000)

    assert result == :ok
  end

  test "connect should connect with correct details without the timeout set" do    
    settings = Application.get_env :exldap, :settings
    server = settings |> Dict.get(:server)
    port = settings |> Dict.get(:port)
    ssl = settings |> Dict.get(:ssl)
    user_dn = settings |> Dict.get(:user_dn)
    password = settings |> Dict.get(:password)

    {result, _} = Exldap.connect(server, port, ssl, user_dn, password)

    assert result == :ok
  end

  test "connect should fail if server doesn't exist with timeout set" do
    result = Exldap.connect("SERVERADDRESS", 636, true, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD", 10)

    assert result == {:error, 'connect failed'}
  end

  test "connect should fail if server doesn't exist without timeout set" do
    result = Exldap.connect("SERVERADDRESS", 636, true, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD")

    assert result == {:error, 'connect failed'}
  end

  test "open works with timeout set" do
    settings = Application.get_env :exldap, :settings
    server = settings |> Dict.get(:server)
    port = settings |> Dict.get(:port)
    ssl = settings |> Dict.get(:ssl)

    {success, _} = Exldap.open(server, port, ssl, 1000)

    assert success == :ok
  end

  test "open works without timeout set" do
    settings = Application.get_env :exldap, :settings
    server = settings |> Dict.get(:server)
    port = settings |> Dict.get(:port)
    ssl = settings |> Dict.get(:ssl)

    {success, _} = Exldap.open(server, port, ssl)

    assert success == :ok
  end

  test "close successfully closes the connection" do
    {:ok, connection} = Exldap.connect
    result = Exldap.close(connection)

    assert result == :ok
  end

  test "connect to LDAP and get test123 cn attribute" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")

    assert object_cn == "test123"
  end

  test "connect to LDAP and get test123 cn attribute using charlists" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, 'cn', 'test123')
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, 'cn')

    assert object_cn == "test123"
  end

  test "search initial substring with binary input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "samAccountName", {:initial, "test123"})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")

    assert object_cn == "test123"
  end

  test "search initial substring with charlist input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base) |> to_charlist
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, 'samAccountName', {:initial, 'test123'})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, 'cn')
    
    assert object_cn == "test123"
  end

  test "search any substring with binary input without specifing a base" do    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")

    assert object_cn == "test123"
  end

  test "search any substring with charlist input without specifing a base" do    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, 'cn', 'test123')
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, 'cn')
    
    assert object_cn == "test123"
  end

  test "search any substring with binary input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")

    assert object_cn == "test123"
  end

  test "search any substring with charlist input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base) |> to_charlist
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, 'cn', 'test123')
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, 'cn')
    
    assert object_cn == "test123"
  end

  test "search final substring with binary input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "cn", {:final, "test123"})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")

    assert object_cn == "test123"
  end

  test "search final substring with charlist input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base) |> to_charlist
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, 'cn', {:final, 'test123'})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, 'cn')
    
    assert object_cn == "test123"
  end

  test "search with multiple results returns list" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "samAccountName", "test")
    
    assert is_list(search_result)
    assert Enum.count(search_result) > 1
  end

  test "search attributes with multiple results returns list" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "cn", {:initial, 'test123'})
    {:ok, first_result} = search_result |> Enum.fetch(0)
    groups = Exldap.search_attributes(first_result, "memberOf")
    
    assert is_list(groups)
    assert Enum.count(groups) > 1
  end

  test "search with an 'and' filter" do
    first_name_filter = Exldap.substrings("givenName", {:any,"Test"})
    last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
    and_filter = Exldap.with_and([first_name_filter, last_name_filter])

    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_with_filter(connection, and_filter)

    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")
    
    assert object_cn == "test123"
  end

  test "search with an 'or' filter" do
    first_name_filter = Exldap.substrings("cn", {:initial,"test123"})
    last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
    and_filter = Exldap.with_or([first_name_filter, last_name_filter])

    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_with_filter(connection, and_filter)

    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")
    
    assert object_cn == "test123"
  end

  test "search with a 'not' filter" do
    first_name_filter = Exldap.substrings("givenName", {:initial,"test"})
    last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
    
    not_first_name = Exldap.substrings("givenName", {:any,"test test"}) |> Exldap.negate

    and_filter = Exldap.with_and([first_name_filter, last_name_filter, not_first_name])

    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_with_filter(connection, and_filter)

    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")
    
    assert object_cn == "test123"
  end

  test "search with a approxMatch, equalityMatch, greaterOrEqual, lessOrEqual_filter and present filter" do
    cn_filter = Exldap.approxMatch("cn", "test123")
    last_name_filter = Exldap.equalityMatch("sn", "123")
    greaterOrEqual_filter = Exldap.greaterOrEqual("badPasswordTime", "10")
    lessOrEqual_filter = Exldap.lessOrEqual("badPwdCount", "10")
    exclude_disabled_accounts = Exldap.extensibleMatch("2", [{:type, "userAccountControl"}, {:matchingRule, "1.2.840.113556.1.4.803"}]) |> Exldap.negate
    
    objectClass_present = Exldap.present("objectClass")

    and_filter = Exldap.with_and([cn_filter, last_name_filter, greaterOrEqual_filter, lessOrEqual_filter, objectClass_present, exclude_disabled_accounts])

    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_with_filter(connection, and_filter)

    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.search_attributes(first_result, "cn")
    
    assert object_cn == "test123"
  end

  test "search for test123 and convert the objectSid into a string" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_sid = Exldap.search_attributes(first_result, "objectSid")

    sid_string = Exldap.sid_to_string(object_sid)

    assert sid_string == "S-1-5-21-3173687960-2960108146-1059612393-9004"
  end

  test "open LDAP connect and attempt authentication" do
    {:ok, connection} = Exldap.open

    result = Exldap.verify_credentials(connection, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD")

    assert result == {:error, :invalidCredentials}
  end
end
