defmodule ExldapTest do
  use ExUnit.Case

  # The tests in this file rely on having correct LDAP details set in config/config.secure.exs
  # and on have a 'test123' user account with a 'samAccountName' attribute of 'test123' and a 'cn' attribute of 'test123'
  # the test123 account should also be a member of multiple groups and NOT be disabled

  test "connect should connect with correct details and timeout set" do    
    settings = Application.get_env :exldap, :settings
    server = settings |> Keyword.get(:server)
    port = settings |> Keyword.get(:port)
    ssl = settings |> Keyword.get(:ssl)
    user_dn = settings |> Keyword.get(:user_dn)
    password = settings |> Keyword.get(:password)

    {result, connection} = Exldap.connect(server, port, ssl, user_dn, password, 1000)

    assert result == :ok

    Exldap.close(connection)
  end

  test "connect should connect with correct details without the timeout set" do    
    settings = Application.get_env :exldap, :settings
    server = settings |> Keyword.get(:server)
    port = settings |> Keyword.get(:port)
    ssl = settings |> Keyword.get(:ssl)
    user_dn = settings |> Keyword.get(:user_dn)
    password = settings |> Keyword.get(:password)

    {result, connection} = Exldap.connect(server, port, ssl, user_dn, password)

    assert result == :ok

    Exldap.close(connection)
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
    server = settings |> Keyword.get(:server)
    port = settings |> Keyword.get(:port)
    ssl = settings |> Keyword.get(:ssl)

    {success, connection} = Exldap.open(server, port, ssl, 1000)

    assert success == :ok

    Exldap.close(connection)
  end

  test "open works without timeout set" do
    settings = Application.get_env :exldap, :settings
    server = settings |> Keyword.get(:server)
    port = settings |> Keyword.get(:port)
    ssl = settings |> Keyword.get(:ssl)

    {success, connection} = Exldap.open(server, port, ssl)

    assert success == :ok

    Exldap.close(connection)
  end

  test "open works with ssl false" do
    settings = Application.get_env :exldap, :settings
    test_settings = Application.get_env(:exldap, :test)
    
    server = settings |> Keyword.get(:server)
    port = test_settings |> Keyword.get(:non_ssl_port)

    {success, connection} = Exldap.open(server, port, false)

    assert success == :ok

    Exldap.close(connection)
  end

  test "close successfully closes the connection" do
    {:ok, connection} = Exldap.connect
    result = Exldap.close(connection)

    assert result == :ok

    Exldap.close(connection)
  end

  test "connect to LDAP and get test123 cn attribute" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")

    assert object_cn == "test123"

    Exldap.close(connection)
  end
  
  test "connect to LDAP and get test123 cn attribute using get_attribute!" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")

    assert object_cn == "test123"

    Exldap.close(connection)
  end
  
  test "connect to LDAP and get test123 cn attribute using get_attribute" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute(first_result, "cn")

    assert object_cn == {:ok, "test123"}

    Exldap.close(connection)
  end

  test "connect to LDAP and get test123 cn attribute using charlists" do
    {:ok, connection} = Exldap.connect

    {:ok, search_result} = Exldap.search_field(connection, 'cn', 'test123')
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, 'cn')

    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search initial substring with binary input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "samAccountName", {:initial, "test123"})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")

    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search initial substring with charlist input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base) |> to_charlist
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, 'samAccountName', {:initial, 'test123'})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, 'cn')
    
    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search any substring with binary input without specifing a base" do    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")

    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search any substring with charlist input without specifing a base" do    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, 'cn', 'test123')
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, 'cn')
    
    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search any substring with binary input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "cn", "test123")
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")

    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search any substring with charlist input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base) |> to_charlist
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, 'cn', 'test123')
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, 'cn')
    
    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search final substring with binary input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "cn", {:final, "test123"})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")

    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search final substring with charlist input" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base) |> to_charlist
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, 'cn', {:final, 'test123'})
    
    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, 'cn')
    
    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search with multiple results returns list" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "samAccountName", "test")
    
    assert is_list(search_result)
    assert Enum.count(search_result) > 1

    Exldap.close(connection)
  end

  test "search attributes with multiple results returns list" do
    settings = Application.get_env :exldap, :settings
    base = settings |> Keyword.get(:base)
    
    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_substring(connection, base, "cn", {:initial, 'test123'})
    {:ok, first_result} = search_result |> Enum.fetch(0)
    groups = Exldap.get_attribute!(first_result, "memberOf")
    
    assert is_list(groups)
    assert Enum.count(groups) > 1

    Exldap.close(connection)
  end

  test "search with an 'and' filter" do
    first_name_filter = Exldap.substrings("givenName", {:any,"Test"})
    last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
    and_filter = Exldap.with_and([first_name_filter, last_name_filter])

    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_with_filter(connection, and_filter)

    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")
    
    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search with an 'or' filter" do
    first_name_filter = Exldap.substrings("cn", {:initial,"test123"})
    last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
    and_filter = Exldap.with_or([first_name_filter, last_name_filter])

    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_with_filter(connection, and_filter)

    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")
    
    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search with a 'not' filter" do
    first_name_filter = Exldap.substrings("givenName", {:initial,"test"})
    last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
    
    not_first_name = Exldap.substrings("givenName", {:any,"test test"}) |> Exldap.negate

    and_filter = Exldap.with_and([first_name_filter, last_name_filter, not_first_name])

    {:ok, connection} = Exldap.connect
    {:ok, search_result} = Exldap.search_with_filter(connection, and_filter)

    {:ok, first_result} = search_result |> Enum.fetch(0)
    object_cn = Exldap.get_attribute!(first_result, "cn")
    
    assert object_cn == "test123"

    Exldap.close(connection)
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
    object_cn = Exldap.get_attribute!(first_result, "cn")
    
    assert object_cn == "test123"

    Exldap.close(connection)
  end

  test "search for test123 and convert the objectSid into a string" do
    binary_sid = <<0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x98, 0xA2, 0x2A, 0xBD, 0x72, 0xAA, 0x6F, 0xB0, 0xE9, 0x66, 0x28, 0x3F, 0x2C, 0x23, 0x00, 0x00>>

    sid_string = Exldap.sid_to_string(binary_sid)

    assert sid_string == "S-1-5-21-3173687960-2960108146-1059612393-9004"
  end

  test "convert sid string into binary sid" do
    string_sid = "S-1-5-21-3173687960-2960108146-1059612393-9004"
    desired_binary = <<0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x98, 0xA2, 0x2A, 0xBD, 0x72, 0xAA, 0x6F, 0xB0, 0xE9, 0x66, 0x28, 0x3F, 0x2C, 0x23, 0x00, 0x00>>

    binary_sid = Exldap.string_to_sid(string_sid)
    
    assert binary_sid == desired_binary
  end

  test "open LDAP connect and attempt authentication" do
    {:ok, connection} = Exldap.open

    result = Exldap.verify_credentials(connection, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD")

    assert result == {:error, :invalidCredentials}

    Exldap.close(connection)
  end  

  test "open LDAP connect and attempt authentication with blank password and invalid DN" do
    {:ok, connection} = Exldap.open

    result = Exldap.verify_credentials(connection, "CN=test123,OU=Accounts,DC=example,DC=com", "")

    assert result == {:error, :invalidCredentials}

    Exldap.close(connection)
  end

  test "open LDAP connect and attempt authentication with blank password and correct DN" do
    {:ok, connection} = Exldap.open
    
    user_dn = Application.get_env(:exldap, :settings) |> Keyword.get(:passwordchange_dn)

    result = Exldap.verify_credentials(connection, user_dn, "")

    assert result == {:error, :invalidCredentials}

    Exldap.close(connection)
  end

  test "open LDAP connect and attempt to change password as admin" do
    {:ok, connection} = Exldap.connect

    passwordchange_dn = Application.get_env(:exldap, :test) |> Keyword.get(:passwordchange_dn)
    passwordchange_password = Application.get_env(:exldap, :test) |> Keyword.get(:passwordchange_password)
    passwordchange_new = Application.get_env(:exldap, :test) |> Keyword.get(:passwordchange_new)

    result = Exldap.change_password(connection, passwordchange_dn, passwordchange_new)
    
    assert result == :ok

    result = Exldap.change_password(connection, passwordchange_dn, passwordchange_password)

    assert result == :ok

    Exldap.close(connection)
  end

  test "open LDAP connect and attempt change password as a user" do
    
    server = Application.get_env(:exldap, :settings) |> Keyword.get(:server)
    port = Application.get_env(:exldap, :settings) |> Keyword.get(:port)    
    ssl = Application.get_env(:exldap, :settings) |> Keyword.get(:ssl)

    passwordchange_dn = Application.get_env(:exldap, :test) |> Keyword.get(:passwordchange_dn)
    passwordchange_password = Application.get_env(:exldap, :test) |> Keyword.get(:passwordchange_password)
    passwordchange_new = Application.get_env(:exldap, :test) |> Keyword.get(:passwordchange_new)
      
    {:ok, connection} = Exldap.connect([server: server, port: port, ssl: ssl, user_dn: passwordchange_dn, password: passwordchange_password], 3000)

    result = Exldap.change_password(connection, passwordchange_dn, passwordchange_password, passwordchange_new)
    
    assert result == :ok
    
    {:ok, connection} = Exldap.connect([server: server, port: port, ssl: ssl, user_dn: passwordchange_dn, password: passwordchange_new], 3000)

    result = Exldap.change_password(connection, passwordchange_dn, passwordchange_new, passwordchange_password)

    assert result == :ok

    Exldap.close(connection)
  end
end
