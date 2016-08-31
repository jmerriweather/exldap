defmodule Exldap do

  @doc ~S"""
  Connects to a LDAP server using the settings defined in config.exs

  ## Example

      iex> Exldap.connect(timeout \\ :infinity)
      {:ok, connection}
      Or
      {:error, error_description}

  """
  def connect(timeout \\ :infinity) do
    settings = Application.get_env :exldap, :settings

    server = settings |> Dict.get(:server)
    port = settings |> Dict.get(:port)
    ssl = settings |> Dict.get(:ssl)
    user_dn = settings |> Dict.get(:user_dn)
    password = settings |> Dict.get(:password)

    connect(server, port, ssl, user_dn, password, timeout)
  end


  @doc ~S"""
  Connects to a LDAP server using the arguments passed into the function

  ## Example

      iex> Exldap.connect("SERVERADDRESS", 636, true, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD", timeout \\ :infinity)
      {:ok, connection}
      Or
      {:error, error_description}

  """
  def connect(server, port, ssl, user_dn, password, timeout \\ :infinity)
  def connect(server, port, ssl, user_dn, password, timeout) do

    case open(server, port, ssl, timeout) do
      {:ok, connection} ->
        case verify_credentials(connection, user_dn, password) do
          :ok -> {:ok, connection}
          {_, message} -> {:error, message}
        end
      error -> error
    end

  end

  @doc ~S"""
  Open a connection to the LDAP server using the settings defined in config.exs

  ## Example

      iex> Exldap.open(timeout \\ :infinity)
      {:ok, connection}
      Or
      {:error, error_description}

  """
  def open(timeout \\ :infinity) do
    settings = Application.get_env :exldap, :settings

    server = settings |> Dict.get(:server)
    port = settings |> Dict.get(:port)
    ssl = settings |> Dict.get(:ssl)

    open(server, port, ssl, timeout)
  end

  @doc ~S"""
  Open a connection to the LDAP server

  ## Example

      iex> Exldap.open("SERVERADDRESS", 636, true, timeout \\ :infinity)
      {:ok, connection}
      Or
      {:error, error_description}

  """
  def open(server, port, ssl, timeout \\ :infinity)

  def open(server, port, ssl, timeout) when is_atom(timeout) do
    :eldap.open([to_charlist(server)], [{:port, port}, {:ssl, ssl}])
  end

  def open(server, port, ssl, timeout) do
    :eldap.open([to_charlist(server)], [{:port, port}, {:ssl, ssl}, {:timeout, timeout}])
  end

  @doc ~S"""
  Shutdown a connection to the LDAP server

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> Exldap.close(connection)

  """
  def close(connection) do
    :eldap.close(connection)
  end

  @doc ~S"""
  Verify the credentials against a LDAP connection

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> Exldap.verify_credentials(connection, "CN=test123,OU=Accounts,DC=example,DC=com", "PASSWORD")
      :ok --> Successfully connected
      Or
      {:error, :invalidCredentials} --> Failed to connect

  """
  def verify_credentials(connection, user_dn, password) do
    :eldap.simple_bind(connection, to_charlist(user_dn), to_charlist(password))
  end

  @doc ~S"""
  Searches for a LDAP entry, the base dn is obtained from the config.exs

  ## Example

      iex> Exldap.search_field(connection, "cn", "useraccount")
      {:ok, search_results}

  """
  def search_field(connection, field, name) do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)
    search_field(connection, base, field, name)
  end


  @doc ~S"""
  Searches for a LDAP entry using the arguments passed into the function

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> Exldap.search_field(connection, "OU=Accounts,DC=example,DC=com", "cn", "useraccount")
      {:ok, search_results}

  """
  def search_field(connection, base, field, name) do
    settings = Application.get_env :exldap, :settings
    search_timeout = settings |> Dict.get(:search_timeout) || 0

    base_config = {:base, to_charlist(base)}
    scope = {:scope, :eldap.wholeSubtree()}
    filter = {:filter, :eldap.equalityMatch(to_charlist(field), to_charlist(name))}
    timeout = {:timeout, search_timeout}
    options = [base_config, scope, filter, timeout]

    search(connection, options)
  end
  
  @doc ~S"""
  Searches for a LDAP entry via a field using a substring, with the search base specified in config.secre.exs. 
  For example, if you want to find all entries that have a last name that starts with "smi", you could supply {:initial, "smi"} to the substring parameter.

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> search_results = Exldap.search_substring(connection, "sn", {:initial, "smi"})
      {:ok, search_results}

  """
  def search_substring(connection, field, substring) do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)

    search_substring(connection, base, field, substring)
  end
  
  @doc ~S"""
  Searches for a LDAP entry via a field using a substring. 
  For example, if you want to find all entries that have a last name that starts with "smi", you could supply {:initial, "smi"} to the substring parameter.

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> search_within = "OU=Accounts,DC=example,DC=com"
      iex> search_results = Exldap.search_substring(connection, search_within, "sn", {:initial, "smi"})
      {:ok, search_results}

  """
  def search_substring(connection, base, field, {atom, substring}) do
    #filter = :eldap.substrings(to_charlist(field), [{:any, to_charlist(substring)}])
    filter = substrings(field, {atom, substring})
    search_with_filter(connection, base, filter)
  end
  
  @doc ~S"""
  Searches for a LDAP entry via a field using a substring. If a string is passed to substring then the default action is {:any, substring}

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> search_within = "OU=Accounts,DC=example,DC=com"
      iex> search_results = Exldap.search_substring(connection, search_within, "sn", "middle")
      {:ok, search_results}

  """
  def search_substring(connection, base, field, substring) do
    search_substring(connection, base, field, {:any, substring})
  end  

  @doc ~S"""
  Creates a substring filter. Please refer to eldap:substrings

  ## Example

      iex> first_name_filter = Exldap.substrings("givenName", {:any,"Test"})
      iex> last_name_filter = Exldap.substrings("sn", [{:any,"123"}])

  """
  def substrings(field, substring) when is_list(substring) do
    list_as_charlist = Enum.map(substring, fn({atom, sub}) -> 
      {atom, to_charlist(sub)} 
    end)
    :eldap.substrings(to_charlist(field), list_as_charlist)
  end

  def substrings(field, {atom, substring}) do
    :eldap.substrings(to_charlist(field), [{atom, to_charlist(substring)}])
  end

  @doc ~S"""
  Creates a approxMatch filter. Please refer to eldap:approxMatch

  ## Example

      iex> first_name_filter = Exldap.approxMatch("givenName", "Test")

  """
  def approxMatch(field, value) do
    :eldap.approxMatch(to_charlist(field), to_charlist(value))
  end

  @doc ~S"""
  Creates a lessOrEqual filter. Please refer to eldap:lessOrEqual

  ## Example

      iex> first_name_filter = Exldap.lessOrEqual("lastLogon", "1000")

  """
  def lessOrEqual(field, value) do
    :eldap.lessOrEqual(to_charlist(field), to_charlist(value))
  end

  @doc ~S"""
  Creates a greaterOrEqual filter. Please refer to eldap:greaterOrEqual

  ## Example

      iex> first_name_filter = Exldap.greaterOrEqual("lastLogon", "1000")

  """
  def greaterOrEqual(field, value) do
    :eldap.greaterOrEqual(to_charlist(field), to_charlist(value))
  end

  @doc ~S"""
  Creates a equalityMatch filter. Please refer to eldap:equalityMatch

  ## Example

      iex> name_filter = Exldap.equalityMatch("cn", "John Smith")

  """
  def equalityMatch(field, value) do
    :eldap.equalityMatch(to_charlist(field), to_charlist(value))
  end

  @doc ~S"""
  Creates a present filter. Please refer to eldap:present

  ## Example

      iex> only_users_filter = Exldap.present("objectClass")

  """
  def present(type) do
    type 
      |> to_charlist 
      |> :eldap.present
  end

  @doc ~S"""
  Allows you to combine filters in a boolean 'and' expression. Please refer to eldap:and

  ## Example

      iex> first_name_filter = Exldap.substrings("givenName", {:any,"Test"})
      iex> last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
      iex> and_filter = Exldap.with_and([first_name_filter, last_name_filter])

  """
  def with_and(filters) do
    :eldap.and(filters)
  end

  @doc ~S"""
  Allows you to combine filters in a boolean 'or' expression. Please refer to eldap:or

  ## Example

      iex> first_name_filter = Exldap.substrings("givenName", {:any,"Test"})
      iex> last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
      iex> and_filter = Exldap.with_or([first_name_filter, last_name_filter])

  """
  def with_or(filters) do
    :eldap.or(filters)
  end

  @doc ~S"""
  Allows you to negate a filter. Please refer to eldap:not
  ## Example

      iex> first_name_filter = Exldap.substrings("givenName", {:any,"Test"})
      iex> last_name_filter = Exldap.substrings("sn", [{:any,"123"}])
      iex> not_last_name = Exldap.negate(last_name_filter)
      iex> and_filter = Exldap.with_or([first_name_filter, not_last_name])

  """
  def negate(filter) do
    :eldap.not(filter)
  end
  
  @doc ~S"""
  Search LDAP with a raw filter function, the base to search within is obtained from config.secret.exs. 
  Look at eldap:search for more information

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> first_name_filter = Exldap.substrings("givenName", [{:any, "test"}])
      iex> last_name_filter = Exldap.substrings("sn", [{:any, "123"}])
      iex> and_filter = Exldap.with_and([first_name_filter, last_name_filter])
      iex> search_results = Exldap.search_with_filter(connection, and_filter)
      {:ok, search_results}

  """
  def search_with_filter(connection, filter) do
    settings = Application.get_env :exldap, :settings
    base = settings |> Dict.get(:base)

    search_with_filter(connection, base, filter)
  end

  @doc ~S"""
  Search LDAP with a raw filter function. Look at eldap:search for more information
  
  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> search_within = "OU=Accounts,DC=example,DC=com"
      iex> filter = Exldap.substrings('cn', [{:any,'userac'}])
      iex> search_results = Exldap.search_substring(connection, search_within, filter)
      {:ok, search_results}

  """
  def search_with_filter(connection, base, filter) do
    settings = Application.get_env :exldap, :settings
    search_timeout = settings |> Dict.get(:search_timeout) || 0

    base_config = {:base, to_charlist(base)}
    scope = {:scope, :eldap.wholeSubtree()}
    filter = {:filter, filter}
    timeout = {:timeout, search_timeout}
    options = [base_config, scope, filter, timeout]

    search(connection, options)
  end

  @doc ~S"""
  Searches for a LDAP entry using the supplier connection and options list.
  Options list should be in the following format: [base, scope, filter, timeout]. Please refer to eldap:search

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> base_config = {:base, 'OU=Accounts,DC=example,DC=com'}
      iex> scope = {:scope, :eldap.wholeSubtree()}
      iex> filter = {:filter, Exldap.substrings('cn', [{:any,'userac'}])}
      iex> timeout = {:timeout, 1000}
      iex> Exldap.search(connection, [base_config, scope, filter, timeout])
      {:ok, search_results}

  """
  def search(connection, options) do
    case :eldap.search(connection, options) do
      {:ok, result} ->
        result = Exldap.SearchResult.from_record(result)
        {:ok, result.entries |> Enum.map(fn(x) -> Exldap.Entry.from_record(x) end)}
      {_, message} -> 
        {:error, message}
    end
  end

  @doc ~S"""
  Searches for a LDAP entry and extracts an attribute based on the specified key, if the attribute does not exist returns nil

  ## Example

      iex> {:ok, connection} = Exldap.connect
      iex> {:ok, search_results} = Exldap.search_field(connection, "OU=Accounts,DC=example,DC=com", "cn", "useraccount")
      iex> {:ok, first_result} = search_result |> Enum.fetch(0)
      iex> Exldap.search_attributes(first_result, "displayName")
      "Test User"

  """
  def search_attributes(%Exldap.Entry{} = entry, key) do
    list_key = key |> to_charlist
    if List.keymember?(entry.attributes, list_key, 0) do
      {_, value} = List.keyfind(entry.attributes, list_key, 0)
      results = Enum.map(value, fn(x) ->
        :erlang.list_to_binary(x)
      end)
      if Enum.count(results) == 1 do
        List.first(results)
      else
        results
      end
    else
      nil
    end
  end

end
