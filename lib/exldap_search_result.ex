defmodule Exldap.SearchResult do
  require Record

  record = Record.extract(:eldap_search_result, from_lib: "eldap/include/eldap.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `Eldap.SearchResult` struct to a `:eldap_search_result` record.
  """
  def to_record(%Exldap.SearchResult{unquote_splicing(pairs)}) do
    {:eldap_search_result, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:eldap_search_result` record into a `Eldap.SearchResult`.
  """
  def from_record(eldap_search_result)
  def from_record({:eldap_search_result, unquote_splicing(vals)}) do
    %Exldap.SearchResult{unquote_splicing(pairs)}
  end
end
