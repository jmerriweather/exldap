defmodule Exldap.SearchResult do
  require Record

  record = Record.extract(:eldap_search_result, from_lib: "eldap/include/eldap.hrl")
  keys   = Enum.map(record, &elem(&1, 0))
  vals   = Enum.map(keys, &{&1, [], nil})
  pairs  = Enum.zip(keys, vals)

  defstruct record
  @type t :: %__MODULE__{}

  @keys keys

  @doc """
  Converts a `Exldap.SearchResult` struct to a `:eldap_search_result` record.
  """
  def to_record(%Exldap.SearchResult{unquote_splicing(pairs)}) do
    {:eldap_search_result, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:eldap_search_result` record into a `Exldap.SearchResult`.

  The record is matched on its tag only, not its arity, so results from an
  `:eldap` version with more or fewer fields than the one this module was
  compiled against (for example the `controls` field added in OTP 24.3) are
  still converted. Extra trailing fields are ignored and missing fields keep
  their struct defaults.
  """
  def from_record(record) when is_tuple(record) and elem(record, 0) == :eldap_search_result do
    [:eldap_search_result | values] = Tuple.to_list(record)
    struct(__MODULE__, Enum.zip(@keys, values))
  end
end
