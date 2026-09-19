defmodule Exldap.Entry do
  require Record

  record = Record.extract(:eldap_entry, from_lib: "eldap/include/eldap.hrl")
  keys   = Enum.map(record, &elem(&1, 0))
  vals   = Enum.map(keys, &{&1, [], nil})
  pairs  = Enum.zip(keys, vals)

  defstruct record
  @type t :: %__MODULE__{}

  @keys keys

  @doc """
  Converts a `Exldap.Entry` struct to a `:eldap_entry` record.
  """
  def to_record(%Exldap.Entry{unquote_splicing(pairs)}) do
    {:eldap_entry, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:eldap_entry` record into a `Exldap.Entry`.

  The record is matched on its tag only, not its arity, so it tolerates
  `:eldap` versions that add trailing fields.
  """
  def from_record(record) when is_tuple(record) and elem(record, 0) == :eldap_entry do
    [:eldap_entry | values] = Tuple.to_list(record)
    struct(__MODULE__, Enum.zip(@keys, values))
  end
end
