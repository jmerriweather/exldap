defmodule Exldap.Entry do
  require Record

  record = Record.extract(:eldap_entry, from_lib: "eldap/include/eldap.hrl")
  keys   = Enum.map(record, &elem(&1, 0))
  vals   = Enum.map(keys, &{&1, [], nil})
  pairs  = Enum.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `Eldap.Entry` struct to a `:eldap_entry` record.
  """
  def to_record(%Exldap.Entry{unquote_splicing(pairs)}) do
    {:eldap_entry, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:eldap_entry` record into a `Eldap.Entry`.
  """
  def from_record(eldap_entry)
  def from_record({:eldap_entry, unquote_splicing(vals)}) do
    %Exldap.Entry{unquote_splicing(pairs)}
  end
end
