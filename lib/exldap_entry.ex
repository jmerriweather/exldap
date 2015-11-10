defmodule Exldap.Entry do
  require Record

  record = Record.extract(:eldap_entry, from_lib: "eldap/include/eldap.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

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
