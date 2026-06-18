defmodule Exosphere.ATProto.RecordKey do
  @moduledoc """
  Record Keys (rkeys).

  A record key identifies an individual record within a collection in a
  repository. See [the Record Key spec](https://atproto.com/specs/record-key).

  Syntax rules:

  - 1 to 512 characters.
  - Allowed characters: alphanumeric (`A-Za-z0-9`) plus `.`, `-`, `_`, `:`, `~`.
  - Case-sensitive.
  - The values `.` and `..` are explicitly disallowed.

  Note: the `tid` record-key *type* (the most common) has additional
  constraints validated by `Exosphere.ATProto.TID.valid?/1`; this module
  validates the general record-key syntax that all rkeys must satisfy.

  ## Examples

      iex> Exosphere.ATProto.RecordKey.valid?("3jzfcijpj2z2a")
      true

      iex> Exosphere.ATProto.RecordKey.valid?("self")
      true

      iex> Exosphere.ATProto.RecordKey.valid?("..")
      false
  """

  @rkey_regex ~r/^[A-Za-z0-9._:~-]{1,512}$/

  @doc """
  Validate a record key string.
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(rkey) when is_binary(rkey) do
    rkey not in [".", ".."] and Regex.match?(@rkey_regex, rkey)
  end

  def valid?(_), do: false
end
