defmodule Exosphere.ATProto.Spaces.Blake3.Native do
  @moduledoc false
  # Raw NIF bindings for `native/exosphere_blake3`. Call
  # `Exosphere.ATProto.Spaces.Blake3` and `Exosphere.ATProto.Spaces.Lthash`
  # rather than this module: they pick the right scheduler and validate
  # arguments so a bad call is an Elixir error rather than a `:badarg` from
  # the NIF.

  # :release mode is the point of the crate — a debug build of BLAKE3 is
  # roughly an order of magnitude slower, which would defeat the exercise.
  use Rustler, otp_app: :exosphere, crate: :exosphere_blake3, mode: :release

  @spec hash_xof(binary(), pos_integer()) :: binary()
  def hash_xof(_input, _out_len), do: :erlang.nif_error(:nif_not_loaded)

  @spec hash_xof_dirty(binary(), pos_integer()) :: binary()
  def hash_xof_dirty(_input, _out_len), do: :erlang.nif_error(:nif_not_loaded)

  @spec lthash_fold(binary(), binary(), boolean()) :: binary()
  def lthash_fold(_state, _element, _add), do: :erlang.nif_error(:nif_not_loaded)

  @spec lthash_fold_many(binary(), [binary()], boolean()) :: binary()
  def lthash_fold_many(_state, _elements, _add), do: :erlang.nif_error(:nif_not_loaded)
end
