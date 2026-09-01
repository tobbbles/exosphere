defmodule Exosphere.ATProto.Spaces.Blake3 do
  @moduledoc """
  BLAKE3 with extendable output (XOF).

  `hash/2` squeezes any number of bytes from a BLAKE3 hash, not just the usual
  32. It is a general-purpose primitive — use it for whatever you like — and it
  is here because `Exosphere.ATProto.Spaces.Lthash` needs it: every set-hash
  element expands to 2048 bytes of extended output.

      Exosphere.ATProto.Spaces.Blake3.hash("hello", 32)    # a plain digest
      Exosphere.ATProto.Spaces.Blake3.hash("hello", 2048)  # 2048 bytes of XOF

  Output is a stream, so a shorter request is a prefix of a longer one:
  `hash(x, 33)` is the first 33 bytes of `hash(x, 2048)`.

  ## Build requirement

  This is a NIF over the upstream [BLAKE3 Rust crate][crate], built from source
  by `native/exosphere_blake3`, so **compiling this library needs a Rust
  toolchain** ([rustup](https://rustup.rs/)).

  It is a NIF because no published Elixir binding offers extendable output: the
  `:blake3` Hex package exposes only the fixed 32-byte digest, and the 2048-byte
  expansion cannot be composed from 32-byte hashes. A pure-Elixir implementation
  is possible — this library shipped one — but at roughly 300µs per expansion it
  puts a large set-hash fold into the multi-second range, against low
  single-digit microseconds natively. Correctness is checked against the
  official BLAKE3 vectors and, differentially, against that pure-Elixir
  implementation, which is retained as a test oracle.

  Large inputs are routed to a dirty CPU scheduler automatically, so a call is
  safe at any size.

  [crate]: https://crates.io/crates/blake3
  """

  alias Exosphere.ATProto.Spaces.Blake3.Native

  # BLAKE3 runs at gigabytes per second, so a normal NIF stays well inside its
  # ~1ms budget for anything under a few hundred KiB. Past that the call goes
  # to a dirty CPU scheduler rather than stalling a normal one, which is what
  # makes hash/2 safe to call on input of any size.
  @dirty_threshold 256 * 1024

  @doc """
  Hash `input` and squeeze `out_len` bytes of extended output (XOF mode).

  `out_len` is unbounded; large calls are scheduled so they cannot stall a
  normal scheduler.

  ## Examples

      iex> Exosphere.ATProto.Spaces.Blake3.hash("", 32) |> Base.encode16(case: :lower)
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"

      iex> byte_size(Exosphere.ATProto.Spaces.Blake3.hash("hello", 2048))
      2048
  """
  @spec hash(binary(), pos_integer()) :: binary()
  def hash(input, out_len) when is_binary(input) and is_integer(out_len) and out_len > 0 do
    if byte_size(input) + out_len > @dirty_threshold do
      Native.hash_xof_dirty(input, out_len)
    else
      Native.hash_xof(input, out_len)
    end
  end
end
