defmodule Exosphere.ATProto.Spaces.Blake3.Native do
  @moduledoc false
  # Raw NIF bindings for `native/exosphere_blake3`. Call
  # `Exosphere.ATProto.Spaces.Blake3` and `Exosphere.ATProto.Spaces.Lthash`
  # rather than this module: they pick the right scheduler and validate
  # arguments so a bad call is an Elixir error rather than a `:badarg` from
  # the NIF.

  # Release builds of this NIF are downloaded as precompiled, checksummed
  # artifacts from the GitHub release for this version (built by the
  # "Precompiled NIFs" workflow), so most users never need a Rust toolchain.
  # Compiling from `native/exosphere_blake3` is the fallback: set
  # EXOSPHERE_BUILD_BLAKE3=1 (required until the first release that carries
  # the artifacts, and whenever native/ has changed since the last release —
  # otherwise you compile against the released, stale binary).
  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :exosphere,
    crate: :exosphere_blake3,
    base_url: "https://github.com/tobbbles/exosphere/releases/download/v#{version}",
    version: version,
    # NIF API 2.16 (OTP 26+) covers every OTP this package supports, and newer
    # OTPs load 2.16 NIFs unchanged.
    nif_versions: ["2.16"],
    # :release mode is the point of the crate — a debug build of BLAKE3 is
    # roughly an order of magnitude slower, which would defeat the exercise.
    # (Applies to local source builds; precompiled artifacts are built in
    # release mode by the release workflow.)
    mode: :release,
    force_build: System.get_env("EXOSPHERE_BUILD_BLAKE3") in ["1", "true"]

  @spec hash_xof(binary(), pos_integer()) :: binary()
  def hash_xof(_input, _out_len), do: :erlang.nif_error(:nif_not_loaded)

  @spec hash_xof_dirty(binary(), pos_integer()) :: binary()
  def hash_xof_dirty(_input, _out_len), do: :erlang.nif_error(:nif_not_loaded)

  @spec lthash_fold(binary(), binary(), boolean()) :: binary()
  def lthash_fold(_state, _element, _add), do: :erlang.nif_error(:nif_not_loaded)

  @spec lthash_fold_many(binary(), [binary()], boolean()) :: binary()
  def lthash_fold_many(_state, _elements, _add), do: :erlang.nif_error(:nif_not_loaded)
end
