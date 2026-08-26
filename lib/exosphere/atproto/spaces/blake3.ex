defmodule Exosphere.ATProto.Spaces.Blake3 do
  @moduledoc """
  Pure-Elixir BLAKE3, providing the extended (XOF) output mode that
  `Exosphere.ATProto.Spaces.Lthash` needs to expand set-hash elements.

  ## Why pure Elixir (the BLAKE3 decision)

  Exosphere keeps a zero-new-NIF property: BLAKE3 is used only to expand
  LtHash elements — 2048 bytes per record, folded once per sync checkpoint or
  full-repo verification, never per firehose frame. A pure-Elixir
  implementation expands an element in the tens of microseconds (see the bench
  in `test/exosphere/atproto/spaces/blake3_test.exs`), which keeps the sync
  path comfortably interactive while adding no mandatory dependency. If a
  future hot path needs native BLAKE3, a NIF can slot in behind this module's
  `hash/2` interface without touching callers.

  Implemented after the BLAKE3 [reference implementation]; unkeyed mode only.

  [reference implementation]: https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
  """

  import Bitwise

  @iv {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
  }

  # permuted[i] = m[MSG_PERMUTATION[i]]
  @msg_permutation {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

  @chunk_start 1
  @chunk_end 2
  @parent 4
  @root 8

  @block_bytes 64
  @chunk_bytes 1024

  @mask 0xFFFFFFFF

  @doc """
  Hash `input` and squeeze `out_len` bytes of extended output (XOF mode).

  ## Examples

      iex> Exosphere.ATProto.Spaces.Blake3.hash("", 32) |> Base.encode16(case: :lower)
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
  """
  @spec hash(binary(), pos_integer()) :: binary()
  def hash(input, out_len) when is_binary(input) and is_integer(out_len) and out_len > 0 do
    {icv, block_words, _counter, block_len, flags} = root_output(input)
    root_flags = flags ||| @root

    blocks = div(out_len + @block_bytes - 1, @block_bytes)

    0..(blocks - 1)
    |> Enum.map(fn counter ->
      icv
      |> compress(block_words, counter, block_len, root_flags)
      |> words_to_binary()
    end)
    |> IO.iodata_to_binary()
    |> binary_part(0, out_len)
  end

  # An "output" is {input_chaining_value, block_words, counter, block_len,
  # flags}: the final compression of a chunk or parent node. The chaining value
  # reuses the output's own counter (the chunk index; 0 for parents), while the
  # root XOF blocks are counter = output block index with the ROOT flag.

  defp root_output(input) do
    len = byte_size(input)

    # Leaves are the 1024-byte chunks that contain bytes; an empty leaf exists
    # only for empty input. A whole number of chunks makes the last full chunk
    # the final (partial-style) leaf rather than adding an empty one.
    {n_full, tail, tail_counter} =
      case div(len, @chunk_bytes) do
        0 ->
          {0, input, 0}

        n when rem(len, @chunk_bytes) == 0 ->
          {n - 1, binary_part(input, (n - 1) * @chunk_bytes, @chunk_bytes), n - 1}

        n ->
          {n, binary_part(input, n * @chunk_bytes, rem(len, @chunk_bytes)), n}
      end

    # `total` is the cumulative chunk count including the one just pushed, so
    # trailing zero bits decide how far each cv merges up the tree.
    stack =
      0..(n_full - 1)//1
      |> Enum.reduce([], fn i, stack -> push_cv(chunk_cv(input, i), stack, i + 1) end)

    # Fold the stack from the top (the subtree nearest the tail) outwards.
    Enum.reduce(stack, chunk_output(tail, tail_counter), fn left_cv, output ->
      right_cv = output_cv(output)
      {iv(), parent_words(left_cv, right_cv), 0, @block_bytes, @parent}
    end)
  end

  # Merge chaining values up the tree while the chunk count is even, per the
  # reference push/mask algorithm.
  defp push_cv(cv, [left | stack], total) when rem(total, 2) == 0,
    do: push_cv(parent_cv(left, cv), stack, div(total, 2))

  defp push_cv(cv, stack, _total), do: [cv | stack]

  defp chunk_cv(input, i) do
    chunk = binary_part(input, i * @chunk_bytes, @chunk_bytes)
    {cv, words, counter, len, flags} = chunk_output(chunk, i)
    cv |> compress(words, counter, len, flags) |> first8()
  end

  # The final block of a chunk (possibly partial, possibly the only one) as an
  # output; the CHUNK_END flag lands on it. `counter` is the chunk's index,
  # used for the compression of every complete block before it.
  defp chunk_output(bytes, counter) do
    {cv, words, len, flags} =
      bytes
      |> blockize()
      |> walk_blocks(iv(), counter, true)

    {cv, words, counter, len, flags ||| @chunk_end}
  end

  defp walk_blocks([last], cv, _counter, first?) do
    {cv, block_words(last), byte_size(last), start_flag(first?)}
  end

  defp walk_blocks([block | rest], cv, counter, first?) do
    next_cv =
      cv
      |> compress(block_words(block), counter, byte_size(block), start_flag(first?))
      |> first8()

    walk_blocks(rest, next_cv, counter, false)
  end

  # A chunk always has at least one block, even when empty.
  defp blockize(<<>>), do: [<<>>]

  defp blockize(bytes) when byte_size(bytes) <= @block_bytes, do: [bytes]

  defp blockize(bytes) do
    <<block::binary-size(@block_bytes), rest::binary>> = bytes
    [block | blockize(rest)]
  end

  defp start_flag(true), do: @chunk_start
  defp start_flag(false), do: 0

  defp output_cv({icv, words, counter, len, flags}),
    do: icv |> compress(words, counter, len, flags) |> first8()

  defp parent_cv(left, right),
    do: iv() |> compress(parent_words(left, right), 0, @block_bytes, @parent) |> first8()

  defp parent_words(left, right),
    do: List.to_tuple(Tuple.to_list(left) ++ Tuple.to_list(right))

  defp iv(), do: @iv

  # The compression function. Words are unbound integers masked after every
  # arithmetic step; v12/v13 carry the 64-bit block counter, v14 the block
  # length, v15 the flags.
  defp compress(cv, m, counter, block_len, flags) do
    v = {
      elem(cv, 0), elem(cv, 1), elem(cv, 2), elem(cv, 3),
      elem(cv, 4), elem(cv, 5), elem(cv, 6), elem(cv, 7),
      elem(@iv, 0), elem(@iv, 1), elem(@iv, 2), elem(@iv, 3),
      counter &&& @mask, (counter >>> 32) &&& @mask,
      block_len &&& @mask, flags &&& @mask
    }

    v
    |> round(m)
    |> round(permute(m))
    |> round(permute(permute(m)))
    |> round(permute(permute(permute(m))))
    |> round(permute(permute(permute(permute(m)))))
    |> round(permute(permute(permute(permute(permute(m))))))
    |> round(permute(permute(permute(permute(permute(permute(m)))))))
    |> finalize_state(cv)
  end

  defp finalize_state(v, cv) do
    {
      bxor(elem(v, 0), elem(v, 8)),
      bxor(elem(v, 1), elem(v, 9)),
      bxor(elem(v, 2), elem(v, 10)),
      bxor(elem(v, 3), elem(v, 11)),
      bxor(elem(v, 4), elem(v, 12)),
      bxor(elem(v, 5), elem(v, 13)),
      bxor(elem(v, 6), elem(v, 14)),
      bxor(elem(v, 7), elem(v, 15)),
      bxor(elem(v, 8), elem(cv, 0)),
      bxor(elem(v, 9), elem(cv, 1)),
      bxor(elem(v, 10), elem(cv, 2)),
      bxor(elem(v, 11), elem(cv, 3)),
      bxor(elem(v, 12), elem(cv, 4)),
      bxor(elem(v, 13), elem(cv, 5)),
      bxor(elem(v, 14), elem(cv, 6)),
      bxor(elem(v, 15), elem(cv, 7))
    }
  end

  defp round(v, m) do
    v
    |> g(0, 4, 8, 12, elem(m, 0), elem(m, 1))
    |> g(1, 5, 9, 13, elem(m, 2), elem(m, 3))
    |> g(2, 6, 10, 14, elem(m, 4), elem(m, 5))
    |> g(3, 7, 11, 15, elem(m, 6), elem(m, 7))
    |> g(0, 5, 10, 15, elem(m, 8), elem(m, 9))
    |> g(1, 6, 11, 12, elem(m, 10), elem(m, 11))
    |> g(2, 7, 8, 13, elem(m, 12), elem(m, 13))
    |> g(3, 4, 9, 14, elem(m, 14), elem(m, 15))
  end

  defp g(v, a, b, c, d, mx, my) do
    va = elem(v, a)
    vb = elem(v, b)
    vc = elem(v, c)
    vd = elem(v, d)

    va = (va + vb + mx) &&& @mask
    vd = rotr32(bxor(vd, va), 16)
    vc = (vc + vd) &&& @mask
    vb = rotr32(bxor(vb, vc), 12)
    va = (va + vb + my) &&& @mask
    vd = rotr32(bxor(vd, va), 8)
    vc = (vc + vd) &&& @mask
    vb = rotr32(bxor(vb, vc), 7)

    v |> put_elem(a, va) |> put_elem(b, vb) |> put_elem(c, vc) |> put_elem(d, vd)
  end

  defp rotr32(x, n), do: ((x >>> n) ||| bsl_masked(x, 32 - n)) &&& @mask

  defp bsl_masked(x, n), do: (x <<< n) &&& @mask

  defp permute(m),
    do: List.to_tuple(for i <- 0..15, do: elem(m, elem(@msg_permutation, i)))

  # A block of up to 64 bytes, zero-padded, as 16 little-endian u32 words.
  defp block_words(bytes) do
    padded =
      case @block_bytes - byte_size(bytes) do
        0 -> bytes
        pad -> bytes <> :binary.copy(<<0>>, pad)
      end

    List.to_tuple(for <<w::little-32 <- padded>>, do: w)
  end

  defp words_to_binary(words) do
    for i <- 0..15, into: <<>>, do: <<elem(words, i)::little-32>>
  end

  defp first8(words) do
    {
      elem(words, 0), elem(words, 1), elem(words, 2), elem(words, 3),
      elem(words, 4), elem(words, 5), elem(words, 6), elem(words, 7)
    }
  end
end
