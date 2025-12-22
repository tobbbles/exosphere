defmodule Exosphere.Firehose.Consumer do
  @moduledoc """
  Public-facing firehose consumer built on top of `Exosphere.ATProto.Firehose.Consumer`.
  """

  @doc """
  Start the firehose consumer.

  See `Exosphere.ATProto.Firehose.Consumer.start_link/1` for options.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  defdelegate start_link(opts), to: Exosphere.ATProto.Firehose.Consumer

  @doc """
  Child spec for supervision trees.
  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  defdelegate child_spec(opts), to: Exosphere.ATProto.Firehose.Consumer
end
