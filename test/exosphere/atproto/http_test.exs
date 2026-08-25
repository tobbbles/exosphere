defmodule Exosphere.ATProto.HTTPTest do
  @moduledoc """
  Socket hygiene: error paths must close their connection.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.HTTP

  test "closes the connection when the response times out" do
    parent = self()

    # A server that accepts and reads the request, then never answers: the
    # client must time out, and the socket it opened must be closed (the
    # server sees EOF) rather than left open.
    {:ok, listen} = :gen_tcp.listen(0, [:inet, :binary, {:active, false}])
    {:ok, port} = :inet.port(listen)

    {:ok, _server} =
      Task.start_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listen, 5_000)
        {:ok, _request} = :gen_tcp.recv(sock, 0, 2_000)

        case :gen_tcp.recv(sock, 0, 5_000) do
          {:error, :closed} -> send(parent, :client_closed)
          {:ok, _more} -> send(parent, :unexpected_data)
          {:error, :timeout} -> send(parent, :client_socket_left_open)
        end

        :gen_tcp.close(sock)
      end)

    assert {:error, :timeout} =
             HTTP.get("http://127.0.0.1:#{port}/xrpc/never-answers", timeout: 100)

    assert_receive :client_closed, 3_000
    :gen_tcp.close(listen)
  end
end
