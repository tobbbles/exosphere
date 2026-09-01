defmodule Exosphere.ATProto.HTTPTest do
  @moduledoc """
  Socket hygiene: error paths must close their connection, and the request
  options a caller sets must survive the trip to it.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.HTTP

  doctest Exosphere.ATProto.HTTP

  test "take_request_opts forwards what a caller may set and nothing else" do
    opts = [
      timeout: 1_500,
      follow_redirects: false,
      http: __MODULE__,
      dpop_key: %{},
      headers: [{"authorization", "Bearer caller"}],
      json: %{"caller" => true}
    ]

    forwarded = HTTP.take_request_opts(opts)

    assert forwarded[:timeout] == 1_500
    assert forwarded[:follow_redirects] == false

    # A transport builds its own auth headers and body; a caller must not be
    # able to displace them through the same keyword list.
    refute Keyword.has_key?(forwarded, :headers)
    refute Keyword.has_key?(forwarded, :json)
    refute Keyword.has_key?(forwarded, :http)
    refute Keyword.has_key?(forwarded, :dpop_key)
  end

  test "take_request_opts leaves an unset timeout unset, so the default stands" do
    assert HTTP.take_request_opts(http: __MODULE__) == []
  end

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
