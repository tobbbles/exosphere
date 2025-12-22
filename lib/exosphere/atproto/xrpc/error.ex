defmodule Exosphere.ATProto.XRPC.Error do
  @moduledoc """
  XRPC error handling.

  XRPC errors follow a standard format with:
  - `error` - A short error code string
  - `message` - A human-readable description
  """

  @enforce_keys [:status, :error]
  defstruct [:status, :error, :message]

  @type t :: %__MODULE__{
          status: pos_integer(),
          error: String.t(),
          message: String.t() | nil
        }

  @doc """
  Create an Error from an HTTP response.
  """
  @spec from_response(pos_integer(), map() | binary()) :: t()
  def from_response(status, %{"error" => error} = body) do
    %__MODULE__{
      status: status,
      error: error,
      message: Map.get(body, "message")
    }
  end

  def from_response(status, body) when is_binary(body) do
    %__MODULE__{
      status: status,
      error: "UnknownError",
      message: body
    }
  end

  def from_response(status, _body) do
    %__MODULE__{
      status: status,
      error: status_to_error(status),
      message: nil
    }
  end

  defp status_to_error(400), do: "InvalidRequest"
  defp status_to_error(401), do: "AuthenticationRequired"
  defp status_to_error(403), do: "Forbidden"
  defp status_to_error(404), do: "NotFound"
  defp status_to_error(429), do: "RateLimitExceeded"
  defp status_to_error(500), do: "InternalServerError"
  defp status_to_error(502), do: "BadGateway"
  defp status_to_error(503), do: "ServiceUnavailable"
  defp status_to_error(_), do: "UnknownError"

  defimpl String.Chars do
    def to_string(%Exosphere.ATProto.XRPC.Error{error: error, message: nil}) do
      error
    end

    def to_string(%Exosphere.ATProto.XRPC.Error{error: error, message: message}) do
      "#{error}: #{message}"
    end
  end
end
