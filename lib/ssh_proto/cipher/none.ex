defmodule SSHProto.Cipher.None do
  @behaviour SSHProto.Cipher

  defmodule State do
    defstruct [
      packet_length: nil,
      tail: nil
    ]

    @type t :: %__MODULE__{
      packet_length: SSHProto.Util.uint32() | nil,
      tail: binary() | nil
    }
  end

  @impl true
  def decrypt(nil, data),
    do: decrypt(%State{}, data)

  def decrypt(state, data) when not is_nil(state.tail) do
    decrypt(%{state | tail: nil}, state.tail <> data)
  end

  def decrypt(state, data) when is_nil(state.packet_length) do
    case decrypt_packet_length(data) do
      :continue ->
	{:continue, %{state | tail: data}}
      {:ok, length} ->
	decrypt(%{state | packet_length: length}, data)
    end
  end

  def decrypt(state, data) do
    # Length including packet_length field
    total_length = state.packet_length + 4

    if byte_size(data) < total_length do
      {:continue, %{state | tail: data}}
    else
      <<packet::binary-size(total_length), rest::binary>> = data

      {:ok, packet, rest, %State{}}
    end
  end

  def decrypt_packet_length(data) do
    if byte_size(data) < 4 do
      :continue
    else
      <<length::integer-size(32), _rest::binary>> = data

      {:ok, length}
    end
  end
end
