defmodule SSHProto.MAC.None do
  @behaviour SSHProto.MAC

  @impl true
  def validate(state, _packet, <<>>) do
    sequence_number = SSHProto.Util.increment_uint32(state.sequence_number)

    {:ok, %{state | sequence_number: sequence_number}}
  end

  def validate(_state, _packet, mac) do
    {:error, {:invalid_mac_length, byte_size(mac), mac}}
  end
end
