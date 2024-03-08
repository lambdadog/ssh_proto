defmodule SSHProto.Packet do
  def payload(packet) do
    try do
      <<packet_length::integer-size(32), rest::binary>> = packet
      <<pad_length::integer, rest::binary>> = rest

      payload_length = packet_length - pad_length - 1
      <<payload::binary-size(payload_length), _::binary>> = rest

      {:ok, payload}
    rescue
      e in RuntimeError -> {:error, e}
    end
  end
end
