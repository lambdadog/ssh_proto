defmodule SSHProto do
  @moduledoc """
  Documentation for `SSHProto`.
  """

  defmodule Config do
    defstruct []

    @typedoc """
    SSH Protocol config.
    """
    @type t :: %__MODULE__{}
  end

  defmodule State do
    defstruct [
      encode: %{},
      decode: %{
	cipher: SSHProto.Cipher.None,
	cipher_state: nil,

	mac: SSHProto.MAC.None,
	mac_state: %SSHProto.MAC.State{},
      }
    ]

    @typedoc """
    Struct to hold the protocol state. Should not be manipulated by caller.
    """
    @opaque t :: %__MODULE__{
      encode: %{},
      decode: %{
	cipher: module(),
	cipher_state: SSHProto.Cipher.state(),

	mac: module(),
	mac_state: SSHProto.MAC.State.t()
      }
    }
  end

  @doc """
  Initialize SSHProto State struct with given Config struct.
  """
  @spec init(Config.t()) :: {:ok, State.t()} | {:error, any()}
  def init(_config) do
    {:ok, %State{}}
  end

  @doc """
  Decodes an SSH message. Due to the nature of the SSH protocol all messages
  must be decoded in order.
  """
  @spec decode(State.t(), binary()) ::
  {:ok, tuple(), State.t()}
  | {:continue, State.t()}
  | {:error, any()}

  def decode(state, data) do
    %{
      cipher: cipher,
      cipher_state: cipher_state
    } = state.decode

    case cipher.decrypt(cipher_state, data) do
      {:continue, cipher_state} ->
	state = put_in(state, [:decode, :cipher_state], cipher_state)

	{:continue, state}
      {:error, e} ->
	{:error, e}

      {:ok, packet, rest, cipher_state} ->
	state = put_in(state, [:decode, :cipher_state], cipher_state)

	_ = {state, packet, rest}

	%{
	  mac: mac,
	  mac_state: mac_state
	} = state.decode

	case mac.validate(mac_state, packet, rest) do
	  :continue ->
	    {:continue, state}

	  {:error, e} ->
	    {:error, e}

	  {:ok, mac_state} ->
	    state = put_in(state, [:decode, :mac_state], mac_state)

	    # extract packet
	    # decode payload
	    # return payload (as tuple)

	    {:error, :unfinished}
	end
    end
  end

  @doc """
  Encodes an SSH message. Due to the nature of the SSH protocol all messages
  must be encoded in order.
  """
  @spec encode(State.t(), tuple()) ::
  {:ok, binary(), State.t()}
  | {:error, any()}

  def encode(_state, _msg) do
    # generate payload
    # generate unencrypted packet
    # generate mac
    # call into cipher to encypt packet
    # return packet <> mac
    {:error, :unimplemented}
  end

  @crlf "\u000d\u000a"

  @doc """
  Decode version message for SSH version exchange.

  ## Examples

      iex> SSHProto.decode_version("SSH-2.0-OpenSSH_9.6\\r\\n")
      {:ok, "OpenSSH_9.6"}

      iex> SSHProto.decode_version("nonsense")
      {:error, {:parse_error, "\\"nonsense\\" is not a valid version message"}}

  """
  @spec decode_version(binary()) :: {:ok, String.t()} | {:error, any()}
  def decode_version(msg) do
    case String.split(msg, ["-", @crlf, " "], parts: 4) do
      ["SSH", ssh_version, remote_version, _] ->
	if ssh_version in ["2.0", "1.99"] do
	  {:ok, remote_version}
	else
	  {:error, {:incompatible_remote_version, remote_version}}
	end
      _ ->
	{:error, {:parse_error, "\"#{msg}\" is not a valid version message"}}
    end
  end

  @doc """
  Encode version message for SSH version exchange. `version_string` can only
  contain printable US-ASCII characters, and CANNOT contain whitespace or
  the minus sign (-).

  ## Examples

      iex> SSHProto.encode_version("Stellar_0.1.0")
      {:ok, "SSH-2.0-Stellar_0.1.0\\r\\n"}

      iex> SSHProto.encode_version("Stellar-0.1.0")
      {:error, :illegal_version_string}

  """
  @spec encode_version(String.t()) :: {:ok, String.t()} | {:error, any()}
  def encode_version(version_string) do
    if SSHProto.Util.legal_version_string?(version_string) do
      {:ok, "SSH-2.0-" <> version_string <> @crlf}
    else
      {:error, :illegal_version_string}
    end
  end
end
