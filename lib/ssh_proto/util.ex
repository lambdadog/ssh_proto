defmodule SSHProto.Util do
  require Logger
  @doc """
  Checks if version string is legal. Version string can only contain printable
  US-ASCII characters and cannot ' ' or '-'.

  ## Examples

      iex> SSHProto.Util.legal_version_string?("Stellar_0.1.0")
      true

      iex> SSHProto.Util.legal_version_string?("Stellar-0.1.0")
      false

  """
  @spec legal_version_string?(String.t()) :: boolean()
  def legal_version_string?(version_string) do
    version_string
    |> :binary.bin_to_list
    |> Enum.all?(fn c -> c in 33..44 or c in 46..126 end)
  end
end
