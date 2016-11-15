defmodule SigAuth do

  @moduledoc """
  This module is primarily intended for client use, or for public key loading
  on the server.  While not strictly necessary, it is highly recommended to use
  `SigAuth.Plug` and a `CredentialServer` to streamline authentication within
  your server routing

  ## Example Use

  ### Client

  This client is using HTTPotion, but any client library that allows specifying
  custom headers (SigAuth provides headers as
  `["authorization", "<authorization-token-stuff>", ...]`) can be used.

  ```elixir
  priv_key = SigAuth.load_key("./test/testing_id_rsa")
  headers = SigAuth.sign("GET", "/api/users/27.json", 1, "", "bob", priv_key)
  # headers contains "authorization", and "x-sigauth-nonce" headers
  HTTPotion.get("www.myapp.com/api/users.27.json", [headers: headers])
  ```

  ### Server

  As previously mentioned, Server authentication should be conducted using the
  `SigAuth.Plug` module and a `CredentialServer`.  See the code for `SigAuth.Plug`
  if you have a requirement to validate signatures without the Plug.

  """
  import ShorterMaps

  @doc """
  This method loads both public and private SSH RSA keys into a variable for use
  with either client-signing, or loading credentials into a credential server.
  """
  @spec load_key(binary) :: {:ok, any}
  def load_key(filename) do
    file_contents = File.read!(filename)
    if file_contents =~ ~r/^-----BEGIN RSA PRIVATE KEY-----/ do
      [entry] = :public_key.pem_decode(file_contents)
      :public_key.pem_entry_decode(entry)
    else
      [{key,_}] = :public_key.ssh_decode(file_contents, :public_key)
      key
    end
  end

  @doc """
  This method actually signs a request, accepting each component thereof.
  """
  @spec sign(binary, binary, integer, binary, binary, any) :: [{binary, binary}]
  def sign(method, path, nonce, body, username, private_key) do
    signature = binary_to_sign(method, path, nonce, body)
                |> :public_key.sign(:sha256, private_key)
                |> Base.encode64
    [{@nonce_header, "#{nonce}"},
     {"authorization", "SIGAUTH #{username}:#{signature}"}]
  end

  @nonce_header "x-sigauth-nonce"
  def nonce_header, do: @nonce_header

  def get_username(headers) do
    extract_authorization(headers)
    |> Map.get(:username)
  end

  def get_nonce(headers) do
    %{@nonce_header => nonce} = Enum.into(headers, %{})
    nonce
  end

  def get_signature(headers) do
    extract_authorization(headers)
    |> Map.get(:signature)
  end

  def valid?(method, path, nonce, body, signature, public_key) do
    binary_to_sign(method, path, nonce, body)
    |> :public_key.verify(:sha256, signature, public_key)
  end

  @doc false
  def binary_to_sign(method, path, nonce, body) do
    "#{method}\n#{path}\n#{nonce}\n#{body}"
  end

  @doc false
  def extract_authorization(headers) do
    %{"authorization" => "SIGAUTH " <> auth} = Enum.into(headers, %{})
    [username, signature] = String.split(auth, ":")
    signature = Base.decode64!(signature)
    ~M{username signature}
  end
end
