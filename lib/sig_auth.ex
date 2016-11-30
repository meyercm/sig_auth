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

  @doc false
  @nonce_header "x-sigauth-nonce"
  def nonce_header, do: @nonce_header

  @doc """
  This method loads both public and private SSH RSA keys into a variable for use
  with either client-signing, or loading credentials into a credential server.

  ## Examples:

      iex> priv = SigAuth.load_key("test/testing_id_rsa")
      {:RSAPrivateKey, :"two-prime", 1925825628552485095461711380...}

      iex> pub = SigAuth.load_key("test/testing_id_rsa.pub")
      {:RSAPublicKey, 1925825628552485...}
  """
  @spec load_key(String.t) :: {:ok, any}
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
  This method actually signs a request, accepting each component thereof.  The
  returned headers should be included when sending the request. The Authorization
  header produced contains the base 64 characters of the signature.

  ## Examples:

      iex> priv = SigAuth.load_key("test/testing_id_rsa")
      ...> nonce = System.system_time(:microseconds)
      ...> headers = SigAuth.sign("GET", "/api/v1/people", nonce, "", "Chris", priv)
      [{"x-sigauth-nonce", "1480535381422"},{"authorization", "SIGAUTH Chris:XlP49MtvM+dkE23...}]
  """
  @spec sign(String.t, String.t, integer, binary, String.t, any) :: [{String.t, String.t}]
  def sign(method, path, nonce, body, username, private_key) do
    signature = binary_to_sign(method, path, nonce, body)
                |> :public_key.sign(:sha256, private_key)
                |> Base.encode64
    [{@nonce_header, "#{nonce}"},
     {"authorization", "SIGAUTH #{username}:#{signature}"}]
  end

  @doc """
  Reports the validity of a signature.  Intended for use by `SigAuth.Plug`, it
  may nevertheless be used by server code that cannot use the Plug.
  """
  @spec valid?(String.t, String.t, integer, binary, binary, any) :: true|false
  def valid?(method, path, nonce, body, signature, public_key) do
    binary_to_sign(method, path, nonce, body)
    |> :public_key.verify(:sha256, signature, public_key)
  end
  #TODO: add another version of this method to accept Base-64 encoded signatures


  @doc """
  Server utility for extracting a username from request headers.
  """
  @spec get_username([{String.t, String.t}]) :: String.t
  def get_username(headers) do
    extract_authorization(headers)
    |> Map.get(:username)
  end

  @doc """
  Utility for extracting a nonce from request headers.
  """
  @spec get_nonce([{String.t, String.t}]) :: integer
  def get_nonce(headers) do
    case Enum.into(headers, %{}) do
      %{@nonce_header => nonce} ->
        String.to_integer(nonce)
      _ -> nil
    end
  end

  @doc """
  Utility for extracting a signature from request headers.
  """
  @spec get_signature([{String.t, String.t}]) :: binary
  def get_signature(headers) do
    extract_authorization(headers)
    |> Map.get(:signature)
  end


  @doc false
  def binary_to_sign(method, path, nonce, body) do
    "#{method}\n#{path}\n#{nonce}\n#{body}"
  end

  @doc false
  def extract_authorization(headers) do
    case Enum.into(headers, %{}) do
      %{"authorization" => "SIGAUTH " <> auth} ->
        [username, signature] = String.split(auth, ":")
        signature = Base.decode64!(signature)
        ~M{username signature}
      _ -> %{}
    end
  end
end
