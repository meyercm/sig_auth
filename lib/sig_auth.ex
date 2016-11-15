defmodule SigAuth do
  import ShorterMaps

  @spec load_key(binary) :: {:ok, binary}
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

  @nonce_header "x-sigauth-nonce"
  def nonce_header, do: @nonce_header

  def sign(method, path, nonce, body, username, private_key) do
    signature = binary_to_sign(method, path, nonce, body)
                |> :public_key.sign(:sha256, private_key)
                |> Base.encode64
    [{@nonce_header, "#{nonce}"},
     {"authorization", "SIGAUTH #{username}:#{signature}"}]
  end

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
