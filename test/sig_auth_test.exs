defmodule SigAuthTest do
  use ExUnit.Case

  test "sign / valid? works happy" do
    priv_key = SigAuth.load_key("./test/testing_id_rsa")
    headers = SigAuth.sign("GET", "/", 1, "", "bob", priv_key)
    assert "bob" == SigAuth.get_username(headers)

    pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
    signature = SigAuth.get_signature(headers)
    nonce = SigAuth.get_nonce(headers)

    assert SigAuth.valid?("GET", "/", nonce, "", signature, pub_key)
  end

  test "sign/valid? returns false if contents changed" do
    priv_key = SigAuth.load_key("./test/testing_id_rsa")
    headers = SigAuth.sign("GET", "/", 1, "", "bob", priv_key)

    pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
    signature = SigAuth.get_signature(headers)
    nonce = SigAuth.get_nonce(headers)

    refute SigAuth.valid?("POST", "/", nonce, "", signature, pub_key)
    refute SigAuth.valid?("GET", "/SOMETHING", nonce, "", signature, pub_key)
    refute SigAuth.valid?("GET", "/", "2", "", signature, pub_key)
    refute SigAuth.valid?("GET", "/", nonce, "body", signature, pub_key)
  end

end
