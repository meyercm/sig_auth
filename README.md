# SigAuth

An HTTP API client authentication scheme based on RSA signatures.

In an HTTPS environment, the server's identity is trusted; proving the identity of the client can be accomplished in many ways; This scheme is inspired by the AWS authentication scheme, with a few modifications for simplicity's sake.

To prove identity, the client holds the private key of an RSA keypair, and creates a digital signature of the request as it is submitted.  The server can then validate the signature using the public key of the client claiming to submit the request.

This library makes no assumptions about your HTTP client or server, except that they allow you to specify and read the headers, body, method and path of a request.

[AWS](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
[Plug authentication framework](http://luk3thomas.com/authentiation-in-elixir-plug-20160722.html)
[Erlang :public_key cheatsheet](https://gist.github.com/zucaritask/3864572)

## Use

### Authorization Header Construction (client-side)

```elixir
iex> private_key = SigAuth.load_key_from_file("~/.ssh/id_rsa")
...> username = "myUserName"
...> method = "GET"
...> path = "/api/v1/people.json"
...> body = ""
...> epoch = System.system_time(:seconds)
...> SigAuth.sign(method, path, epoch, body, username, private_key)
[{"x-epoch", "1477530330"}, {"authorization", "SIGAUTH myUserName gY/n9ahh9+JfR..."}]
```

### Request Validation (server-side)

```elixir
# within the context of a Plug request handler, hence the existing variable `conn`
iex> %Conn{req_headers: headers, method: method, request_path: path} = conn
...> %{"authorization" => auth, "x-epoch" => epoch} = Enum.into(headers, %{})
...> ["SIGAUTH", username, signature] = String.split(auth, " ")
...> public_key = MyKeyDb.get_public_key_for(username)
...> SigAuth.verify(method, path, epoch, body, signature, public_key)
true
```



## Installation

```elixir
{:sig_auth, "~> 0.1.0"},
```
