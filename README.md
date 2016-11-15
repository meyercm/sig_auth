# SigAuth

An HTTP API client authentication scheme based on RSA signatures.

In an HTTPS environment, the server's identity is trusted; proving the identity of the client can be accomplished in many ways; This scheme is inspired by the AWS authentication scheme, with a few modifications for simplicity's sake.

To prove identity, the client holds the private key of an RSA keypair, and creates a digital signature of the request as it is submitted.  The server can then validate the signature using the public key of the client claiming to submit the request.

This library makes no assumptions about your HTTP client or server, except that they allow you to specify and read the headers, body, method and path of a request.

## Example Use

### Client

This client is using HTTPotion, but any client library that allows specifying
custom headers can be used (SigAuth provides headers as binary 2-tuples, e.g.:
`[{"authorization", "<authorization-token-stuff>"}, ...]`).

```elixir
priv_key = SigAuth.load_key("./test/testing_id_rsa")
headers = SigAuth.sign("GET", "/api/users/27.json", 1, "", "bob", priv_key)
# headers contains "authorization", and "x-sigauth-nonce" headers
HTTPotion.get("www.myapp.com/api/users.27.json", [headers: headers])
```

### Request Validation (server-side)

SigAuth provides the `SigAuth.Plug` module to streamline request validation and
nonce maintenince.  Here is an example usage, with a public, non-authenticated
API endpoint followed by a private, authenticated endpoint.

```elixir
defmodule MyApp.ApiRouter
  use Plug.Router

  plug :match
  plug :dispatch

  # Not Authenticated:
  forward "/public", to: MyApp.PublicApiRouter

  plug SigAuth.Plug, credential_server: MyApp.CredServer # See below for details

  # Authenticated:
  forward "/private", to: MyApp.PrivateApiRouter
  # ...

```

## IMPORTANT NOTES:

 - This plug *must* read the body of the request to verify the signature. This
 may well break your plug pipeline (Parsers, especially).  Currently, the body
 is stored in `conn.assigns[:body]` after it is read.  If you have an idea for
 a more elegant solution, feel free to provide a pull-request.

 - The username in the "authorization" header is stored for convenience in
 `conn.assigns[:username]`; this field can be used for user / role based
 authentication of individual endpoints; `SigAuth` has proven that the
 requestor possesses the private key associated with that username.

## CredentialServer

Rather than owning the enrollment and key management problem, SigAuth offloads
this work to you.  The `SigAuth.CredentialServer` module specifies the method
signatures that your credential server must expose for SigAuth.Plug to use it.

An example in-memory credential server is provided in
`SigAuth.ExampleCredentialServer`.

## Installation (Not yet)

```elixir
{:sig_auth, "~> 0.1.0"},
```

## Credits

I found the following links helpful in the construction of this application:

[AWS authorization scheme](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
[Plug authentication example](http://luk3thomas.com/authentiation-in-elixir-plug-20160722.html)
[Erlang :public_key cheatsheet](https://gist.github.com/zucaritask/3864572)
