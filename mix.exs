defmodule SigAuth.Mixfile do
  use Mix.Project

  @version "0.1.3"
  @repo_url "https://github.com/meyercm/sig_auth"

  def project do
    [
      app: :sig_auth,
      version: @version,
      elixir: "~> 1.3",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      package: hex_package(),
      description: "An HTTP API client authentication scheme based on RSA signatures."
    ]
  end

  defp hex_package do
    [maintainers: ["Chris Meyer"],
     licenses: ["MIT"],
     links: %{"GitHub" => @repo_url}]
  end


  def application do
    [applications: [:logger]]
  end

  defp deps do
    [
      {:plug, "~> 1.2"},
      {:shorter_maps, "~> 2.1"},
      {:ex_doc, ">= 0.0.0", only: :dev},
    ]
  end
end
