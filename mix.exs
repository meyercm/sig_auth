defmodule SigAuth.Mixfile do
  use Mix.Project

  def project do
    [app: :sig_auth,
     version: "0.1.0",
     elixir: "~> 1.3",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    [
      {:plug, "~> 1.2"},
      {:shorter_maps, "~> 1.0"},
    ]
  end
end
