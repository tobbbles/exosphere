defmodule Exosphere.MixProject do
  use Mix.Project

  def project do
    [
      app: :exosphere,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Exosphere",
      description: "A collection of ATProto clients and utilities, including XRPC clients, firehose consumers, and more.",
      source_url: "https://github.com/tobbbles/exosphere",
      docs: docs(),
      package: package(),
      dialyzer: [
        # Put the project-level PLT in the priv/ directory (instead of the default _build/ location)
        plt_file: {:no_warn, "priv/plts/project.plt"}
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.4"},
      {:mint, "~> 1.7"},
      {:fresh, "~> 0.4"},
      {:cbor, "~> 1.0"},
      {:varint, "~> 1.5"},
      {:jose, "~> 1.11"},
      {:ex_secp256k1, "~> 0.7"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false, warn_if_outdated: true}
    ]
  end

  defp docs do
    [
      main: "readme",
      logo: "docs/static/logo.png",
      extras: ["README.md"]
    ]
  end

  defp package do
    [
      name: "exosphere",
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Toby Archer"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/tobbbles/exosphere"}
    ]
  end
end
