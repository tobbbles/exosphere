defmodule Exosphere.MixProject do
  use Mix.Project

  def project do
    [
      app: :exosphere,
      version: "0.2.1",
      elixir: "~> 1.19",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Exosphere",
      description:
        "A collection of ATProto clients and utilities, including XRPC clients, firehose consumers, and more.",
      source_url: "https://github.com/tobbbles/exosphere",
      docs: docs(),
      package: package(),
      dialyzer: [
        # Put the project-level PLT in the priv/ directory (instead of the default _build/ location)
        plt_file: {:no_warn, "priv/plts/project.plt"},
        # The maintenance tasks in tasks/ call Mix.raise/Mix.shell/OptionParser
        plt_add_apps: [:mix]
      ]
    ]
  end

  # The tasks/ directory holds repo-maintenance Mix tasks (changelog.add,
  # changelog.cut); compiling them only in :test keeps them out of the Hex
  # package and the published docs.
  defp elixirc_paths(:test), do: ["lib", "tasks", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

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
      {:websockex, "~> 0.5"},
      {:cbor, "~> 1.0"},
      {:varint, "~> 1.5"},
      {:jose, "~> 1.11"},
      {:ex_secp256k1, "~> 0.7"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false, warn_if_outdated: true}
    ]
  end

  defp docs do
    [
      main: "readme",
      logo: "docs/static/logo.png",
      extras: ["README.md", "docs/firehose.md"]
    ]
  end

  defp package do
    [
      name: "exosphere",
      files: ["lib", "mix.exs", "README.md", "LICENSE", "CHANGELOG.md", "docs"],
      maintainers: ["Toby Archer"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/tobbbles/exosphere"}
    ]
  end
end
