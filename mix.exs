defmodule UeberauthAdfs.MixProject do
  use Mix.Project

  @version "0.1.0"
  @url "https://github.com/Kuret/ueberauth_adfs"
  @maintainers ["Rick Littel"]

  def project do
    [
      app: :ueberauth_adfs,
      version: @version,
      elixir: "~> 1.6",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Ueberauth ADFS",
      description: "ADFS Strategy for Überauth",
      source_url: @url,
      homepage_url: @url,
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{"GitHub" => @url},
      files: ~w(lib) ++ ~w(LICENSE.md mix.exs README.md)
    ]
  end

  def docs do
    [
      extras: ["README.md", "LICENSE.md"],
      source_ref: "v#{@version}",
      main: "readme"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :ueberauth, :oauth2]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:earmark, "~> 1.2", only: :dev, runtime: false},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false},
      {:httpoison, "~> 0.13"},
      {:joken, "~> 1.5"},
      {:oauth2, "~> 0.9"},
      {:sweet_xml, "~> 0.6"},
      {:ueberauth, "~> 0.5"}
    ]
  end
end
