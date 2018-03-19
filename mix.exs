defmodule UeberauthAdfs.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_adfs,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      name: "Ueberauth ADFS",
      source_url: "https://github.com/jmerriweather/ueberauth_adfs",
      docs: [main: "Ueberauth ADFS", # The main page in the docs
             extras: ["README.md"]]
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
      {:oauth2, "~> 0.9"},
      {:ueberauth, "~> 0.5"},
      {:joken, "~> 1.5"},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false}
    ]
  end
end
