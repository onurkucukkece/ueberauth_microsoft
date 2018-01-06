defmodule UeberauthMicrosoft.Mixfile do
  use Mix.Project

  def project do
    [app: :ueberauth_microsoft,
     version: "0.3.0",
     elixir: "~> 1.4",
     description: description(),
     package: package(),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [extra_applications: [:logger, :ueberauth, :oauth2]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:my_dep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:my_dep, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:oauth2, "~> 0.8", path: "../oauth2-master"},
      {:ueberauth, "~> 0.4"},
      {:json, "~> 1.0"},
      {:json_web_token, "~> 0.2"},
      {:ex_doc, ">= 0.14.0", only: :dev}
    ]
  end

  defp description do
    "Microsoft Strategy for Überauth"
  end

  defp package do
    [name: :ueberauth_microsoft,
     maintainers: ["swelham"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/swelham/ueberauth_microsoft"}]
  end
end
