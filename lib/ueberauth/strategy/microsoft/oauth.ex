defmodule Ueberauth.Strategy.Microsoft.OAuth do
  use OAuth2.Strategy

  alias OAuth2.Client
  alias OAuth2.Strategy.AuthCode

  @defaults [
    strategy: __MODULE__,
    site: "https://graph.microsoft.com",
    authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    request_opts: [ssl_options: [versions: [:'tlsv1.2']]]
  ]

  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Microsoft.OAuth)

    @defaults
      |> Keyword.replace(:authorize_url, org_authorize_url())
      |> Keyword.replace(:token_url, org_token_url())
      |> Keyword.merge(config)
      |> Keyword.merge(opts)
      |> Client.new
  end

  def authorize_url!(params \\ [], opts \\ []) do
    opts
      |> client
      |> Client.authorize_url!(params)
  end

  def get_token!(params \\ [], opts \\ []) do
    opts
      |> client
      |> Client.get_token!(params)
  end

  # oauth2 Strategy Callbacks

  def authorize_url(client, params) do
    params = Map.update(params, :response_mode, "form_post", &(&1 * "form_post"))
    params = Map.update(params, :response_type, "code id_token", &(&1 * "code id_token"))
    params = Map.update(params, :nonce, SecureRandom.uuid, &(&1 * SecureRandom.uuid))
    AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
      |> put_param(:client_secret, client.client_secret)
      |> put_header("Accept", "application/json")
      |> AuthCode.get_token(params, headers)
  end

  def org_token_url do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Microsoft.OAuth)
    "https://login.microsoftonline.com/#{config[:tenant]}/oauth2/token"
  end

  def org_authorize_url do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Microsoft.OAuth)
    "https://login.microsoftonline.com/#{config[:tenant]}/oauth2/authorize"
  end
end
