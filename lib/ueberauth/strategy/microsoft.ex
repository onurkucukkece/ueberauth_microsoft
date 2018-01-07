defmodule Ueberauth.Strategy.Microsoft do
  use Ueberauth.Strategy, default_scope: "https://graph.microsoft.com/user.read openid email offline_access",
                          uid_field: :id

  alias OAuth2.{Response, Error}
  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.Microsoft.OAuth

  @doc """
  Handles initial request for Microsoft authentication.
  """
  def handle_request!(conn) do
    default_scopes = option(conn, :default_scope)
    extra_scopes = option(conn, :extra_scopes)

    scopes = "#{extra_scopes} #{default_scopes}"

    authorize_url =
      conn.params
      #|> put_param(conn, "scope", :default_scope)
      |> Map.put(:scope, scopes)
      |> Map.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!

    redirect!(conn, authorize_url)
  end

  @doc """
  Handles the callback from Microsoft.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]
    # client = OAuth.get_token!([code: code], opts)
    client = OAuth.get_token!([code: code, grant_type: "client_credentials"], opts)
    token = client.token

    case token.access_token do
      nil ->
        err = token.other_params["error"]
        desc = token.other_params["error_description"]
        set_errors!(conn, [error(err, desc)])
      _token ->
        fetch_user(conn, client)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
      |> put_private(:ms_token, nil)
      |> put_private(:ms_user, nil)
  end

  def uid(conn) do
    user = conn
      |> option(:uid_field)
      |> to_string

    conn.private.ms_user[user]
  end

  def credentials(conn) do
    token = conn.private.ms_token

    %Credentials{
      expires: token.expires_at != nil,
      expires_at: token.expires_at,
      scopes: token.other_params["scope"],
      token: token.access_token,
      refresh_token: token.refresh_token,
      token_type: token.token_type
    }
  end

  def info(conn) do
    user = conn.private.ms_user

    %Info{
      name: user["displayName"],
      email: user["mail"] || user["userPrincipalName"],
      first_name: user["givenName"],
      last_name: user["surname"]
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.ms_token,
        user: conn.private.ms_user
      }
    }
  end

  defp fetch_user(conn, client) do
    IO.inspect conn.body_params
    # IO.inspect JWTex.decode conn.body_params["id_token"], nil
    # public_key = jwks_uri() |> get_discovery_keys |> formatted_cert |> decode_pem

    # verify with RSA SHA256 algorithm
    public = JsonWebToken.Algorithm.RsaUtil.public_key("/tmp", "key.pem")

    opts = %{
      alg: "RS256",
      key: public
    }

    {:ok, claims} = JsonWebToken.verify(conn.body_params["id_token"], opts)
    IO.puts claims[:upn]
  end

  defp option(conn, key) do
    default = Keyword.get(default_options(), key)

    conn
      |> options
      |> Keyword.get(key, default)
  end

  defp jwks_uri do
    body = http_request("https://login.microsoftonline.com/common/.well-known/openid-configuration")
    {status, list} = JSON.decode(body)
    if status == :ok, do: list["jwks_uri"], else: nil
  end

  defp get_discovery_keys(url)do
    list_body = http_request url
    {status, list} = JSON.decode list_body

    if status == :ok do
      item = Enum.at(list["keys"], 0)
      item["x5c"]
    end
  end

  defp http_request(url) do
    {:ok, resp} = :httpc.request(:get, {to_charlist(url), []}, [], [])
    {{_, 200, 'OK'}, _headers, body} = resp
    body
  end

  defp decode_pem(certificate) do
    [entry] = :public_key.pem_decode certificate
    pem_entry = :public_key.pem_entry_decode entry
    public_key = pem_entry |> elem(1) |> elem(7) |> elem(2)
     |> Base.encode64 |> formatted_key
    rsa_key = :public_key.der_decode(:RSAPublicKey, public_key)
  end

  defp formatted_cert(cert) do
    "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----\n"
  end
  
  defp formatted_key(key_string) do
    IO.puts key_string
    key_string = to_charlist(key_string) |> Enum.chunk(64) |> Enum.join("\n")
    "-----BEGIN PUBLIC KEY-----\n#{key_string}\n-----END PUBLIC KEY-----\n"
  end

  defp save_to_tmp(public_key) do
    filename = SecureRandom.uuid
    {:ok, file} = File.open "/tmp/#{filename}", [:write]
    IO.binwrite file, public_key
    File.close file
    filename
  end
end
