defmodule Ueberauth.Strategy.ADFS do
  @moduledoc """
  ADFS Strategy for Überauth.
  """

  import SweetXml

  use Ueberauth.Strategy

  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.ADFS.OAuth

  def handle_request!(conn) do
    if __MODULE__.configured?() do
      redirect_to_authorization(conn)
    else
      redirect!(conn, "/")
    end
  end

  def logout(conn, token) do
    params = %{redirect_uri: callback_url(conn), token: token}

    with {:ok, signout_url} <- OAuth.signout_url(params) do
      redirect!(conn, signout_url)
    else
      _ ->
        set_errors!(conn, [error("Logout Failed", "Failed to logout, please close your browser")])
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    with {:ok, client} <- OAuth.get_token(code, redirect_uri: callback_url(conn)) do
      fetch_user(conn, client)
    else
      {:error, %{reason: reason}} ->
        set_errors!(conn, [error("Authentication Error", reason)])

      {:error, %OAuth2.Response{body: %{"error_description" => reason}}} ->
        set_errors!(conn, [error("Authentication Error", reason)])
    end
  end

  def handle_callback!(
        %Plug.Conn{params: %{"error" => error, "error_description" => error_description}} = conn
      ) do
    set_errors!(conn, [error(error, error_description)])
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:adfs_user, nil)
    |> put_private(:adfs_token, nil)
  end

  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.adfs_user[uid_field]
  end

  def credentials(conn) do
    token = conn.private.adfs_token

    %Credentials{token: token.token}
  end

  def info(conn) do
    user = conn.private.adfs_user

    %Info{
      name: "#{user["given_name"]} #{user["family_name"]}",
      nickname: user["winaccountname"],
      email: user["email"]
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private[:adfs_token],
        user: conn.private[:adfs_user]
      }
    }
  end

  def configured? do
    :ueberauth
    |> Application.get_env(__MODULE__)
    |> env_present?
  end

  defp fetch_user(conn, %{token: %{access_token: access_token}}) do
    url = config(:adfs_metadata_url)

    with {:ok, %HTTPoison.Response{body: metadata}} <-
           HTTPoison.get(url, [], ssl: [versions: [:"tlsv1.2"]]),
         true <- String.starts_with?(metadata, "<EntityDescriptor"),
         {:ok, certificate} <- cert_from_metadata(metadata) do
      key =
        certificate
        |> JOSE.JWK.from_pem()
        |> Joken.rs256()

      jwt =
        access_token
        |> Joken.token()
        |> Joken.with_signer(key)
        |> Joken.verify()

      conn = put_private(conn, :adfs_token, jwt)

      with %Joken.Token{claims: claims_user} <- jwt do
        put_private(conn, :adfs_user, claims_user)
      else
        _ -> set_errors!(conn, [error("token", "unauthorized")])
      end
    else
      {:error, :metadata_not_found} -> set_errors!(conn, [error("metadata", "not_found")])
      {:error, :cert_not_found} -> set_errors!(conn, [error("certificate", "not_found")])
      _ -> set_errors!(conn, [error("metadata", "unkown")])
    end
  end

  defp cert_from_metadata(metadata) when is_binary(metadata) do
    metadata
    |> xpath(~x"//EntityDescriptor/ds:Signature/KeyInfo/X509Data/X509Certificate/text()"s)
    |> build_cert()
  end

  defp cert_from_metadata(_), do: {:error, :metadata_not_found}

  defp build_cert(cert_content) when is_binary(cert_content) do
    {:ok,
     """
     -----BEGIN CERTIFICATE-----
     #{cert_content}
     -----END CERTIFICATE-----
     """}
  end

  defp build_cert(_), do: {:error, :cert_not_found}

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp config(option) do
    :ueberauth
    |> Application.get_env(__MODULE__)
    |> Keyword.get(option)
  end

  defp redirect_to_authorization(conn) do
    authorize_url =
      conn.params
      |> Map.put(:resource, config(:resource_identifier))
      |> Map.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!()

    redirect!(conn, authorize_url)
  end

  defp env_present?(
         [adfs_url: _, adfs_metadata_url: _, client_id: _, resource_identifier: _] = env
       ) do
    env
    |> Keyword.values()
    |> Enum.all?(&(byte_size(&1 || <<>>) > 0))
  end

  defp env_present?(_), do: false
end
