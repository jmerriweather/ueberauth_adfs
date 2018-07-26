defmodule Ueberauth.Strategy.ADFSTest do
  use ExUnit.Case
  use Ueberauth.Strategy

  import Mock

  alias Ueberauth.Strategy.ADFS

  @mock_metadata "<EntityDescriptor><ds:Signature><KeyInfo>" <>
                   "<X509Data><X509Certificate>MAgCAgTSAgIWLg==</X509Certificate></X509Data>" <>
                   "</KeyInfo></ds:Signature></EntityDescriptor>"

  describe "ADFS Strategy" do
    setup_with_mocks [
      {Ueberauth.Strategy.Helpers, [:passthrough],
       [
         callback_url: fn _ -> "https://test.com" end,
         redirect!: fn _conn, auth_url -> auth_url end,
         set_errors!: fn _conn, errors -> errors end
       ]},
      {OAuth2.Client, [:passthrough],
       [get_token: fn client, code -> {:ok, %{token: %{access_token: "1234"}}} end]},
      {HTTPoison, [:passthrough], [get: &mock_metadata/3]},
      {JOSE.JWK, [:passthrough], [from_pem: fn _ -> %{foo: :bar} end]}
    ] do
      :ok
    end

    test "Handles the ADFS request" do
      adfs_url = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)[:adfs_url]
      request = ADFS.handle_request!(%Plug.Conn{params: %{}})

      assert request =~ "#{adfs_url}/adfs/oauth2/authorize"
    end

    test "Redirects ADFS request to index when missing config" do
      env = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)
      Application.delete_env(:ueberauth, Ueberauth.Strategy.ADFS)

      assert ADFS.handle_request!(nil) == "/"

      Application.put_env(:ueberauth, Ueberauth.Strategy.ADFS, env)
    end

    test "Handles the logout request" do
      adfs_url = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)[:adfs_url]
      assert ADFS.logout(nil, nil) =~ "#{adfs_url}/adfs/ls/?wa=wsignout1.0"
    end

    test "Gives an error upon logout request with missing config" do
      env = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)
      Application.delete_env(:ueberauth, Ueberauth.Strategy.ADFS)

      assert ADFS.logout(nil, nil) == [
               %Ueberauth.Failure.Error{
                 message: "Failed to logout, please close your browser",
                 message_key: "Logout Failed"
               }
             ]

      Application.put_env(:ueberauth, Ueberauth.Strategy.ADFS, env)
    end

    test "Handle callback from ADFS provider" do
      IO.inspect(ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}}))
    end
  end

  describe "ADFS Oauth Client" do
    test "Gets the client with the config properties" do
      env = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)
      client = ADFS.OAuth.client()

      assert client.client_id == env[:client_id]
      assert client.authorize_url == "#{env[:adfs_url]}/adfs/oauth2/authorize"
      assert client.token_url == "#{env[:adfs_url]}/adfs/oauth2/token"
    end

    test "Gets the client with options" do
      env = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)
      client = ADFS.OAuth.client(client_id: "other_client")
      assert client.client_id == "other_client"
    end

    test "Doesn't get the client without config" do
      env = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)
      Application.delete_env(:ueberauth, Ueberauth.Strategy.ADFS)

      client = ADFS.OAuth.client()

      Application.put_env(:ueberauth, Ueberauth.Strategy.ADFS, env)

      assert client == {nil, []}
    end

    test "Get the authorize_url" do
      adfs_url = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)[:adfs_url]

      assert ADFS.OAuth.authorize_url!() ==
               "#{adfs_url}/adfs/oauth2/authorize?client_id=example_client&redirect_uri=&response_type=code"
    end

    test "Gets the signout url" do
      adfs_url = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)[:adfs_url]

      assert ADFS.OAuth.signout_url() == {:ok, "#{adfs_url}/adfs/ls/?wa=wsignout1.0"}
    end

    test "Gets the signout url with params" do
      adfs_url = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)[:adfs_url]

      assert ADFS.OAuth.signout_url(%{redirect_uri: "https://test.com"}) ==
               {:ok, "#{adfs_url}/adfs/ls/?wa=wsignout1.0&wreply=https://test.com"}
    end

    test "Fails to get the signout url without config" do
      env = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)
      Application.delete_env(:ueberauth, Ueberauth.Strategy.ADFS)

      assert ADFS.OAuth.signout_url() == {:error, :failed_to_logout}

      Application.put_env(:ueberauth, Ueberauth.Strategy.ADFS, env)
    end
  end

  defp mock_metadata(_url, _, _) do
    {:ok, %HTTPoison.Response{body: @mock_metadata}}
  end
end
