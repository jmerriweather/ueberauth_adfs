use Mix.Config

config :ueberauth, Ueberauth.Strategy.ADFS,
  adfs_url: "https://example.com",
  adfs_metadata_url: "https://example.com/metadata.xml",
  client_id: "example_client",
  resource_identifier: "example_resource"
