use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

pub mod types {
  use std::fmt::Display;

  use serde::{Deserialize, Serialize};

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct ControllerNetwork {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<std::collections::HashMap<String, String>>,
    #[serde(rename = "creationTime", default, skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<f64>,
    #[serde(rename = "enableBroadcast", default, skip_serializing_if = "Option::is_none")]
    pub enable_broadcast: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "ipAssignmentPools", default, skip_serializing_if = "Vec::is_empty")]
    pub ip_assignment_pools: Vec<ControllerNetworkIpAssignmentPoolsItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<i64>,
    #[serde(rename = "multicastLimit", default, skip_serializing_if = "Option::is_none")]
    pub multicast_limit: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nwid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objtype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private: Option<bool>,
    #[serde(rename = "remoteTraceLevel", default, skip_serializing_if = "Option::is_none")]
    pub remote_trace_level: Option<i64>,
    #[serde(rename = "remoteTraceTarget", default, skip_serializing_if = "Option::is_none")]
    pub remote_trace_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<ControllerNetworkRoutesItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(rename = "v4AssignMode", default, skip_serializing_if = "Option::is_none")]
    pub v4_assign_mode: Option<ControllerNetworkV4AssignMode>,
    #[serde(rename = "v6AssignMode", default, skip_serializing_if = "Option::is_none")]
    pub v6_assign_mode: Option<ControllerNetworkV6AssignMode>,
  }

  impl Display for ControllerNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(
        f,
        "ControllerNetwork: {}",
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "Invalid JSON".to_string())
      )
    }
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct ControllerNetworkIpAssignmentPoolsItem {
    #[serde(rename = "ipRangeEnd", default, skip_serializing_if = "Option::is_none")]
    pub ip_range_end: Option<String>,
    #[serde(rename = "ipRangeStart", default, skip_serializing_if = "Option::is_none")]
    pub ip_range_start: Option<String>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct ControllerNetworkMember {
    #[serde(rename = "activeBridge", default, skip_serializing_if = "Option::is_none")]
    pub active_bridge: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(rename = "ipAssignments", default, skip_serializing_if = "Vec::is_empty")]
    pub ip_assignments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nwid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
    #[serde(rename = "vMajor", default, skip_serializing_if = "Option::is_none")]
    pub v_major: Option<i64>,
    #[serde(rename = "vMinor", default, skip_serializing_if = "Option::is_none")]
    pub v_minor: Option<i64>,
    #[serde(rename = "vProto", default, skip_serializing_if = "Option::is_none")]
    pub v_proto: Option<i64>,
    #[serde(rename = "vRev", default, skip_serializing_if = "Option::is_none")]
    pub v_rev: Option<i64>,
  }

  impl Display for ControllerNetworkMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(
        f,
        "ControllerNetworkMember: {}",
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "Invalid JSON".to_string())
      )
    }
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct ControllerNetworkRoutesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct ControllerNetworkV4AssignMode {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zt: Option<bool>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct ControllerNetworkV6AssignMode {
    #[serde(rename = "6plane", default, skip_serializing_if = "Option::is_none")]
    pub _6plane: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc4193: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zt: Option<bool>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct ControllerStatus {
    #[serde(rename = "apiVersion", default, skip_serializing_if = "Option::is_none")]
    pub api_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
  }

  impl Display for ControllerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(
        f,
        "ControllerStatus: {}",
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "Invalid JSON".to_string())
      )
    }
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct Network {
    #[doc = "Let ZeroTier modify the system's default route."]
    #[serde(rename = "allowDefault", default, skip_serializing_if = "Option::is_none")]
    pub allow_default: Option<bool>,
    #[doc = "Let ZeroTier modify the system's DNS settings."]
    #[serde(rename = "allowDNS", default, skip_serializing_if = "Option::is_none")]
    pub allow_dns: Option<bool>,
    #[doc = "Let ZeroTier manage IP addresses and Route assignments that aren't in private ranges (rfc1918)."]
    #[serde(rename = "allowGlobal", default, skip_serializing_if = "Option::is_none")]
    pub allow_global: Option<bool>,
    #[doc = "Let ZeroTier to manage IP addresses and Route assignments."]
    #[serde(rename = "allowManaged", default, skip_serializing_if = "Option::is_none")]
    pub allow_managed: Option<bool>,
    #[serde(rename = "assignedAddresses", default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<bool>,
    #[serde(rename = "broadcastEnabled", default, skip_serializing_if = "Option::is_none")]
    pub broadcast_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<NetworkSubtype1Dns>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[doc = "MAC address for this network's interface."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<i64>,
    #[serde(rename = "multicastSubscriptions", default, skip_serializing_if = "Vec::is_empty")]
    pub multicast_subscriptions: Vec<NetworkSubtype1MulticastSubscriptionsItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "netconfRevision", default, skip_serializing_if = "Option::is_none")]
    pub netconf_revision: Option<i64>,
    #[serde(rename = "portDeviceName", default, skip_serializing_if = "Option::is_none")]
    pub port_device_name: Option<String>,
    #[serde(rename = "portError", default, skip_serializing_if = "Option::is_none")]
    pub port_error: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<NetworkSubtype1RoutesItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
  }

  impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(
        f,
        "Network: {}",
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "Invalid JSON".to_string())
      )
    }
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct NetworkSubtype1Dns {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct NetworkSubtype1MulticastSubscriptionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adi: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct NetworkSubtype1RoutesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct Peer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "isBonded", default, skip_serializing_if = "Option::is_none")]
    pub is_bonded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PeerPathsItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionMajor", default, skip_serializing_if = "Option::is_none")]
    pub version_major: Option<i64>,
    #[serde(rename = "versionMinor", default, skip_serializing_if = "Option::is_none")]
    pub version_minor: Option<i64>,
    #[serde(rename = "versionRev", default, skip_serializing_if = "Option::is_none")]
    pub version_rev: Option<i64>,
  }

  impl Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(
        f,
        "Peer: {}",
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "Invalid JSON".to_string())
      )
    }
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct PeerPathsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "lastReceive", default, skip_serializing_if = "Option::is_none")]
    pub last_receive: Option<i64>,
    #[serde(rename = "lastSend", default, skip_serializing_if = "Option::is_none")]
    pub last_send: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred: Option<bool>,
    #[serde(rename = "trustedPathId", default, skip_serializing_if = "Option::is_none")]
    pub trusted_path_id: Option<i64>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct Status {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<StatusConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(rename = "planetWorldId", default, skip_serializing_if = "Option::is_none")]
    pub planet_world_id: Option<i64>,
    #[serde(rename = "planetWorldTimestamp", default, skip_serializing_if = "Option::is_none")]
    pub planet_world_timestamp: Option<i64>,
    #[serde(rename = "publicIdentity", default, skip_serializing_if = "Option::is_none")]
    pub public_identity: Option<String>,
    #[serde(rename = "tcpFallbackActive", default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback_active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionBuild", default, skip_serializing_if = "Option::is_none")]
    pub version_build: Option<i64>,
    #[serde(rename = "versionMajor", default, skip_serializing_if = "Option::is_none")]
    pub version_major: Option<i64>,
    #[serde(rename = "versionMinor", default, skip_serializing_if = "Option::is_none")]
    pub version_minor: Option<i64>,
    #[serde(rename = "versionRev", default, skip_serializing_if = "Option::is_none")]
    pub version_rev: Option<i64>,
  }

  impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(
        f,
        "Status: {}",
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "Invalid JSON".to_string())
      )
    }
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct StatusConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<StatusConfigSettings>,
  }

  #[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct StatusConfigSettings {
    #[serde(rename = "allowTcpFallbackRelay", default, skip_serializing_if = "Option::is_none")]
    pub allow_tcp_fallback_relay: Option<bool>,
    #[serde(rename = "portMappingEnabled", default, skip_serializing_if = "Option::is_none")]
    pub port_mapping_enabled: Option<bool>,
    #[serde(rename = "primaryPort", default, skip_serializing_if = "Option::is_none")]
    pub primary_port: Option<i64>,
  }
}

#[derive(Clone)]
pub struct Client {
  baseurl: Url,
  token: String,
  client: reqwest::Client,
}

impl Client {
  pub fn new(baseurl: &str, token: &str) -> anyhow::Result<Self> {
    let client = reqwest::ClientBuilder::new()
      .connect_timeout(std::time::Duration::from_secs(5))
      .timeout(std::time::Duration::from_secs(5))
      .build()?;
    let r = Self {
      baseurl: Url::parse(baseurl)?,
      token: token.to_string(),
      client,
    };
    Ok(r)
  }

  fn request(&self, method: reqwest::Method, path: &str) -> anyhow::Result<reqwest::RequestBuilder> {
    let r = self.client.request(method, self.baseurl.join(path)?).header("X-ZT1-AUTH", self.token.clone());
    Ok(r)
  }

  async fn exec(&self, request: reqwest::Request) -> anyhow::Result<Response> {
    let response = self.client.execute(request).await?;
    let status = response.status();
    match status {
      StatusCode::OK => Ok(response),
      StatusCode::UNAUTHORIZED => anyhow::bail!("unauthorized request"),
      _ => anyhow::bail!("unexpected response: {}", status),
    }
  }

  async fn json<T: for<'a> Deserialize<'a>>(&self, request: reqwest::Request) -> anyhow::Result<T> {
    let body = self.exec(request).await?.bytes().await?;
    let response: T = serde_json::from_slice(&body)?;
    Ok(response)
  }

  async fn get_json<T: for<'a> Deserialize<'a>>(&self, path: &str) -> anyhow::Result<T> {
    let r = self.request(reqwest::Method::GET, path)?.build()?;
    let r = self.json(r).await?;
    Ok(r)
  }

  async fn post<T: Serialize, R: for<'a> Deserialize<'a>>(&self, path: &str, body: &T) -> anyhow::Result<R> {
    let r = self
      .request(reqwest::Method::POST, path)?
      .header("content-type", "application/json")
      .body(serde_json::to_string(body)?)
      .build()?;
    let response = self.json(r).await?;
    Ok(response)
  }

  async fn delete(&self, path: &str) -> anyhow::Result<()> {
    let r = self.request(reqwest::Method::DELETE, path)?.build()?;
    let _ = self.exec(r).await?;
    Ok(())
  }

  /// Get Controller Status
  /// Check for controller function and return controller status.
  /// Sends a `GET` request to `/controller`
  pub async fn get_controller_status(&self) -> anyhow::Result<types::ControllerStatus> {
    self.get_json("/controller").await
  }

  /// List Networks
  /// List IDs of all networks hosted by this controller.
  /// Sends a `GET` request to `/controller/network`
  pub async fn get_controller_networks(&self) -> anyhow::Result<Vec<String>> {
    self.get_json("/controller/network").await
  }

  /// Get Network by ID
  /// Get details of a network by its ID.
  /// Sends a `GET` request to `/controller/network/{networkID}`
  pub async fn get_controller_network(&self, network_id: &str) -> anyhow::Result<types::ControllerNetwork> {
    let path = format!("/controller/network/{}", network_id);
    self.get_json(&path).await
  }

  /// Create or Update a Network
  /// Sends a `POST` request to `/controller/network/{networkID}`
  pub async fn set_controller_network(
    &self, network_id: &str, body: &types::ControllerNetwork,
  ) -> anyhow::Result<types::ControllerNetwork> {
    self.post(&format!("/controller/network/{}", network_id), body).await
  }

  /// Generate Random Network ID
  /// Create a new network with a random ID.
  /// Sends a `POST` request to `/controller/network/{controllerID}`
  pub async fn generate_controller_network(
    &self, controller_id: &str, body: &types::ControllerNetwork,
  ) -> anyhow::Result<types::ControllerNetwork> {
    self.post(&format!("/controller/network/{}", controller_id), body).await
  }

  /// List Network Members
  /// JSON object containing all member IDs as keys and their memberRevisionCounter values as values.
  /// Sends a `GET` request to `/controller/network/{networkID}/member`
  pub async fn get_controller_network_members(
    &self, network_id: &str,
  ) -> anyhow::Result<std::collections::HashMap<String, i64>> {
    self.get_json(&format!("/controller/network/{}/member", network_id)).await
  }

  /// Get Network Member Details by ID
  /// Sends a `GET` request to `/controller/network/{networkID}/member/{nodeID}`
  pub async fn get_controller_network_member(
    &self, network_id: &str, node_id: &str,
  ) -> anyhow::Result<types::ControllerNetworkMember> {
    self.get_json(&format!("/controller/network/{}/member/{}", network_id, node_id)).await
  }

  pub async fn update_controller_network_member(
    &self, network_id: &str, node_id: &str, body: &types::ControllerNetworkMember,
  ) -> anyhow::Result<types::ControllerNetworkMember> {
    self.post(&format!("/controller/network/{}/member/{}", network_id, node_id), body).await
  }

  /// Node status and addressing info
  /// Sends a `GET` request to `/status`
  pub async fn get_status(&self) -> anyhow::Result<types::Status> { self.get_json("/status").await }

  /// Get all network memberships
  /// Sends a `GET` request to `/network`
  pub async fn get_networks(&self) -> anyhow::Result<Vec<types::Network>> { self.get_json("/network").await }

  /// Get a joined Network membership configuration by Network ID
  /// Sends a `GET` request to `/network/{networkID}`
  pub async fn get_network(&self, network_id: &str) -> anyhow::Result<types::Network> {
    self.get_json(&format!("/network/{}", network_id)).await
  }

  /// Join a network or update its configuration by Network ID
  /// Sends a `POST` request to `/network/{networkID}`
  pub async fn update_network(&self, network_id: &str, body: &types::Network) -> anyhow::Result<types::Network> {
    self.post(&format!("/network/{}", network_id), body).await
  }

  /// Leave a network
  /// Sends a `DELETE` request to `/network/{networkID}`
  pub async fn delete_network(&self, network_id: &str) -> anyhow::Result<()> {
    self.delete(&format!("/network/{}", network_id)).await
  }

  /// Get all peers
  /// Sends a `GET` request to `/peer`
  pub async fn get_peers(&self) -> anyhow::Result<Vec<types::Peer>> { self.get_json("/peer").await }

  /// Get information about a specific peer by Node ID
  /// Sends a `GET` request to `/peer/{address}`
  pub async fn get_peer(&self, address: &str) -> anyhow::Result<types::Peer> {
    self.get_json(&format!("/peer/{}", address)).await
  }
}
