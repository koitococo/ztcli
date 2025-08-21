use clap::{CommandFactory as _, Parser};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display};
use tokio::fs;
mod ztapi;
use crate::ztapi::Client;

fn pretty_print<T: Display>(obj: &T) {
  eprintln!("{}", obj);
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
  if std::fs::exists(".env")? {
    let _ = dotenvy::dotenv()?;
  }

  env_logger::init();
  Args::parse().apply((), &mut ()).await
}

trait Apply {
  type Context;
  type PersistentState;

  async fn apply(self, ctx: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()>;
}

#[derive(Debug, Parser)]
#[clap(name = "ztcli", version = "0.1.0")]
struct Args {
  #[clap(long = "token", short = 'a', env = "TOKEN")]
  /// Authentication token for the ZeroTier API
  token: Option<String>,

  #[clap(
    long = "token-path",
    short = 'p',
    env = "TOKEN_PATH",
    default_value = "/var/lib/zerotier-one/authtoken.secret"
  )]
  /// Path to the file containing the ZeroTier API authentication token
  token_path: String,

  #[clap(
    long = "endpoint",
    short = 'e',
    env = "ENDPOINT",
    default_value = "http://localhost:9993"
  )]
  /// Base URL for the ZeroTier API endpoint
  endpoint: String,

  #[clap(long = "state_path", short = 's', env = "STATE_PATH", default_value = "state.json")]
  /// Path to state file which contains datas used only by ztcli
  state_path: String,

  #[clap(long = "disable_state", short = 'S', env = "DISABLE_STATE", default_value = "false")]
  /// If true, ztcli will not read state from filesystem, and will not sync changes to it
  disable_state: bool,

  #[clap(subcommand)]
  cmd: Command,
}

#[derive(Serialize, Deserialize, Default)]
struct States {
  ctrl_net_states: CtrlNetStates,
}

impl Apply for Args {
  type Context = ();
  type PersistentState = ();

  async fn apply(self, _: Self::Context, _: &mut Self::PersistentState) -> anyhow::Result<()> {
    let Some(token) = self.token.clone().or_else(|| match std::fs::read_to_string(&self.token_path) {
      Ok(content) => Some(content),
      Err(e) => {
        log::error!("Failed to read token from path: {:?}", e);
        None
      }
    }) else {
      anyhow::bail!("No authentication token provided");
    };

    let mut ps: States = if self.disable_state || !std::fs::exists(&self.state_path)? {
      Default::default()
    } else {
      let content = fs::read_to_string(&self.state_path).await?;
      serde_json::from_str(&content)?
    };

    let client = ztapi::Client::new(self.endpoint.as_str(), &token)?;
    self.cmd.apply(client, &mut ps.ctrl_net_states).await?;

    if !self.disable_state {
      let content = serde_json::to_string(&ps)?;
      fs::write(&self.state_path, content).await?;
    }
    Ok(())
  }
}

#[derive(Debug, Parser)]
enum Command {
  #[clap()]
  Completions(CompletionsArgs),

  /// Show status of the node
  Status,

  /// Manage network controller
  #[clap(subcommand, alias = "c")]
  Controller(CtrlCmds),

  /// Manage networks
  #[clap(subcommand, alias = "n")]
  Network(NetCmds),

  /// Manage peers
  #[clap(subcommand, alias = "p")]
  Peer(PeerCmds),
}

impl Apply for Command {
  type Context = Client;
  type PersistentState = CtrlNetStates;

  async fn apply(self, client: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    match self {
      Self::Completions(args) => args.apply((), &mut ()).await?,
      Self::Status => {
        let r = client.get_status().await?;
        log::info!("Node status: {:?}", r);
        pretty_print(&r);
      }
      Self::Controller(args) => args.apply(client, ps).await?,
      Self::Network(args) => args.apply(client, &mut ()).await?,
      Self::Peer(args) => args.apply(client, &mut ()).await?,
    }
    Ok(())
  }
}

#[derive(Debug, Parser)]
struct CompletionsArgs {
  shell: clap_complete::Shell,
}

impl Apply for CompletionsArgs {
  type Context = ();
  type PersistentState = ();

  async fn apply(self, _: Self::Context, _: &mut Self::PersistentState) -> anyhow::Result<()> {
    clap_complete::generate(
      self.shell,
      &mut Args::command(),
      std::env::current_exe()
        .unwrap()
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or("ztcli".to_string()),
      &mut std::io::stdout(),
    );
    Ok(())
  }
}

#[derive(Debug, Parser)]
enum CtrlCmds {
  /// Show status of the controller
  Status,

  /// List all networks managed by the controller
  List,

  #[clap(alias = "n")]
  /// Manage controller networks
  Network(CtrlNetArgs),
}

impl Apply for CtrlCmds {
  type Context = Client;
  type PersistentState = CtrlNetStates;

  async fn apply(self, client: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    match self {
      Self::Status => {
        let r = client.get_controller_status().await?;
        log::info!("Controller status: {:?}", r);
        pretty_print(&r);
      }
      Self::List => {
        let r = client.get_controller_networks().await?;
        log::info!("Controller networks: {:?}", r);
        for i in r {
          pretty_print(&i);
        }
      }
      Self::Network(args) => args.apply(client, ps).await?,
    }
    Ok(())
  }
}

#[derive(Debug, Parser)]
struct CtrlNetArgs {
  #[clap(long, short)]
  /// ID of the network to operate on
  network_id: String,

  #[clap(subcommand)]
  cmd: CtrlNetCmds,
}

#[derive(Serialize, Deserialize, Default)]
struct CtrlNetStates {
  networks: HashMap<String, CtrlNetMemTagStates>,
}

impl Apply for CtrlNetArgs {
  type Context = Client;
  type PersistentState = CtrlNetStates;

  async fn apply(self, client: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    self.cmd.apply((client, self.network_id), ps).await
  }
}

#[derive(Debug, Parser)]
enum CtrlNetCmds {
  #[clap(alias = "c")]
  /// Create a new network
  Create(Box<CtrlNetParams>),

  #[clap(alias = "u")]
  /// Update an existing network
  Update(Box<CtrlNetParams>),

  #[clap(alias = "m")]
  /// Manage network members
  Member(CtrlNetMemArgs),

  /// Show details of the network
  Info,

  /// List all members of the network
  Members,
}

impl Apply for CtrlNetCmds {
  type Context = (Client, String);
  type PersistentState = CtrlNetStates;

  async fn apply(self, (client, network_id): Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    let next_ps = if let Some(inner) = ps.networks.get_mut(&network_id) {
      inner
    } else {
      let inner = Default::default();
      ps.networks.insert(network_id.clone(), inner);
      ps.networks.get_mut(&network_id).unwrap() // We can assume this unwrap is always safe
    };
    match self {
      Self::Create(args) => {
        let r = client.generate_controller_network(&network_id, &(*args).into()).await?;
        log::info!("Network created successfully: {:?}", r);
        pretty_print(&r);
      }
      Self::Update(args) => {
        let r = client.set_controller_network(&network_id, &(*args).into()).await?;
        log::info!("Network updated successfully: {:?}", r);
        pretty_print(&r);
      }
      Self::Member(args) => args.apply((client, network_id), next_ps).await?,
      Self::Info => {
        let r = client.get_controller_network(&network_id).await?;
        log::info!("Network information: {:?}", r);
        pretty_print(&r);
      }
      Self::Members => {
        let r = client.get_controller_network_members(&network_id).await?;

        log::info!("Members information: {:?}", r);
        for (k, v) in r {
          let msg = if let Some(tag) = next_ps.tags.get_mut(&k) {
            format!("{k}: {v} ({tag})")
          } else {
            format!("{k}: {v}")
          };
          pretty_print(&msg);
        }
      }
    }
    Ok(())
  }
}

#[derive(Debug, Parser)]
struct CtrlNetParams {
  #[clap(long)]
  /// Creation time of the network
  creation_time: Option<f64>,

  #[clap(long)]
  /// Enable broadcast on the network
  enable_broadcast: Option<bool>,

  #[clap(long)]
  /// ID of the network
  id: Option<String>,

  #[clap(long)]
  /// IP assignment pools for the network
  /// Format: "start-end", e.g., "192.168.1.1-192.168.1.254"
  ip_assignment_pools: Vec<String>,

  #[clap(long)]
  /// MTU (Maximum Transmission Unit) for the network
  mtu: Option<i64>,

  #[clap(long)]
  /// Multicast limit for the network
  multicast_limit: Option<i64>,

  #[clap(long)]
  /// Name of the network
  name: Option<String>,

  #[clap(long)]
  /// Network ID (nwid) for the network
  nwid: Option<String>,

  #[clap(long)]
  /// Object type for the network
  objtype: Option<String>,

  #[clap(long)]
  /// Whether the network is private
  /// If true, the network is private and every member must be explicitly authorized
  /// If false, the network is public and any member can join
  private: Option<bool>,

  #[clap(long)]
  /// Remote trace level for the network
  remote_trace_level: Option<i64>,

  #[clap(long)]
  /// Remote trace target for the network
  remote_trace_target: Option<String>,

  #[clap(long)]
  /// Revision number for the network
  revision: Option<i64>,

  #[clap(long)]
  /// Routes for the network
  /// Format: "target", e.g., "192.168.1.0/24"
  /// Currently, 'via' is not supported
  routes: Vec<String>,

  #[clap(long)]
  /// V4 assign mode for the network
  v4_assign_mode: Option<bool>,

  #[clap(long)]
  /// V6 assign mode for the network
  v6_assign_mode_6plane: Option<bool>,

  #[clap(long)]
  /// V6 assign mode for the network using RFC 4193
  v6_assign_mode_rfc4193: Option<bool>,

  #[clap(long)]
  /// V6 assign mode for the network using ZeroTier's own method
  v6_assign_mode_zt: Option<bool>,
}

impl From<CtrlNetParams> for crate::ztapi::types::ControllerNetwork {
  fn from(params: CtrlNetParams) -> Self {
    crate::ztapi::types::ControllerNetwork {
      capabilities: vec![], // FIXME:
      creation_time: params.creation_time,
      enable_broadcast: params.enable_broadcast,
      id: params.id,
      ip_assignment_pools: params
        .ip_assignment_pools
        .into_iter()
        .filter_map(|v| {
          let Some((start, end)) = v.split_once("-") else {
            log::warn!("Invalid IP assignment pool format: {}", v);
            return None;
          };
          Some(crate::ztapi::types::ControllerNetworkIpAssignmentPoolsItem {
            ip_range_end: Some(end.to_string()),
            ip_range_start: Some(start.to_string()),
          })
        })
        .collect(),
      mtu: params.mtu,
      multicast_limit: params.multicast_limit,
      name: params.name,
      nwid: params.nwid,
      objtype: params.objtype,
      private: params.private,
      remote_trace_level: params.remote_trace_level,
      remote_trace_target: params.remote_trace_target,
      revision: params.revision,
      routes: params
        .routes
        .into_iter()
        .map(|v| {
          crate::ztapi::types::ControllerNetworkRoutesItem {
            target: Some(v),
            via: None, // FIXME:
          }
        })
        .collect(),
      rules: vec![], // FIXME:
      tags: vec![],  // FIXME:
      v4_assign_mode: params.v4_assign_mode.map(|v| {
        if v {
          crate::ztapi::types::ControllerNetworkV4AssignMode { zt: Some(true) }
        } else {
          crate::ztapi::types::ControllerNetworkV4AssignMode { zt: Some(false) }
        }
      }),
      v6_assign_mode: {
        if params.v6_assign_mode_6plane.is_none() &&
          params.v6_assign_mode_rfc4193.is_none() &&
          params.v6_assign_mode_zt.is_none()
        {
          None
        } else {
          Some(crate::ztapi::types::ControllerNetworkV6AssignMode {
            _6plane: params.v6_assign_mode_6plane,
            rfc4193: params.v6_assign_mode_rfc4193,
            zt: params.v6_assign_mode_zt,
          })
        }
      },
    }
  }
}

#[derive(Debug, Parser)]
struct CtrlNetMemArgs {
  #[clap(long, short)]
  /// ID of the member to operate on
  member_id: String,

  #[clap(subcommand)]
  cmd: CtrlNetMemCmds,
}

impl Apply for CtrlNetMemArgs {
  type Context = (Client, String);
  type PersistentState = CtrlNetMemTagStates;

  async fn apply(self, (client, network_id): Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    self.cmd.apply((client, network_id, self.member_id), ps).await
  }
}

#[derive(Debug, Parser)]
#[clap(value_enum)]
enum CtrlNetMemCmds {
  /// Show member information
  Info,

  /// Update member information
  Update(Box<CtrlNetMemParams>),

  Tag(CtrlNetMemTagArgs),
}

impl Apply for CtrlNetMemCmds {
  type Context = (Client, String, String);
  type PersistentState = CtrlNetMemTagStates;

  async fn apply(
    self, (client, network_id, member_id): Self::Context, ps: &mut Self::PersistentState,
  ) -> anyhow::Result<()> {
    match self {
      Self::Info => {
        let r = client.get_controller_network_member(&network_id, &member_id).await?;
        log::info!("Member information: {:?}", r);
        pretty_print(&r);
      }
      Self::Update(params) => {
        let body = (*params).into();
        let r = client.update_controller_network_member(&network_id, &member_id, &body).await?;
        log::info!("Member information: {:?}", r);
        pretty_print(&r);
      }
      Self::Tag(args) => {
        args.apply(member_id, ps).await?;
      }
    }
    Ok(())
  }
}

#[derive(Debug, Parser)]
struct CtrlNetMemParams {
  #[clap(long)]
  /// Active bridge status for the member
  active_bridge: Option<bool>,

  #[clap(long)]
  /// Address of the member
  address: Option<String>,

  #[clap(long)]
  /// Whether the member is authorized
  authorized: Option<bool>,

  #[clap(long)]
  /// ID of the member
  id: Option<String>,

  #[clap(long)]
  /// Identity of the member
  identity: Option<String>,

  #[clap(long)]
  /// IP assignments for the member
  ip_assignments: Vec<String>,

  #[clap(long)]
  /// Network ID (nwid) for the member
  nwid: Option<String>,

  #[clap(long)]
  /// Revision number for the member
  revision: Option<i64>,

  #[clap(long)]
  /// Major version of the member
  v_major: Option<i64>,

  #[clap(long)]
  /// Minor version of the member
  v_minor: Option<i64>,

  #[clap(long)]
  /// Protocol version of the member
  v_proto: Option<i64>,

  #[clap(long)]
  /// Revision version of the member
  v_rev: Option<i64>,
}

impl From<CtrlNetMemParams> for crate::ztapi::types::ControllerNetworkMember {
  fn from(params: CtrlNetMemParams) -> Self {
    crate::ztapi::types::ControllerNetworkMember {
      active_bridge: params.active_bridge,
      address: params.address,
      authorized: params.authorized,
      id: params.id,
      identity: params.identity,
      ip_assignments: params.ip_assignments,
      nwid: params.nwid,
      revision: params.revision,
      v_major: params.v_major,
      v_minor: params.v_minor,
      v_proto: params.v_proto,
      v_rev: params.v_rev,
    }
  }
}

#[derive(Debug, Parser)]
struct CtrlNetMemTagArgs {
  tag: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct CtrlNetMemTagStates {
  tags: HashMap<String, String>,
}

impl Apply for CtrlNetMemTagArgs {
  type Context = String;
  type PersistentState = CtrlNetMemTagStates;

  async fn apply(self, id: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    if let Some(tag) = self.tag {
      if tag.is_empty() {
        ps.tags.remove(&id);
        log::info!("Tag removed for {}", id);
      } else {
        ps.tags.insert(id.clone(), tag.clone());
        log::info!("Tag set for {}: {}", id, tag);
      }
    } else if let Some(tag) = ps.tags.get(&id) {
      pretty_print(tag);
    } else {
      log::info!("No tag found for {}", id);
    }
    Ok(())
  }
}

#[derive(Debug, Parser)]
enum PeerCmds {
  /// List all peers
  List,

  /// Show information about a specific peer
  Info(PeerInfoArgs),
}

impl Apply for PeerCmds {
  type Context = Client;
  type PersistentState = ();

  async fn apply(self, client: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    match self {
      Self::List => {
        let r = client.get_peers().await?;
        log::info!("Peers information: {:?}", r);
        for i in r {
          pretty_print(&i);
        }
        Ok(())
      }
      Self::Info(args) => args.apply(client, ps).await,
    }
  }
}

#[derive(Debug, Parser)]
struct PeerInfoArgs {
  #[clap(long, short)]
  /// ID of the peer to operate on
  peer_id: String,
}

impl Apply for PeerInfoArgs {
  type Context = Client;
  type PersistentState = ();

  async fn apply(self, client: Self::Context, _: &mut Self::PersistentState) -> anyhow::Result<()> {
    let r = client.get_peer(&self.peer_id).await?;
    log::info!("Peer information: {:?}", r);
    pretty_print(&r);
    Ok(())
  }
}

#[derive(Debug, Parser)]
enum NetCmds {
  /// List all networks
  List,

  /// Get information about a specific network or edit it
  Edit(NetEditArgs),
}

impl Apply for NetCmds {
  type Context = Client;
  type PersistentState = ();

  async fn apply(self, client: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    match self {
      Self::List => {
        let r = client.get_networks().await?;
        log::info!("Networks information: {:?}", r);
        for i in r {
          pretty_print(&i);
        }
        Ok(())
      }
      Self::Edit(args) => args.apply(client, ps).await,
    }
  }
}

#[derive(Debug, Parser)]
struct NetEditArgs {
  #[clap(long, short)]
  /// ID of the network to operate on
  network_id: String,

  #[clap(subcommand)]
  cmd: NetEditCmds,
}

impl Apply for NetEditArgs {
  type Context = Client;
  type PersistentState = ();

  async fn apply(self, client: Self::Context, ps: &mut Self::PersistentState) -> anyhow::Result<()> {
    self.cmd.apply((client, self.network_id), ps).await
  }
}

#[derive(Debug, Parser)]
enum NetEditCmds {
  /// Show information about a specific network
  Info,

  /// Join a network or Update an existing network
  Update(Box<NetParams>),

  /// Leave a network
  Delete,
}

impl Apply for NetEditCmds {
  type Context = (Client, String);
  type PersistentState = ();

  async fn apply(self, (client, network_id): Self::Context, _: &mut Self::PersistentState) -> anyhow::Result<()> {
    match self {
      Self::Info => {
        let r = client.get_network(&network_id).await?;
        log::info!("Network information: {:?}", r);
        pretty_print(&r);
      }
      Self::Update(args) => {
        let body = (*args).into();
        let r = client.update_network(&network_id, &body).await?;
        log::info!("Network joined or updated successfully: {:?}", r);
        pretty_print(&r);
      }
      Self::Delete => {
        client.delete_network(&network_id).await?;
        log::info!("Network deleted successfully");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Parser)]
struct NetParams {
  #[clap(long)]
  /// Let ZeroTier modify the system's default route
  allow_default: Option<bool>,

  #[clap(long)]
  /// Let ZeroTier modify the system's DNS settings
  allow_dns: Option<bool>,

  #[clap(long)]
  /// Let ZeroTier manage IP addresses and Route assignments that aren't in private ranges (rfc1918)
  allow_global: Option<bool>,

  #[clap(long)]
  /// Let ZeroTier to manage IP addresses and Route assignments.
  allow_managed: Option<bool>,

  #[clap(long)]
  /// Assigned IP addresses for the network
  assigned_addresses: Vec<String>,

  #[clap(long)]
  /// Whether the network is bridged
  bridge: Option<bool>,

  #[clap(long)]
  /// Whether the network broadcasts packets
  broadcast_enabled: Option<bool>,

  #[clap(long)]
  /// ID of the network
  id: Option<String>,

  #[clap(long)]
  /// MAC address for this network's interface
  mac: Option<String>,

  #[clap(long)]
  /// Maximum Transmission Unit (MTU) for the network
  mtu: Option<i64>,

  #[clap(long)]
  multicast_subscriptions: Vec<String>,

  #[clap(long)]
  /// Name of the network
  name: Option<String>,

  #[clap(long)]
  netconf_revision: Option<i64>,

  #[clap(long)]
  port_device_name: Option<String>,

  #[clap(long)]
  port_error: Option<i64>,

  #[clap(long)]
  /// Status of the network
  status: Option<String>,

  #[clap(long)]
  /// Type of the network
  type_: Option<String>,
}

impl From<NetParams> for crate::ztapi::types::Network {
  fn from(params: NetParams) -> Self {
    // Convert NetParams to Network
    crate::ztapi::types::Network {
      allow_default: params.allow_default,
      allow_dns: params.allow_dns,
      allow_global: params.allow_global,
      allow_managed: params.allow_managed,
      assigned_addresses: params.assigned_addresses,
      bridge: params.bridge,
      broadcast_enabled: params.broadcast_enabled,
      dns: None, // FIXME:
      id: params.id,
      mac: params.mac,
      mtu: params.mtu,
      multicast_subscriptions: params
        .multicast_subscriptions
        .iter()
        .map(|v| crate::ztapi::types::NetworkSubtype1MulticastSubscriptionsItem {
          adi: None, // FIXME:
          mac: Some(v.clone()),
        })
        .collect::<Vec<_>>(),
      name: params.name,
      netconf_revision: params.netconf_revision,
      port_device_name: params.port_device_name,
      port_error: params.port_error,
      routes: vec![], // FIXME:
      status: params.status,
      type_: params.type_,
    }
  }
}
