use clap::Parser;

#[derive(Debug, Parser)]
#[clap(name = "ztcli", version = "0.1.0")]
pub(crate) struct Args {
  #[clap(long = "token", short = 'a', env = "TOKEN")]
  /// Authentication token for the ZeroTier API
  pub(crate) token: Option<String>,

  #[clap(
    long = "token-path",
    short = 'p',
    env = "TOKEN_PATH",
    default_value = "/var/lib/zerotier-one/authtoken.secret"
  )]
  /// Path to the file containing the ZeroTier API authentication token
  pub(crate) token_path: String,

  #[clap(
    long = "endpoint",
    short = 'e',
    env = "ENDPOINT",
    default_value = "http://localhost:9993"
  )]
  /// Base URL for the ZeroTier API endpoint
  pub(crate) endpoint: String,

  #[clap(subcommand)]
  pub(crate) cmd: Command,
}

#[derive(Debug, Parser)]
pub(crate) enum Command {
  /// Show status of the node
  Status,

  /// Manage network controller
  #[clap(subcommand)]
  Controller(CtrlCmds),

  /// Manage networks
  #[clap(subcommand)]
  Network(NetCmds),

  /// Manage peers
  #[clap(subcommand)]
  Peer(PeerCmds),
}

#[derive(Debug, Parser)]
pub(crate) enum CtrlCmds {
  /// Show status of the controller
  Status,

  /// List all networks managed by the controller
  List,

  /// Manage controller networks
  Network(CtrlNetArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct CtrlNetArgs {
  #[clap(long = "id", short = 'n')]
  /// ID of the network to operate on
  pub(crate) network_id: String,

  #[clap(subcommand)]
  pub(crate) cmd: CtrlNetCmds,
}

#[derive(Debug, Parser)]
pub(crate) enum CtrlNetCmds {
  /// Create a new network
  Create(Box<CtrlNetParams>),

  /// Update an existing network
  Update(Box<CtrlNetParams>),

  /// Delete an existing network
  Delete,

  /// Manage network members
  Member(CtrlNetMemArgs),

  /// Show details of the network
  Info,

  /// List all members of the network
  Members,
}

#[derive(Debug, Parser)]
pub(crate) struct CtrlNetParams {
  #[clap(long)]
  /// Creation time of the network
  pub(crate) creation_time: Option<f64>,

  #[clap(long)]
  /// Enable broadcast on the network
  pub(crate) enable_broadcast: Option<bool>,

  #[clap(long)]
  /// ID of the network
  pub(crate) id: Option<String>,

  #[clap(long)]
  /// IP assignment pools for the network
  /// Format: "start-end", e.g., "192.168.1.1-192.168.1.254"
  pub(crate) ip_assignment_pools: Vec<String>,

  #[clap(long)]
  /// MTU (Maximum Transmission Unit) for the network
  pub(crate) mtu: Option<i64>,

  #[clap(long)]
  /// Multicast limit for the network
  pub(crate) multicast_limit: Option<i64>,

  #[clap(long)]
  /// Name of the network
  pub(crate) name: Option<String>,

  #[clap(long)]
  /// Network ID (nwid) for the network
  pub(crate) nwid: Option<String>,

  #[clap(long)]
  /// Object type for the network
  pub(crate) objtype: Option<String>,

  #[clap(long)]
  /// Whether the network is private
  /// If true, the network is private and every member must be explicitly authorized
  /// If false, the network is public and any member can join
  pub(crate) private: Option<bool>,

  #[clap(long)]
  /// Remote trace level for the network
  pub(crate) remote_trace_level: Option<i64>,

  #[clap(long)]
  /// Remote trace target for the network
  pub(crate) remote_trace_target: Option<String>,

  #[clap(long)]
  /// Revision number for the network
  pub(crate) revision: Option<i64>,

  #[clap(long)]
  /// Routes for the network
  /// Format: "target", e.g., "192.168.1.0/24"
  /// Currently, 'via' is not supported
  pub(crate) routes: Vec<String>,

  #[clap(long)]
  /// V4 assign mode for the network
  pub(crate) v4_assign_mode: Option<bool>,

  #[clap(long)]
  /// V6 assign mode for the network
  pub(crate) v6_assign_mode_6plane: Option<bool>,

  #[clap(long)]
  /// V6 assign mode for the network using RFC 4193
  pub(crate) v6_assign_mode_rfc4193: Option<bool>,

  #[clap(long)]
  /// V6 assign mode for the network using ZeroTier's own method
  pub(crate) v6_assign_mode_zt: Option<bool>,
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
pub(crate) struct CtrlNetMemArgs {
  #[clap(long = "id", short = 'i')]
  /// ID of the member to operate on
  pub(crate) member_id: String,

  #[clap(subcommand)]
  pub(crate) cmd: CtrlNetMemCmds,
}

#[derive(Debug, Parser)]
#[clap(value_enum)]
pub(crate) enum CtrlNetMemCmds {
  /// Show member information
  Info,

  Update(Box<CtrlNetMemParams>),
}

#[derive(Debug, Parser)]
pub(crate) struct CtrlNetMemParams {
  #[clap(long)]
  /// Active bridge status for the member
  pub(crate) active_bridge: Option<bool>,

  #[clap(long)]
  /// Address of the member
  pub(crate) address: Option<String>,

  #[clap(long)]
  /// Whether the member is authorized
  pub(crate) authorized: Option<bool>,

  #[clap(long)]
  /// ID of the member
  pub(crate) id: Option<String>,

  #[clap(long)]
  /// Identity of the member
  pub(crate) identity: Option<String>,

  #[clap(long)]
  /// IP assignments for the member
  pub(crate) ip_assignments: Vec<String>,

  #[clap(long)]
  /// Network ID (nwid) for the member
  pub(crate) nwid: Option<String>,

  #[clap(long)]
  /// Revision number for the member
  pub(crate) revision: Option<i64>,

  #[clap(long)]
  /// Major version of the member
  pub(crate) v_major: Option<i64>,

  #[clap(long)]
  /// Minor version of the member
  pub(crate) v_minor: Option<i64>,

  #[clap(long)]
  /// Protocol version of the member
  pub(crate) v_proto: Option<i64>,

  #[clap(long)]
  /// Revision version of the member
  pub(crate) v_rev: Option<i64>,
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
pub(crate) enum PeerCmds {
  /// List all peers
  List,

  /// Show information about a specific peer
  Info(PeerInfoArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct PeerInfoArgs {
  #[clap(long = "id", short = 'i')]
  /// ID of the peer to operate on
  pub(crate) peer_id: String,
}

#[derive(Debug, Parser)]
pub(crate) enum NetCmds {
  /// List all networks
  List,

  /// Show information about a specific network
  Info(NetInfoArgs),

  /// Update an existing network
  Update(NetUpdateArgs),
}

#[derive(Debug, Parser)]
pub(crate) struct NetInfoArgs {
  #[clap(long = "id", short = 'n')]
  /// ID of the network to operate on
  pub(crate) network_id: String,
}

#[derive(Debug, Parser)]
pub(crate) struct NetUpdateArgs {
  #[clap(long = "id", short = 'n')]
  /// ID of the network to operate on
  pub(crate) network_id: String,
  #[clap(flatten)]
  pub(crate) params: Box<NetParams>,
}

#[derive(Debug, Parser)]
pub(crate) struct NetParams {
  #[clap(long)]
  pub(crate) allow_default: Option<bool>,

  #[clap(long)]
  pub(crate) allow_dns: Option<bool>,

  #[clap(long)]
  pub(crate) allow_global: Option<bool>,

  #[clap(long)]
  pub(crate) allow_managed: Option<bool>,

  #[clap(long)]
  /// Assigned IP addresses for the network
  pub(crate) assigned_addresses: Vec<String>,

  #[clap(long)]
  /// Whether the network is bridged
  pub(crate) bridge: Option<bool>,

  #[clap(long)]
  /// Whether the network broadcasts packets
  pub(crate) broadcast_enabled: Option<bool>,

  #[clap(long)]
  /// ID of the network
  pub(crate) id: Option<String>,

  #[clap(long)]
  /// MAC address for the network
  pub(crate) mac: Option<String>,

  #[clap(long)]
  /// Maximum Transmission Unit (MTU) for the network
  pub(crate) mtu: Option<i64>,

  #[clap(long)]
  pub(crate) multicast_subscriptions: Vec<String>,

  #[clap(long)]
  /// Name of the network
  pub(crate) name: Option<String>,

  #[clap(long)]
  pub(crate) netconf_revision: Option<i64>,

  #[clap(long)]
  pub(crate) port_device_name: Option<String>,

  #[clap(long)]
  pub(crate) port_error: Option<i64>,

  #[clap(long)]
  /// Status of the network
  pub(crate) status: Option<String>,

  #[clap(long)]
  /// Type of the network
  pub(crate) type_: Option<String>,
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
