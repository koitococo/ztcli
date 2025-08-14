use std::{fmt::Display, fs};

use clap::{CommandFactory, Parser as _};

mod cli;
mod ztapi;

fn pretty_print<T: Display>(obj: &T) {
  eprintln!("{}", obj);
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
  if fs::exists(".env")? {
    let _ = dotenvy::dotenv()?;
  }

  env_logger::init();

  let cli = cli::Args::parse();
  let Some(token) = cli.token.or_else(|| match std::fs::read_to_string(&cli.token_path) {
    Ok(content) => Some(content),
    Err(e) => {
      log::error!("Failed to read token from path: {:?}", e);
      None
    }
  }) else {
    return Err(anyhow::anyhow!("No authentication token provided"));
  };

  let client = ztapi::Client::new(cli.endpoint.as_str(), &token)?;

  match cli.cmd {
    cli::Command::Completions(args) => {
      clap_complete::generate(
        args.shell,
        &mut cli::Args::command(),
        std::env::current_exe()?
          .file_name()
          .map(|v| v.to_string_lossy().to_string())
          .unwrap_or("ztcli".to_string()),
        &mut std::io::stdout(),
      );
    }
    cli::Command::Status => {
      let r = client.get_status().await?;
      log::info!("Node status: {:?}", r);
      pretty_print(&r);
    }
    cli::Command::Controller(cmd) => match cmd {
      cli::CtrlCmds::Status => {
        let r = client.get_controller_status().await?;
        log::info!("Controller status: {:?}", r);
        pretty_print(&r);
      }
      cli::CtrlCmds::List => {
        let r = client.get_controller_networks().await?;
        log::info!("Controller networks: {:?}", r);
        for i in r {
          pretty_print(&i);
        }
      }
      cli::CtrlCmds::Network(net) => match net.cmd {
        cli::CtrlNetCmds::Create(args) => {
          let r = client.generate_controller_network(&net.network_id, &(*args).into()).await?;
          log::info!("Network created successfully: {:?}", r);
          pretty_print(&r);
        }
        cli::CtrlNetCmds::Update(args) => {
          let r = client.set_controller_network(&net.network_id, &(*args).into()).await?;
          log::info!("Network updated successfully: {:?}", r);
          pretty_print(&r);
        }
        cli::CtrlNetCmds::Member(member) => match member.cmd {
          cli::CtrlNetMemCmds::Info => {
            let r = client.get_controller_network_member(&net.network_id, &member.member_id).await?;
            log::info!("Member information: {:?}", r);
            pretty_print(&r);
          }
          cli::CtrlNetMemCmds::Update(params) => {
            let body = (*params).into();
            let r = client.update_controller_network_member(&net.network_id, &member.member_id, &body).await?;
            log::info!("Member information: {:?}", r);
            pretty_print(&r);
          }
        },
        cli::CtrlNetCmds::Info => {
          let r = client.get_controller_network(&net.network_id).await?;
          log::info!("Network information: {:?}", r);
          pretty_print(&r);
        }
        cli::CtrlNetCmds::Members => {
          let r = client.get_controller_network_members(&net.network_id).await?;
          log::info!("Members information: {:?}", r);
          for (k, v) in r {
            println!("{}: {}", k, v);
          }
        }
      },
    },
    cli::Command::Peer(cmd) => match cmd {
      cli::PeerCmds::List => {
        let r = client.get_peers().await?;
        log::info!("Peers information: {:?}", r);
        for i in r {
          pretty_print(&i);
        }
      }
      cli::PeerCmds::Info(info) => {
        let r = client.get_peer(&info.peer_id).await?;
        log::info!("Peer information: {:?}", r);
        pretty_print(&r);
      }
    },
    cli::Command::Network(cmd) => match cmd {
      cli::NetCmds::List => {
        let r = client.get_networks().await?;
        log::info!("Networks information: {:?}", r);
        for i in r {
          pretty_print(&i);
        }
      }
      cli::NetCmds::Edit(args) => {
        let net_id = args.network_id;
        match args.cmd {
          cli::NetEditCmds::Info => {
            let r = client.get_network(&net_id).await?;
            log::info!("Network information: {:?}", r);
            pretty_print(&r);
          }
          cli::NetEditCmds::Update(args) => {
            let body = (*args).into();
            let r = client.update_network(&net_id, &body).await?;
            log::info!("Network joined or updated successfully: {:?}", r);
            pretty_print(&r);
          }
          cli::NetEditCmds::Delete => {
            client.delete_network(&net_id).await?;
            log::info!("Network deleted successfully");
          }
        }
      }
    },
  }
  Ok(())
}
