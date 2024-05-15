use clap::{Parser, Subcommand};

use crate::ethernet::EthernetFrame;
use tokio::sync::broadcast::{self};

mod arp;
mod arping;
mod ethernet;
mod icmp;
mod interface;
mod ipv4;
mod pingcmd;

#[derive(Debug, Parser)]
struct CommandArguments {
    #[clap(subcommand)]
    second_command: SecondCommand,

    /// Print verbose log.
    #[clap(short, long)]
    verbose: bool,

    /// Print more verbose log.
    #[clap(short, long)]
    trivia: bool,
}

/// document.
#[derive(Debug, Subcommand)]
enum SecondCommand {
    /// Send ARP requests.
    Arping(PingCLIOpts),
    /// ICMP Ping を送信する.
    Ping(PingCLIOpts),
    /// TCP Server.
    Server,
    /// TCP Client.
    Client,
}

#[derive(Debug, Parser)]
struct PingCLIOpts {
    /// IPv4 Address.
    ipv4_address: String,
}

fn set_loglevel(cli_cmds: &CommandArguments) {
    std::env::set_var("RUST_LOG", "NONE");
    if cli_cmds.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    if cli_cmds.trivia {
        std::env::set_var("RUST_LOG", "trace");
    }

    // Setup logging.
    env_logger::builder().format_timestamp_millis().init();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli_cmds = CommandArguments::parse();
    set_loglevel(&cli_cmds);

    // Datalink tx and rx from pnet crate.
    let (tx, rx) = crate::interface::get_channel().await?;
    let (iface_send, iface_recv) = broadcast::channel::<EthernetFrame>(2);

    let iface_send3 = iface_send.clone();
    crate::interface::spawn_tx_handler(iface_recv, iface_send3, tx, rx).await;

    use std::net::Ipv4Addr;

    match cli_cmds.second_command {
        SecondCommand::Arping(opts) => {
            // Call arping.
            let ip = opts.ipv4_address.parse::<Ipv4Addr>()?;
            log::info!("Destination IP Address: {ip:?}");
            crate::arping::main(ip).await?;
            std::process::exit(0);
        }
        SecondCommand::Ping(opts) => {
            let ip = opts.ipv4_address.parse::<Ipv4Addr>()?;
            log::info!("Destination IP Address: {ip:?}");
            crate::pingcmd::main(ip).await?;
            std::process::exit(0);
        }
        SecondCommand::Server => {}
        _ => unimplemented!(),
    }

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            log::info!("Graceful Shutdown.");
        }
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        }
    }

    Ok(())
}
