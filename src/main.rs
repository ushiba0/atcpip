use clap::{Parser, Subcommand};

use crate::ethernet::EthernetFrame;
use std::net::Ipv4Addr;
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

trait OptionExt<T> {
    async fn unwrap_or_yield(self) -> T;
}

impl<T> OptionExt<T> for Option<T> {
    async fn unwrap_or_yield( self) -> T {
        const COUNT_WARN_THRESHOULD: usize = 10usize;
        let mut count = 0usize;
        loop {
            if let Some(value) = self {
                return value;
            } else {
                // tokio::task::yield_now().await;
                use tokio::time::{sleep, Duration};
                    sleep(Duration::from_millis(20)).await;
            }
            count += 1;
            if count > COUNT_WARN_THRESHOULD {
                log::warn!("{:?}", anyhow::anyhow!("spin!!!!!!!"));
            }
        }
    }
}

// #[tokio::main(flavor = "current_thread")]
#[tokio::main(flavor = "multi_thread", worker_threads = 1)]
async fn main() -> anyhow::Result<()> {
    let cli_cmds = CommandArguments::parse();
    set_loglevel(&cli_cmds);

    // Datalink tx and rx from pnet crate.
    let (tx, rx) = crate::interface::get_channel().await?;
    let (iface_send, iface_recv) = broadcast::channel::<EthernetFrame>(2);

    let iface_send3 = iface_send.clone();
    crate::interface::spawn_tx_handler(iface_recv, iface_send3, tx, rx).await;

    let handle = match cli_cmds.second_command {
        SecondCommand::Arping(opts) => {
            // Call arping.
            let ip = opts.ipv4_address.parse::<Ipv4Addr>()?;
            log::info!("Destination IP Address: {ip:?}");

            tokio::spawn(async move { crate::arping::main(ip).await })
            // std::process::exit(0);
        }
        SecondCommand::Ping(opts) => {
            let ip = opts.ipv4_address.parse::<Ipv4Addr>()?;
            log::info!("Destination IP Address: {ip:?}");
            tokio::spawn(async move { crate::pingcmd::main(ip).await })
        }
        SecondCommand::Server => {
            use tokio::time::{sleep, Duration};
            tokio::spawn(async move {
                sleep(Duration::from_millis(1000 * 60)).await;
                Ok(())
            })
        }
        _ => unimplemented!(),
    };

    tokio::spawn(async move {
        let result = handle.await;
        log::info!("{result:?}");
        std::process::exit(0);
    });

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            log::info!("Signal received. Graceful Shutdown.");
        }
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        }
    }

    Ok(())
}
