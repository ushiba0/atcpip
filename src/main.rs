use anyhow::Context;
use clap::{Parser, Subcommand};

use std::net::Ipv4Addr;

mod arping;
mod common;
mod pingcmd;
mod syn_flood_attack;
mod tokio_tcp_server;
mod udp_echo;
mod udp_echo_verify;

mod layer2;
mod layer3;
mod layer4;

#[derive(Debug, Parser)]
struct CommandArguments {
    #[clap(subcommand)]
    second_command: SecondCommand,

    /// Print info level log.
    #[clap(short, long)]
    info: bool,

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
    /// Send ICMP Echo requests.
    Ping(PingCLIOpts),
    /// TCP Server.
    Server,
    /// TCP Client.
    Client,
    /// TCP SYN Flood attack.
    /// !!!!Warning!!!! This is only for testing and learning purposes.
    SynFloodAttack(AddrAndPort),
    /// Tokio TCP Server.
    TokioTcpServer,
    /// UDP echo Server.
    UdpEchoServer(UdpEchoOpts),
    /// UDP echo veririer.
    UdpEchoVerify,
    /// UDP Client.
    UdpClient,
}

#[derive(Debug, Parser)]
struct PingCLIOpts {
    /// IPv4 Address.
    ipv4_address: String,

    /// Stop after <count> replies.
    #[clap(short, long, default_value = "0")]
    count: usize,

    /// Echo reply timeout in ms.
    #[clap(long, default_value = "1000")]
    timeout_ms: u64,

    /// ICMP payload size in bytes.
    #[clap(short, long, default_value = "20")]
    size: usize,
}

#[derive(Debug, Parser)]
struct UdpEchoOpts {
    /// Listen port.
    #[clap(short, long, default_value = "1234")]
    port: u16,
}

#[derive(Debug, Parser)]
struct AddrAndPort {
    /// Target address.
    #[clap(short, long)]
    address: Ipv4Addr,

    /// Target port.
    #[clap(short, long)]
    port: u16,
}

fn set_loglevel(cli_cmds: &CommandArguments) {
    std::env::set_var("RUST_LOG", "NONE");
    if cli_cmds.info {
        std::env::set_var("RUST_LOG", "info");
    }
    if cli_cmds.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    if cli_cmds.trivia {
        std::env::set_var("RUST_LOG", "trace");
    }

    // Setup logging.
    env_logger::builder().format_timestamp_millis().init();
}

// #[tokio::main(flavor = "current_thread")]
#[tokio::main(flavor = "multi_thread", worker_threads = 1)]
async fn main() -> anyhow::Result<()> {
    let cli_cmds = CommandArguments::parse();
    set_loglevel(&cli_cmds);

    crate::layer2::interface::spawn_tx_handler().await;

    let cmd_handle = tokio::spawn(async move {
        match cli_cmds.second_command {
            SecondCommand::Arping(opts) => {
                let ip = opts.ipv4_address.parse::<Ipv4Addr>()?;
                log::info!("Destination IP Address: {ip:?}");
                crate::arping::main(ip).await
            }
            SecondCommand::Ping(opts) => {
                let ip = opts.ipv4_address.parse::<Ipv4Addr>()?;
                log::info!("Destination IP Address: {ip:?}");
                crate::pingcmd::main(ip, opts.count, opts.timeout_ms, opts.size).await
            }
            SecondCommand::Server => {
                use tokio::time::{sleep, Duration};
                async fn testfunc() -> anyhow::Result<()> {
                    sleep(Duration::from_millis(1000 * 60)).await;
                    Ok(())
                }
                testfunc().await
            }
            SecondCommand::UdpClient => unimplemented!(),
            SecondCommand::UdpEchoServer(opts) => crate::udp_echo::main(opts.port).await,
            SecondCommand::UdpEchoVerify => crate::udp_echo_verify::main(1234).await,
            SecondCommand::SynFloodAttack(opts) => {
                crate::syn_flood_attack::main(opts.address, opts.port).await
            }
            SecondCommand::TokioTcpServer => crate::tokio_tcp_server::main().await,
            _ => unimplemented!(),
        }
    });

    tokio::spawn(async move {
        match cmd_handle.await {
            Ok(_) => log::info!("Ok"),
            Err(e) => log::error!("Command end with error: {e:?}"),
        }
        std::process::exit(0);
    });

    tokio::signal::ctrl_c().await.context("Signal handler err.")
}
