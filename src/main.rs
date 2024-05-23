use clap::{Parser, Subcommand};

use std::net::Ipv4Addr;

mod arping;
mod pingcmd;

mod layer2;
mod layer3;

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
            tokio::spawn(async move {
                crate::pingcmd::main(ip, opts.count, opts.timeout_ms, opts.size).await
            })
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
        match handle.await {
            Ok(inner) => match inner {
                // タスク、コマンドともに正常終了.
                Ok(a) => log::info!("Ok: {a:?}"),
                // タスクは正常終了したが、タスクの戻り値がエラー。
                Err(e) => log::error!("{e:?}"),
            },
            //コマンドを実行したタスクが panic したか、またはランタイムのシャットダウンでタスクが強制終了した。
            Err(e) => log::error!("Task end with error: {e:?}"),
        }
        std::process::exit(0);
    });

    // Call an shutdown handler,
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            log::info!("Signal received. Graceful Shutdown.");
            Ok(())
        }
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
            Err(anyhow::anyhow!("{err:?}"))
        }
    }
}

#[macro_export]
macro_rules! unwrap_or_yield {
    ($global_var:expr, $method:ident) => {
        loop {
            let a = $global_var.lock().await;
            match a.as_ref() {
                Some(value) => break value.$method(),
                None => tokio::task::yield_now().await,
            }
        }
    };
}
