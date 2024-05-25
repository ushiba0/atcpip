use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Result;
use rand::Rng;
use tokio::{
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};

pub async fn main() -> Result<()> {
    let mut socket = crate::layer4::udp::UdpSocket::bind([127, 0, 0, 1], 1234).await?;
    loop {
        let (source_ip, bytes) = socket.recv_from().await;
        let message = std::str::from_utf8(&bytes)?;
        println!("[UDP Data from {source_ip:?}] {}", message);
    }
    Ok(())
}
