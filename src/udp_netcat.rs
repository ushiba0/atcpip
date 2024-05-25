use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Result;

pub async fn main() -> Result<()> {
    let listen_addr = Ipv4Addr::from_str("127.0.0.1")?;
    let mut socket = crate::layer4::udp::UdpSocket::bind(listen_addr, 1234).await?;
    loop {
        let (source_ip, bytes) = socket.recv_from().await;
        let message = std::str::from_utf8(&bytes)?;
        println!("[UDP Data from {source_ip:?}] {:?}", message);
    }
}
