use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Result;

pub async fn main(port: u16) -> Result<()> {
    let listen_addr = Ipv4Addr::from_str("127.0.0.1")?;
    let mut socket = crate::layer4::udp::UdpSocket::bind(listen_addr, port)?;
    loop {
        let (source_ip, bytes) = socket.recv_from().await;
        match std::str::from_utf8(&bytes) {
            Ok(msg) => println!("[UDP Data from {source_ip:?}] {:?}", msg),
            Err(_) => println!("[UDP Data from {source_ip:?}] {:?}", bytes),
        }
        socket.send_to(bytes, source_ip).await?;
    }
}
