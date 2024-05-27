use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Result;
use bytes::Bytes;

pub async fn main(remote_port: u16) -> Result<()> {
    let listen_addr = Ipv4Addr::from_str("127.0.0.1")?;
    let local_port = 18294;

    let std_ipaddr = std::net::Ipv4Addr::new(192, 168, 1, 237);
    let std_sockaddr = std::net::SocketAddrV4::new(std_ipaddr, remote_port);
    let mut socket = crate::layer4::udp::UdpSocket::bind(listen_addr, local_port)?;

    let test_data = Bytes::copy_from_slice(&vec![0xabu8; 20000]);

    socket.send_to(test_data.clone(), std_sockaddr).await?;
    let (sockaddr, response_bytes) = socket.recv_from().await;
    log::info!("[UDP echo client]: reply from {sockaddr} msg: {:?}", &response_bytes);

    if test_data == response_bytes {
        println!("UDP echo server verify ok.");
    }else {
        println!("UDP echo server verify failed. Response data is not match.");
    }
    Ok(())
}
