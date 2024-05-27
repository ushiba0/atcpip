use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{ensure, Context};
use bytes::{BufMut, Bytes, BytesMut};
use once_cell::sync::Lazy;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::layer3::ipv4::Ipv4Frame;

// https://datatracker.ietf.org/doc/html/rfc768
#[derive(Debug, Default, PartialEq, Clone)]
pub struct UdpPacket {
    source_port: u16,
    target_port: u16,
    length: u16,
    checksum: u16,
    payload: Bytes,
}

#[derive(Debug)]
pub struct UdpSocket {
    receiver: Receiver<(SocketAddr, Bytes)>,
    local_port: u16,
}

impl UdpPacket {
    pub fn from_bytes(bytes: &Bytes) -> Self {
        Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            target_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: bytes.slice(8..),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u16(self.source_port);
        bytes.put_u16(self.target_port);
        bytes.put_u16(self.length);
        bytes.put_u16(self.checksum);
        bytes.put(self.payload.clone());
        bytes.freeze()
    }
}

// 下位のレイヤから UDP パケットが来たら、この Hashmap の Sender で送る。
// Listen しているユーザーアプリケーションは Receiver で受け取る。
pub static PORT_MAP: Lazy<parking_lot::RwLock<HashMap<u16, Sender<(SocketAddr, Bytes)>>>> =
    Lazy::new(Default::default);

impl UdpSocket {
    pub fn bind(_ip: Ipv4Addr, port: u16) -> anyhow::Result<Self> {
        let mut portmap = PORT_MAP.write();
        ensure!(portmap.get(&port).is_none(), "Address already in use.");

        let (rx_sender, rx_receiver) = mpsc::channel::<(SocketAddr, Bytes)>(2);
        portmap.insert(port, rx_sender);

        log::info!("Listening UDP on port {port}.");
        Ok(Self {
            receiver: rx_receiver,
            local_port: port,
        })
    }

    pub async fn recv_from(&mut self) -> (std::net::SocketAddrV4, Bytes) {
        let (std_sockaddr, bytes) = self.receiver.recv().await.unwrap();
        let std_sock = match std_sockaddr {
            std::net::SocketAddr::V4(v) => v,
            std::net::SocketAddr::V6(_) => unimplemented!(),
        };
        (std_sock, bytes)
    }

    pub async fn send_to(&self, bytes: Bytes, addr: std::net::SocketAddrV4) -> anyhow::Result<()> {
        // Todo: MTU を考慮してパケットを分割して送る。なくてもいい。

        const UDP_HEADER_SIZE: u16 = 8;
        let target_ip = addr.ip();

        let udp_pkt = UdpPacket {
            source_port: self.local_port,
            target_port: addr.port(),
            length: bytes.len() as u16 + UDP_HEADER_SIZE,
            checksum: 0, // Todo: Checksum の計算.
            payload: bytes,
        };
        
        crate::layer3::ipv4::send_udp(udp_pkt, target_ip).await
    }
}

pub async fn udp_handler(mut receiver: Receiver<Ipv4Frame>) -> anyhow::Result<()> {
    loop {
        let ipv4_frame = receiver.recv().await.context("closed")?;
        let source_ip = ipv4_frame.get_source_address();
        let udp_packet = UdpPacket::from_bytes(&ipv4_frame.payload);

        // Todo: Checksum の計算

        // sender を clone して使わない場合、RwLock が sender().send().await() を跨ぐ
        // ことになりコンパイルエラーとなる。
        let sender = match PORT_MAP.read().get(&udp_packet.target_port) {
            Some(v) => v.clone(),
            None => {
                log::warn!("[udp_handler] listen していない port 宛に UDP パケットが来た。");
                continue;
            }
        };
        let std_sockaddrv4 = std::net::SocketAddrV4::new(source_ip, udp_packet.source_port);
        let std_sockaddr = std::net::SocketAddr::from(std_sockaddrv4);
        sender
            .send((std_sockaddr, udp_packet.payload))
            .await
            .unwrap();
    }
}
