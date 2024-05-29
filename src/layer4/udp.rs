use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{ensure, Context};
use bytes::{BufMut, Bytes, BytesMut};
use once_cell::sync::Lazy;
use parking_lot::RwLock;

use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::layer3::ipv4::Ipv4Packet;

pub static UDP_CHANNEL: Lazy<
    parking_lot::RwLock<(
        broadcast::Sender<Ipv4Packet>,
        broadcast::Receiver<Ipv4Packet>,
    )>,
> = Lazy::new(|| {
    let (udp_ch_sender, udp_ch_receiver) = broadcast::channel::<Ipv4Packet>(2);
    RwLock::new((udp_ch_sender, udp_ch_receiver))
});

const UDP_HEADER_SIZE: usize = 8;

// https://datatracker.ietf.org/doc/html/rfc768
#[derive(Debug, Default, PartialEq, Clone)]
pub struct UdpPacket {
    bytes: Bytes,
}

// https://datatracker.ietf.org/doc/html/rfc768
#[derive(Debug, Default, PartialEq, Clone)]
pub struct UdpPacketUnverified {
    bytes: BytesMut,
}

#[derive(Debug)]
pub struct UdpSocket {
    receiver: Receiver<(SocketAddr, Bytes)>,
    local_port: u16,
}

impl UdpPacket {
    pub fn from_bytes(bytes: &Bytes) -> Self {
        Self {
            bytes: bytes.clone(),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    crate::impl_get!(get_source_port, bytes, 0, 2, u16);
    crate::impl_get!(get_target_port, bytes, 2, 4, u16);
    crate::impl_get!(get_length, bytes, 4, 6, u16);
    crate::impl_get!(get_checksum, bytes, 6, 8, u16);

    pub fn get_payload(&self) -> Bytes {
        self.bytes.slice(8..)
    }
}

impl UdpPacketUnverified {
    pub fn new() -> Self {
        Self {
            bytes: BytesMut::zeroed(8),
        }
    }

    crate::impl_set!(set_source_port, bytes, 0, 2, u16);
    crate::impl_set!(set_target_port, bytes, 2, 4, u16);
    crate::impl_set!(set_length, bytes, 4, 6, u16);
    crate::impl_set!(set_checksum, bytes, 6, 8, u16);

    pub fn set_payload(&mut self, payload: &Bytes) -> &Self {
        debug_assert_eq!(self.bytes.len(), UDP_HEADER_SIZE);
        self.bytes.put(payload.clone());
        self
    }

    pub fn freeze(&self) -> UdpPacket {
        UdpPacket {
            bytes: self.bytes.clone().freeze(),
        }
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

        let target_ip = addr.ip();

        let mut udp_pkt_unckecked = UdpPacketUnverified::new();
        udp_pkt_unckecked
            .set_source_port(self.local_port)
            .set_target_port(addr.port())
            .set_length(bytes.len() as u16)
            .set_checksum(0)
            .set_payload(&bytes);
        let udp_pkt = udp_pkt_unckecked.freeze();

        crate::layer3::ipv4::send_udp(udp_pkt, target_ip).await
    }
}

pub async fn udp_handler() -> anyhow::Result<()> {
    log::info!("Spawned UDP handler.");
    let mut receiver = UDP_CHANNEL.read().1.resubscribe();
    loop {
        let ipv4_frame = receiver.recv().await.context("closed")?;
        let source_ip = ipv4_frame.get_source_address();
        // let udp_packet = UdpPacket::from_bytes(&ipv4_frame.payload);
        let udp_packet = UdpPacket::from_bytes(&ipv4_frame.get_payload());

        // Todo: Checksum の計算
        let _ = udp_packet.get_checksum();
        let _ = udp_packet.get_length();

        // sender を clone して使わない場合、RwLock が sender().send().await() を跨ぐ
        // ことになりコンパイルエラーとなる。
        let sender = match PORT_MAP.read().get(&udp_packet.get_target_port()) {
            Some(v) => v.clone(),
            None => {
                log::warn!("[udp_handler] listen していない port 宛に UDP パケットが来た。");
                continue;
            }
        };
        let std_sockaddrv4 = std::net::SocketAddrV4::new(source_ip, udp_packet.get_source_port());
        let std_sockaddr = std::net::SocketAddr::from(std_sockaddrv4);
        sender
            .send((std_sockaddr, udp_packet.get_payload()))
            .await
            .unwrap();
    }
}
