use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::{ensure, Context};
use bytes::Bytes;
use once_cell::sync::Lazy;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;

use crate::layer3::ipv4::Ipv4Frame;

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
    receiver: Receiver<(Ipv4Addr, Bytes)>,
}

impl UdpPacket {
    // pub fn new() -> Self {
    //     Default::default()
    // }

    pub fn from_bytes(bytes: &Bytes) -> Self {
        Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            target_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: bytes.slice(8..),
        }
    }
}

// 下位のレイヤから UDP パケットが来たら、この Hashmap の Sender で送る。
// Listen しているユーザーアプリケーションは Receiver で受け取る。
pub static LISTEN_ADDRESSES: Lazy<Mutex<HashMap<u16, Sender<(Ipv4Addr, Bytes)>>>> =
    Lazy::new(Default::default);

impl UdpSocket {
    pub async fn bind(_ip: Ipv4Addr, port: u16) -> anyhow::Result<Self> {
        let mut portlist = LISTEN_ADDRESSES.lock().await;
        ensure!(portlist.get(&port).is_none(), "Address already in use.");

        let (rx_sender, rx_receiver) = mpsc::channel::<(Ipv4Addr, Bytes)>(2);
        portlist.insert(port, rx_sender);

        log::info!("Listening UDP on port {port}.");
        Ok(Self {
            receiver: rx_receiver,
        })
    }

    pub async fn recv_from(&mut self) -> (Ipv4Addr, Bytes) {
        self.receiver.recv().await.unwrap()
    }
}

pub async fn udp_handler(mut receiver: Receiver<Ipv4Frame>) -> anyhow::Result<()> {
    loop {
        let ipv4_frame = receiver.recv().await.context("closed")?;
        let source_ip = ipv4_frame.get_source_address();
        let udp_packet = UdpPacket::from_bytes(&ipv4_frame.payload);

        // Todo: Checksum の計算

        if let Some(s) = LISTEN_ADDRESSES.lock().await.get(&udp_packet.target_port) {
            s.send((source_ip, udp_packet.payload)).await.unwrap();
        }
    }
}
