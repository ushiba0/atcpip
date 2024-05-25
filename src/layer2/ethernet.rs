use std::net::Ipv4Addr;

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use num_traits::FromPrimitive;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Receiver;

use crate::layer2::arp::Arp;
use crate::layer2::interface::{DEFAULT_GATEWAY, MY_IP_ADDRESS, MY_MAC_ADDRESS, SUBNET_MASK};
use crate::layer3::ipv4::Ipv4Frame;

#[derive(Debug, Default, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    #[default]
    Invalid = 0xffff,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct EthernetHeader {
    pub destination_mac_address: [u8; 6],
    pub source_mac_address: [u8; 6],
    pub ethernet_type: u16,
}

#[derive(Default, Clone, Debug)]
pub struct EthernetFrame {
    pub header: EthernetHeader,
    pub payload: Bytes,
}

impl EthernetHeader {
    fn from_bytes(bytes: &[u8; 14] ) -> Self {
        Self {
            destination_mac_address: bytes[0..6].try_into().unwrap(),
            source_mac_address: bytes[6..12].try_into().unwrap(),
            ethernet_type: u16::from_be_bytes(bytes[12..14].try_into().unwrap())
        }
    }

    fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::zeroed(200);
        bytes[0..6].copy_from_slice(&self.destination_mac_address);
        bytes[6..12].copy_from_slice(&self.source_mac_address);
        bytes.put_u16(self.ethernet_type);
        bytes.freeze()
    }
}

impl EthernetFrame {
    pub fn from_bytes(buf: &[u8]) -> Self {
        Self {
            header: EthernetHeader::from_bytes(&buf[0..14].try_into().unwrap()),
            payload: Bytes::copy_from_slice(&buf[14..]),
        }
    }

    pub fn build_to_packet(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put(self.header.to_bytes());
        bytes.put(self.payload.clone());
        bytes.freeze()
    }

    pub fn to_arp(&self) -> Result<Arp> {
        Arp::from_eth_header_and_payload(&self.header, &self.payload)
    }

    pub async fn send(&self) -> Result<usize> {
        let f = self.clone();
        f.validate_mtu()?;
        send_ethernet_frame(f).await
    }

    fn validate_mtu(&self) -> Result<()> {
        anyhow::ensure!(
            self.payload.len() <= super::interface::MTU,
            "Ethernet payload ({}) exceeds MTU.",
            self.payload.len()
        );
        Ok(())
    }
}

pub async fn send_ethernet_frame(ethernet_frame: EthernetFrame) -> Result<usize> {
    crate::layer2::interface::send_to_pnet(ethernet_frame).await
}

fn is_same_subnet(dest_ip: Ipv4Addr) -> bool {
    let subnet_mask = u32::from_be_bytes(SUBNET_MASK);
    let my_nw_u32 = u32::from_be_bytes(MY_IP_ADDRESS) & subnet_mask;
    let dest_nw_u32 = u32::from_be_bytes(dest_ip.octets()) & subnet_mask;
    my_nw_u32 == dest_nw_u32
}

// Default gateway に振るか、同一サブネットかを判断する.
async fn generate_ethernet_header(dest_ip: Ipv4Addr) -> Result<EthernetHeader> {
    let destination_mac_address = if is_same_subnet(dest_ip) {
        // dest_ip を ARP 解決して MAC を返す。
        crate::layer2::arp::resolve_arp(dest_ip.octets()).await?
    } else {
        // Default gateway をARP 解決する。
        crate::layer2::arp::resolve_arp(DEFAULT_GATEWAY).await?
    };
    Ok(EthernetHeader {
        destination_mac_address,
        source_mac_address: crate::unwrap_or_yield!(MY_MAC_ADDRESS, clone),
        ethernet_type: EtherType::Ipv4 as u16,
    })
}

// 設計思想:
// 1 つ上にどんなレイヤがあるかは知っておく必要がある。
// 下にどんなレイヤがあるかは全く知る必要がない。
pub async fn send_ipv4(ipv4_frame: crate::layer3::ipv4::Ipv4Frame) -> Result<usize> {
    let destination_ip = ipv4_frame.get_destination_address();
    let eth_header = generate_ethernet_header(destination_ip).await?;

    let ether_frame = EthernetFrame {
        header: eth_header,
        payload: Bytes::copy_from_slice(&ipv4_frame.clone().build_to_bytes().to_vec()),
        ..Default::default()
    };

    ether_frame.send().await
}

pub async fn ethernet_handler(mut receiver: Receiver<EthernetFrame>) {
    // Datalink Rx.
    log::info!("Spawned Ethernet Rx handler.");

    // ARP ハンドラスレッドを spawn し、 ARP ハンドラスレッドに通知する用の Sender を返す。
    let arp_rx_sender = {
        // ARP packet が来たら、この channel で上のレイヤに通知する。
        let (arp_rx_sender, arp_rx_receiver) = broadcast::channel::<Arp>(2);

        // Spawn ARP handler.
        tokio::spawn(async move {
            crate::layer2::arp::arp_handler(arp_rx_receiver).await;
        });
        arp_rx_sender
    };

    // IPv4 ハンドラスレッドを spawn し、 IPv4 ハンドラスレッドに通知する用の Sender を返す。
    let ipv4_rx_sender = {
        // Ipv4 の受信を上のレイヤに伝えるチャネル.
        let (ipv4_rx_sender, ipv4_rx_receiver) = broadcast::channel::<Ipv4Frame>(2);

        // Spawn IPv4 handler.
        tokio::spawn(async move {
            crate::layer3::ipv4::ipv4_handler(ipv4_rx_receiver).await;
        });
        ipv4_rx_sender
    };

    loop {
        tokio::task::yield_now().await;
        // rx.next() はパケットが届かない場合は PNET_RX_TIMEOUT_MICROSEC ms で timeout する。
        // 逆にここで PNET_RX_TIMEOUT_MICROSEC ms のブロックが発生する可能性がある。
        if let Some(eth_frame) = receiver.recv().await {
            // EtherType を見て Arp handler, IPv4 handler に渡す。
            match EtherType::from_u16(eth_frame.header.ethernet_type).unwrap_or_default() {
                EtherType::Arp => {
                    let arp = eth_frame.to_arp().unwrap();
                    arp_rx_sender.send(arp).unwrap();
                }
                EtherType::Ipv4 => {
                    let ipv4frame = Ipv4Frame::from_buffer(&eth_frame.payload);
                    // Send to ipv4_handler() at crate::layer3::ipv4.
                    ipv4_rx_sender.send(ipv4frame).unwrap();
                }
                _ => {}
            }
        }
    }
}
