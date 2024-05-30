use std::net::Ipv4Addr;

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use num_traits::FromPrimitive;
use tokio::sync::mpsc::Receiver;

use crate::layer2::arp::Arp;
use crate::layer2::interface::{DEFAULT_GATEWAY_IPV4, MY_IP_ADDRESS, SUBNET_MASK};
use crate::layer3::ipv4::Ipv4Packet;

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
    fn from_bytes(bytes: &[u8; 14]) -> Self {
        Self {
            destination_mac_address: bytes[0..6].try_into().unwrap(),
            source_mac_address: bytes[6..12].try_into().unwrap(),
            ethernet_type: u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
        }
    }

    fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::zeroed(12);
        bytes[0..6].copy_from_slice(&self.destination_mac_address);
        bytes[6..12].copy_from_slice(&self.source_mac_address);
        bytes.put_u16(self.ethernet_type);
        debug_assert_eq!(bytes.len(), 14);
        bytes.freeze()
    }
}

impl EthernetFrame {
    pub fn from_slice(buf: &[u8]) -> Self {
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
        crate::layer2::arp::resolve_arp(dest_ip).await?
    } else {
        // Default gateway をARP 解決する。
        crate::layer2::arp::resolve_arp(DEFAULT_GATEWAY_IPV4).await?
    };
    Ok(EthernetHeader {
        destination_mac_address,
        source_mac_address: *crate::layer2::interface::MY_MAC_ADDRESS,
        ethernet_type: EtherType::Ipv4 as u16,
    })
}

pub async fn send_ipv4(ipv4_frame: crate::layer3::ipv4::Ipv4Packet) -> Result<usize> {
    let destination_ip = ipv4_frame.get_destination_address();
    let eth_header = generate_ethernet_header(destination_ip).await?;

    let ether_frame = EthernetFrame {
        header: eth_header,
        payload: Bytes::copy_from_slice(&ipv4_frame.to_bytes()),
    };

    ether_frame.send().await
}

async fn ethernet_handler_inner(mut receiver: Receiver<EthernetFrame>) -> anyhow::Result<()> {
    let arp_rx_sender = crate::layer2::arp::ARP_RECEIVER.read().0.clone();
    let ipv4_rx_sender = crate::layer3::ipv4::IPV4_RECEIVER.read().0.clone();

    loop {
        tokio::task::yield_now().await;
        // rx.next() はパケットが届かない場合は PNET_RX_TIMEOUT_MICROSEC ms で timeout する。
        // 逆にここで PNET_RX_TIMEOUT_MICROSEC ms のブロックが発生する可能性がある。
        if let Some(eth_frame) = receiver.recv().await {
            // EtherType を見て Arp handler, IPv4 handler に渡す。
            match EtherType::from_u16(eth_frame.header.ethernet_type).unwrap_or_default() {
                EtherType::Arp => {
                    let arp = eth_frame.to_arp()?;
                    arp_rx_sender.send(arp)?;
                }
                EtherType::Ipv4 => {
                    let ipv4frame = Ipv4Packet::from_bytes(&eth_frame.payload);
                    ipv4_rx_sender.send(ipv4frame)?;
                }
                _ => {}
            }
        } else {
            // Timed out.
        }
    }
}

pub async fn ethernet_handler(receiver: Receiver<EthernetFrame>) -> anyhow::Result<()> {
    // Datalink Rx.
    log::info!("Spawned Ethernet Rx handler.");

    tokio::spawn(async {
        crate::layer2::arp::arp_handler().await.unwrap();
    });

    tokio::spawn(async {
        crate::layer3::ipv4::ipv4_handler().await.unwrap();
    });

    tokio::spawn(async { ethernet_handler_inner(receiver).await.unwrap() });
    Ok(())
}
