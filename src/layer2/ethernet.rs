use std::net::Ipv4Addr;

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use num_traits::FromPrimitive;
use tokio::sync::mpsc::Receiver;

use crate::layer2::arp::Arp;
use crate::layer2::interface::{DEFAULT_GATEWAY_IPV4, MY_IP_ADDRESS, SUBNET_MASK};
use crate::layer3::ipv4::Ipv4Packet;

const ETHERNET_HEADER_LEN: usize = 14;

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
    pub bytes: BytesMut,
}

#[derive(Default, Clone, Debug)]
pub struct EthernetFrame {
    pub header: EthernetHeader,
    pub payload: Bytes,
}

impl EthernetHeader {
    pub fn new(destination: &[u8; 6], source: &[u8; 6], ether_type: EtherType) -> Self {
        let mut bytes = BytesMut::with_capacity(ETHERNET_HEADER_LEN);
        bytes.put_slice(destination);
        bytes.put_slice(source);
        bytes.put_u16(ether_type as u16);
        Self { bytes }
    }

    fn from_bytes(bytes_arg: &BytesMut) -> Self {
        Self {
            bytes: bytes_arg.clone(),
        }
    }

    fn to_bytes(&self) -> Bytes {
        self.bytes.clone().freeze()
    }

    crate::impl_get_slice!(get_destination_mac_address, bytes, 0, 6, [u8; 6]);
    crate::impl_get_slice!(get_source_mac_address, bytes, 6, 12, [u8; 6]);
    crate::impl_get!(get_ethernet_type, bytes, 12, 14, u16);
    crate::impl_set_slice!(set_destination_mac_address, bytes, 0, 6, [u8; 6]);
    crate::impl_set_slice!(set_source_mac_address, bytes, 6, 12, [u8; 6]);
    crate::impl_set!(set_ethernet_type, bytes, 12, 14, u16);
}

impl EthernetFrame {
    pub fn from_slice(buf: &[u8]) -> Self {
        let mut bytesmut = BytesMut::new();
        bytesmut.extend_from_slice(buf);
        let header = bytesmut.split_to(ETHERNET_HEADER_LEN);
        let header = EthernetHeader::from_bytes(&header);
        let payload = bytesmut.freeze();
        Self { header, payload }
    }

    pub fn to_bytes(&self) -> Bytes {
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
            "Ethernet payload ({} bytes) exceeds MTU.",
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

    Ok(EthernetHeader::new(
        &destination_mac_address,
        &*crate::layer2::interface::MY_MAC_ADDRESS,
        EtherType::Ipv4,
    ))
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
        if let Some(eth_frame) = receiver.recv().await {
            // EtherType を見て Arp handler, IPv4 handler に渡す。
            match EtherType::from_u16(eth_frame.header.get_ethernet_type()).unwrap_or_default() {
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
