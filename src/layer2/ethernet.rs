const ETHERNET_FRAME_SIZE: usize = 1500;

use crate::layer2::arp::Arp;
use crate::layer2::interface::{DEFAULT_GATEWAY, MY_IP_ADDRESS, MY_MAC_ADDRESS, SUBNET_MASK};

#[derive(Debug, Default, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum EtherType {
    #[default]
    Empty = 0x0000u16,
    Ipv4 = 0x0800,
    Arp = 0x0806,
}

impl EtherType {
    pub fn from_u16(x: u16) -> Self {
        let x = x as isize;
        match x {
            0x0000isize => Self::Empty,
            0x0800isize => Self::Ipv4,
            0x0806isize => Self::Arp,
            _ => Self::Empty,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
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
    pub payload: Vec<u8>,
}

impl EthernetHeader {
    pub fn new(buf: &[u8; 14]) -> Self {
        let mut destination_mac_address = [0u8; 6];
        let mut source_mac_address = [0u8; 6];
        let ethernet_type = u16::from_be_bytes(buf[12..14].try_into().unwrap());

        destination_mac_address.copy_from_slice(&buf[0..6]);
        source_mac_address.copy_from_slice(&buf[6..12]);

        Self {
            destination_mac_address,
            source_mac_address,
            ethernet_type,
        }
    }

    fn to_bin(&self) -> Vec<u8> {
        let mut bin: Vec<u8> = Vec::new();
        bin.extend_from_slice(&self.destination_mac_address);
        bin.extend_from_slice(&self.source_mac_address);
        bin.extend_from_slice(&self.ethernet_type.to_be_bytes());
        bin
    }

    // pub fn is_broadcast(&self) -> bool {
    //     self.destination_mac_address == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    // }
}

impl EthernetFrame {
    pub fn new(buf: &[u8]) -> Self {
        let header_bytes = &buf[0..14];
        let header = EthernetHeader::new(header_bytes.try_into().unwrap());
        let payload = buf[14..].to_vec();
        debug_assert!(payload.len() <= ETHERNET_FRAME_SIZE);

        Self { header, payload }
    }

    // pub fn minimal() -> Self {
    //     Self::new(&Vec::new())
    // }

    pub fn build_to_packet(&self) -> Vec<u8> {
        let mut packet: Vec<u8> = Vec::new();
        packet.extend_from_slice(&self.header.to_bin());
        packet.extend_from_slice(&self.payload);
        packet
    }

    pub fn to_arp(&self) -> anyhow::Result<Arp> {
        Arp::from_eth_header_and_payload(&self.header, &self.payload)
    }

    pub async fn send(&self) -> anyhow::Result<usize> {
        let f = self.clone();
        f.validate_mtu()?;
        send_ethernet_frame(f).await
    }

    fn validate_mtu(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.payload.len() <= super::interface::MTU,
            "Ethernet payload ({}) exceeds MTU.",
            self.payload.len()
        );
        Ok(())
    }
}

pub async fn send_ethernet_frame(ethernet_frame: EthernetFrame) -> anyhow::Result<usize> {
    crate::layer2::interface::send_to_pnet(ethernet_frame).await
}

fn is_same_subnet(dest_ip: [u8; 4]) -> bool {
    let subnet_mask = u32::from_be_bytes(SUBNET_MASK);
    let my_nw_u32 = u32::from_be_bytes(MY_IP_ADDRESS) & subnet_mask;
    let dest_nw_u32 = u32::from_be_bytes(dest_ip) & subnet_mask;
    my_nw_u32 == dest_nw_u32
}

// Default gateway に振るか、同一サブネット化を判断する.
async fn generate_ethernet_header(dest_ip: [u8; 4]) -> anyhow::Result<EthernetHeader> {
    let destination_mac_address = if is_same_subnet(dest_ip) {
        // dest_ip を ARP 解決して MAC を返す。
        crate::layer2::arp::resolve_arp(dest_ip).await?
    } else {
        // Default gateway をARP 解決する。
        crate::layer2::arp::resolve_arp(DEFAULT_GATEWAY).await?
    };
    Ok(EthernetHeader {
        destination_mac_address,
        source_mac_address: crate::unwrap_or_yield!(MY_MAC_ADDRESS, clone),
        ethernet_type: EtherType::Ipv4.as_u16(),
    })
}

// 設計思想:
// 1 つ上にどんなレイヤがあるかは知っておく必要がある。
// 下にどんなレイヤがあるかは全く知る必要がない。
pub async fn send_ipv4(ipv4_frame: crate::layer3::ipv4::Ipv4Frame) -> anyhow::Result<usize> {
    let destination_ip = ipv4_frame.destination_address;
    let eth_header = generate_ethernet_header(destination_ip).await?;

    let ether_frame = EthernetFrame {
        header: eth_header,
        payload: ipv4_frame.clone().build_to_bytes().to_vec(),
    };

    ether_frame.send().await
}
