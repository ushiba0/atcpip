use once_cell::sync::Lazy;
use std::collections::HashMap;

use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::Mutex;

use crate::ethernet::EthernetFrame;

#[derive(Debug, Default, Clone, Copy)]
#[repr(u8)]
pub enum IcmpType {
    #[default]
    Request = 0x08u8,
    Reply = 0x0,
}

impl IcmpType {
    pub fn from_u16(a: u16) -> Self {
        match a {
            0x0001u16 => Self::Request,
            0x0002u16 => Self::Reply,
            _ => {
                unreachable!("{a:?}");
            }
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Default, Debug, Clone)]
pub struct Icmp {
    pub icmp_type: u8, // 0: Reply, 8: Echo Reqest.
    pub code: u8,
    pub checksum: u8,
    pub identifier: u16,
    pub seqence_number: u16,
    pub data: Vec<u8>, // Timestamp (8 bytes) + Data (40 bytes).
}

impl Icmp {
    pub fn echo_reqest_minimal() -> Self {
        Self {
            icmp_type: IcmpType::Request.as_u8(),
            ..Default::default()
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.icmp_type.to_be_bytes());
        bytes.extend_from_slice(&self.code.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.seqence_number.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn fill_checksum(&mut self) {
        self.checksum = 0;
    }

    pub fn to_ipv4_frame(&self) -> crate::ipv4::Ipv4Frame {
        let mut frame = crate::ipv4::Ipv4Frame::minimal();

        frame
    }

    // pub fn from_eth_header_and_payload(
    //     eth_header: &crate::ethernet::EthernetHeader,
    //     payload: &[u8],
    // ) -> anyhow::Result<Self> {
    //     Ok(Self {
    //         ethernet_header: eth_header.clone(),
    //         hardware_type: u16::from_be_bytes(payload[0..2].try_into()?),
    //         protcol_type: u16::from_be_bytes(payload[2..4].try_into()?),
    //         hardware_address_length: payload[4],
    //         protcol_address_length: payload[5],
    //         opcode: u16::from_be_bytes(payload[6..8].try_into()?),
    //         sender_mac_address: payload[8..14].try_into()?,
    //         sender_ip_address: payload[14..18].try_into()?,
    //         target_mac_address: payload[18..24].try_into()?,
    //         target_ip_address: payload[24..28].try_into()?,
    //     })
    // }
}
