use once_cell::sync::Lazy;
use std::collections::HashMap;

use tokio::sync::broadcast::Receiver;
use tokio::sync::Mutex;

use crate::ethernet::EthernetFrame;

pub static ARP_TABLE: Lazy<Mutex<HashMap<[u8; 4], [u8; 6]>>> = Lazy::new(Default::default);

#[derive(Debug, Default, Clone, Copy)]
#[repr(u16)]
pub enum ArpOpCode {
    #[default]
    Request = 0x0001u16,
    Reply = 0x0002u16,
}

impl ArpOpCode {
    pub fn from_u16(a: u16) -> Self {
        match a {
            0x0001u16 => Self::Request,
            0x0002u16 => Self::Reply,
            _ => {
                unreachable!("{a:?}");
            }
        }
    }
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Default, Debug, Clone)]
pub struct Arp {
    pub ethernet_header: crate::ethernet::EthernetHeader,

    pub hardware_type: u16,          // 0x0001: Ethernet
    pub protcol_type: u16,           // 0x0800: IPv4
    pub hardware_address_length: u8, // 0x06: Length of MAC address.
    pub protcol_address_length: u8,  // 0x04: Length of IPv4 Address.
    pub opcode: u16,                 // 0x0001: Request.
    pub sender_mac_address: [u8; 6],
    pub sender_ip_address: [u8; 4],
    pub target_mac_address: [u8; 6],
    pub target_ip_address: [u8; 4],
}

impl Arp {
    pub fn from_eth_header_and_payload(
        eth_header: &crate::ethernet::EthernetHeader,
        payload: &[u8],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            ethernet_header: eth_header.clone(),
            hardware_type: u16::from_be_bytes(payload[0..2].try_into()?),
            protcol_type: u16::from_be_bytes(payload[2..4].try_into()?),
            hardware_address_length: payload[4],
            protcol_address_length: payload[5],
            opcode: u16::from_be_bytes(payload[6..8].try_into()?),
            sender_mac_address: payload[8..14].try_into()?,
            sender_ip_address: payload[14..18].try_into()?,
            target_mac_address: payload[18..24].try_into()?,
            target_ip_address: payload[24..28].try_into()?,
        })
    }

    pub fn request_minimal() -> Self {
        let ethernet_header = crate::ethernet::EthernetHeader {
            ethernet_type: crate::ethernet::EtherType::Arp.as_u16(),
            ..Default::default()
        };
        Self {
            ethernet_header,
            hardware_type: 0x0001,
            protcol_type: 0x0800,
            hardware_address_length: 0x06,
            protcol_address_length: 0x04,
            opcode: ArpOpCode::Request.as_u16(),
            ..Default::default()
        }
    }

    pub fn to_ethernet_frame(&self) -> EthernetFrame {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&self.hardware_type.to_be_bytes());
        payload.extend_from_slice(&self.protcol_type.to_be_bytes());
        payload.extend_from_slice(&self.hardware_address_length.to_be_bytes());
        payload.extend_from_slice(&self.protcol_address_length.to_be_bytes());
        payload.extend_from_slice(&self.opcode.to_be_bytes());

        payload.extend_from_slice(&self.sender_mac_address);
        payload.extend_from_slice(&self.sender_ip_address);
        payload.extend_from_slice(&self.target_mac_address);
        payload.extend_from_slice(&self.target_ip_address);

        EthernetFrame {
            header: self.ethernet_header.clone(),
            payload,
        }
    }

    pub async fn build_arp_request_packet(ip: [u8; 4]) -> Self {
        let mut req = crate::arp::Arp::request_minimal();
        let my_mac = loop {
            if crate::interface::MY_MAC_ADDRESS.lock().await.is_some() {
                break crate::interface::MY_MAC_ADDRESS.lock().await.unwrap();
            }
        };

        req.ethernet_header.destination_mac_address = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        req.ethernet_header.source_mac_address = my_mac;

        req.sender_mac_address = my_mac;
        req.sender_ip_address = crate::interface::MY_IP_ADDRESS;
        req.target_mac_address = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        req.target_ip_address = ip;

        req
    }
}

pub static ARP_RECEIVER: Lazy<Mutex<Option<Receiver<Arp>>>> = Lazy::new(Default::default);

async fn send_arp_reply(arp_req: Arp) {
    let mut arp_reply = Arp::request_minimal();

    // Set ethernet header.
    arp_reply.ethernet_header.destination_mac_address = arp_req.ethernet_header.source_mac_address;
    arp_reply.ethernet_header.source_mac_address =
        crate::interface::MY_MAC_ADDRESS.lock().await.unwrap();

    // Set arp payload.
    arp_reply.opcode = ArpOpCode::Reply.as_u16();
    arp_reply.sender_mac_address = crate::interface::MY_MAC_ADDRESS.lock().await.unwrap();
    arp_reply.sender_ip_address = crate::interface::MY_IP_ADDRESS;
    arp_reply.target_mac_address = arp_req.sender_mac_address;
    arp_reply.target_ip_address = arp_req.sender_ip_address;

    // Todo.
    // Sender IP, Sender MAC を MAC アドレステーブルにいれる。

    crate::ethernet::send_ethernet_frame(arp_reply.to_ethernet_frame()).await;
    log::trace!("Sent an Arp reply: {arp_reply:?}");
}

pub async fn arp_handler(mut arp_receive: Receiver<Arp>) {
    *ARP_RECEIVER.lock().await = Some(arp_receive.resubscribe());
    loop {
        let arp = arp_receive.recv().await.unwrap();

        let opcode = ArpOpCode::from_u16(arp.opcode);
        match opcode {
            ArpOpCode::Request => {
                if arp.target_ip_address == crate::interface::MY_IP_ADDRESS {
                    // Send an arp reply.
                    log::trace!("Get arp request");
                    send_arp_reply(arp).await;
                }
            }

            ArpOpCode::Reply => {
                log::trace!("ARP Reply: {arp:x?}");
                crate::arp::ARP_TABLE
                    .lock()
                    .await
                    .insert(arp.sender_ip_address, arp.sender_mac_address);
                // Todo.
                // Arp 解決を待っている人に通知する。
            }
        }
    }
}

pub async fn resolve_arp(ip: [u8; 4]) -> [u8; 6] {
    loop {
        if let Some(mac) = ARP_TABLE.lock().await.get(&ip) {
            return *mac;
        } else {
            // Resolve ARP.
            log::trace!("Resolving IP: {ip:x?}");
            let arp_req = Arp::build_arp_request_packet(ip).await;
            let eth_frame = arp_req.to_ethernet_frame();
            eth_frame.send().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        }
    }
}
