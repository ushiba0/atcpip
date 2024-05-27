use std::collections::HashMap;
use std::net::Ipv4Addr;

use bytes::Bytes;
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;

use tokio::sync::broadcast::{self, Receiver};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use crate::layer2::ethernet::{EtherType, EthernetFrame, EthernetHeader};
use crate::layer2::interface::{MY_IP_ADDRESS, MY_MAC_ADDRESS};

// static ARP_TABLE: Lazy<Mutex<HashMap<[u8; 4], [u8; 6]>>> = Lazy::new(Default::default);
static ARP_TABLEV2: Lazy<parking_lot::RwLock<HashMap<Ipv4Addr, [u8; 6]>>> =
    Lazy::new(Default::default);

const ARP_RESOLVE_LOOP_COUNT_THRESHOULD: usize = 20;

#[derive(Debug, Default, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(u16)]
pub enum ArpOpCode {
    Request = 0x0001u16,
    Reply = 0x0002u16,
    #[default]
    Invalid = 0xffff,
}

#[derive(Default, Debug, Clone)]
pub struct Arp {
    pub ethernet_header: EthernetHeader,
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
        eth_header: &EthernetHeader,
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
        let ethernet_header = EthernetHeader {
            ethernet_type: EtherType::Arp as u16,
            ..Default::default()
        };
        Self {
            ethernet_header,
            hardware_type: 0x0001,
            protcol_type: 0x0800,
            hardware_address_length: 0x06,
            protcol_address_length: 0x04,
            opcode: ArpOpCode::Request as u16,
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
            payload: Bytes::copy_from_slice(&payload),
        }
    }

    async fn new_arp_request_packet(ip: Ipv4Addr) -> Self {
        let mut req = Arp::request_minimal();
        let my_mac = *MY_MAC_ADDRESS;

        req.ethernet_header.destination_mac_address = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        req.ethernet_header.source_mac_address = my_mac;

        req.sender_mac_address = my_mac;
        req.sender_ip_address = MY_IP_ADDRESS;
        req.target_mac_address = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        req.target_ip_address = ip.octets();

        req
    }

    fn get_sender_ip_address(&self) -> Ipv4Addr {
        let s = self.sender_ip_address;
        Ipv4Addr::new(s[0], s[1], s[2], s[3])
    }
}

pub static ARP_RECEIVER: Lazy<Mutex<Option<Receiver<Arp>>>> = Lazy::new(Default::default);
pub static ARP_REPLY_NOTIFIER: Lazy<Mutex<Option<Receiver<bool>>>> = Lazy::new(Default::default);

async fn send_arp_reply(arp_req: Arp) {
    let mut arp_reply = Arp::request_minimal();

    // Set ethernet header.
    arp_reply.ethernet_header.destination_mac_address = arp_req.ethernet_header.source_mac_address;
    arp_reply.ethernet_header.source_mac_address = *MY_MAC_ADDRESS;

    // Set arp payload.
    arp_reply.opcode = ArpOpCode::Reply as u16;
    arp_reply.sender_mac_address = *MY_MAC_ADDRESS;
    arp_reply.sender_ip_address = MY_IP_ADDRESS;
    arp_reply.target_mac_address = arp_req.sender_mac_address;
    arp_reply.target_ip_address = arp_req.sender_ip_address;

    // Todo.
    // Sender IP, Sender MAC を MAC アドレステーブルにいれる。

    arp_reply.to_ethernet_frame().send().await.unwrap();
    log::trace!("Sent an Arp reply: {arp_reply:?}");
}

pub async fn arp_handler(mut arp_receive: Receiver<Arp>) {
    let arp_receive2 = arp_receive.resubscribe();
    *ARP_RECEIVER.lock().await = Some(arp_receive2);

    // ARP Reply を通知するためのチャネル.
    let (arp_reply_sender, arp_reply_receiver) = broadcast::channel::<bool>(2);
    *ARP_REPLY_NOTIFIER.lock().await = Some(arp_reply_receiver);

    loop {
        let arp = match arp_receive.recv().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Some ARP Packets are dropped. {e:?}");
                continue;
            }
        };

        let opcode = ArpOpCode::from_u16(arp.opcode).unwrap_or_default();
        match opcode {
            ArpOpCode::Request => {
                if arp.target_ip_address == MY_IP_ADDRESS {
                    // Send an arp reply.
                    log::trace!("Get arp request");
                    send_arp_reply(arp).await;
                }
            }

            ArpOpCode::Reply => {
                log::trace!("ARP Reply: {arp:x?}");
                ARP_TABLEV2
                    .write()
                    .insert(arp.get_sender_ip_address(), arp.sender_mac_address);
                // Arp 解決を待っている人に通知する。
                arp_reply_sender.send(true).unwrap();
            }

            ArpOpCode::Invalid => {
                log::warn!(
                    "Got an unimplemented arp opcode: {}. The packet is ignored.",
                    arp.opcode
                );
            }
        }
    }
}

pub async fn resolve_arp(ip: Ipv4Addr) -> anyhow::Result<[u8; 6]> {
    let mut arp_reply_notifier = crate::unwrap_or_yield!(ARP_REPLY_NOTIFIER, resubscribe);

    for count in 0..ARP_RESOLVE_LOOP_COUNT_THRESHOULD {
        if let Some(&mac) = ARP_TABLEV2.read().get(&ip) {
            return Ok(mac);
        }
        log::trace!("Sending ARP reqest for {ip}");
        Arp::new_arp_request_packet(ip)
            .await
            .to_ethernet_frame()
            .send()
            .await
            .unwrap();
        let timeout_ms = 8 << count;
        match timeout(Duration::from_millis(timeout_ms), arp_reply_notifier.recv()).await {
            Ok(_) => {} // We get an arp reply. Thre value can be got in next loop.
            Err(_) => tokio::task::yield_now().await, // Timed out. Yielding CPU to other tasks.
        };
        log::warn!("IP {ip} did not respond in {timeout_ms} ms. Retrying..")
    }
    let error_msg = format!(
        "[resolve_arp] Exceeded loop count threshould during ARP resolving IP {:?}",
        ip
    );
    log::warn!("{error_msg}");
    anyhow::bail!(error_msg);
}
