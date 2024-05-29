use std::collections::HashMap;
use std::net::Ipv4Addr;

use bytes::Bytes;
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;

use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};

use crate::layer2::ethernet::{EtherType, EthernetFrame, EthernetHeader};
use crate::layer2::interface::{MY_IP_ADDRESS, MY_MAC_ADDRESS};

static ARP_TABLE: Lazy<RwLock<HashMap<Ipv4Addr, [u8; 6]>>> = Lazy::new(Default::default);

pub static ARP_RECEIVER: Lazy<
    parking_lot::RwLock<(broadcast::Sender<Arp>, broadcast::Receiver<Arp>)>,
> = Lazy::new(|| {
    let (arp_rx_sender, arp_rx_receiver) = broadcast::channel::<Arp>(2);
    RwLock::new((arp_rx_sender, arp_rx_receiver))
});

pub static ARP_REPLY_NOTIFIER: Lazy<
    parking_lot::RwLock<(broadcast::Sender<()>, broadcast::Receiver<()>)>,
> = Lazy::new(|| {
    let (arp_reply_sender, arp_reply_receiver) = broadcast::channel::<()>(2);
    RwLock::new((arp_reply_sender, arp_reply_receiver))
});

const ARP_RESOLVE_LOOP_COUNT_THRESHOULD: usize = 10;

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

    pub fn minimal() -> Self {
        Self {
            ethernet_header: EthernetHeader {
                ethernet_type: EtherType::Arp as u16,
                source_mac_address: *MY_MAC_ADDRESS,
                ..Default::default()
            },
            hardware_type: 0x0001,
            protcol_type: 0x0800,
            hardware_address_length: 0x06,
            protcol_address_length: 0x04,
            sender_mac_address: *MY_MAC_ADDRESS,
            sender_ip_address: MY_IP_ADDRESS,
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
        let mut req = Arp::minimal();
        req.ethernet_header.destination_mac_address = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        req.target_mac_address = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        req.target_ip_address = ip.octets();
        req.opcode = ArpOpCode::Request as u16;
        req
    }

    fn get_sender_ip_address(&self) -> Ipv4Addr {
        self.sender_ip_address.into()
    }
}

async fn send_arp_reply(arp_req: Arp) -> anyhow::Result<()> {
    let mut arp_reply = Arp::minimal();

    // Set ethernet header.
    arp_reply.ethernet_header.destination_mac_address = arp_req.ethernet_header.source_mac_address;

    // Set arp payload.
    arp_reply.opcode = ArpOpCode::Reply as u16;
    arp_reply.target_mac_address = arp_req.sender_mac_address;
    arp_reply.target_ip_address = arp_req.sender_ip_address;

    // Todo.
    // Sender IP, Sender MAC を MAC アドレステーブルにいれる。

    arp_reply.to_ethernet_frame().send().await?;
    log::trace!("Sent an Arp reply: {arp_reply:?}");
    Ok(())
}

pub async fn arp_handler() -> anyhow::Result<()> {
    log::info!("Spawned ARP handler.");
    let mut arp_receive = ARP_RECEIVER.read().1.resubscribe();

    // ARP Reply を通知するためのチャネル.
    let arp_reply_sender = ARP_REPLY_NOTIFIER.read().0.clone();

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
                    send_arp_reply(arp).await?;
                }
            }

            ArpOpCode::Reply => {
                log::trace!("ARP Reply: {arp:x?}");
                ARP_TABLE
                    .write()
                    .insert(arp.get_sender_ip_address(), arp.sender_mac_address);
                // Arp 解決を待っている人に通知する。
                arp_reply_sender.send(())?;
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
    log::trace!("Resolving IP: {ip}");
    let mut arp_reply_notifier = ARP_REPLY_NOTIFIER.read().1.resubscribe();

    for count in 0..ARP_RESOLVE_LOOP_COUNT_THRESHOULD {
        if let Some(&mac) = ARP_TABLE.read().get(&ip) {
            return Ok(mac);
        }
        log::trace!("Sending ARP reqest for {ip}");
        Arp::new_arp_request_packet(ip)
            .await
            .to_ethernet_frame()
            .send()
            .await?;
        let timeout_ms = 8 << count;
        match timeout(Duration::from_millis(timeout_ms), arp_reply_notifier.recv()).await {
            Ok(_) => {} // We get an arp reply. Thre value can be got in next loop.
            Err(_) => tokio::task::yield_now().await, // Timed out. Yielding CPU to other tasks.
        };
        log::warn!("IP {ip} did not respond in {timeout_ms} ms. Retrying..")
    }
    let error_msg = format!("Exceeded loop count threshould in resolve_arp for {ip:?}");
    log::warn!("{error_msg}");
    anyhow::bail!(error_msg);
}
