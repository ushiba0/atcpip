use std::collections::HashMap;
use std::net::Ipv4Addr;

use bytes::{Bytes, BytesMut};
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use parking_lot::RwLock;

use tokio::sync::broadcast;

use crate::layer2::interface::MY_IP_ADDRESS;

mod fragment_ipv4;
mod impl_ipv4_pkt;
mod impl_ipv4_pkt_mut;
mod reassemble_ipv4;

pub static IPV4_RECEIVER: Lazy<
    parking_lot::RwLock<(
        broadcast::Sender<Ipv4Packet>,
        broadcast::Receiver<Ipv4Packet>,
    )>,
> = Lazy::new(|| {
    let (ipv4_rx_sender, ipv4_rx_receiver) =
        broadcast::channel::<Ipv4Packet>(crate::common::BUFFER_SIZE_DEFAULT);
    RwLock::new((ipv4_rx_sender, ipv4_rx_receiver))
});

pub const IPV4_HEADER_LEN: usize = 20;
const IPV4_MAX_PAYLOAD_SIZE: usize = 65536;

#[derive(Debug, Default, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(u8)]
pub enum Ipv4Protcol {
    Icmp = 0x01,
    Ip = 0x04,
    Tcp = 0x06,
    Udp = 17,
    Ipv6 = 41,
    #[default]
    Invalid = 0xff,
}

#[derive(Debug, Default, Clone)]
pub struct Ipv4Packet {
    header: Bytes,
    payload: Bytes,
}

#[derive(Debug, Default, Clone)]
pub struct Ipv4PacketMut {
    header: BytesMut,
    payload: Bytes,
}

async fn ipv4_handler_inner() -> anyhow::Result<()> {
    let mut ipv4_receive = IPV4_RECEIVER.read().1.resubscribe();
    let icmp_rx_sender = crate::layer3::icmp::ICMP_CHANNEL.read().0.clone();
    let udp_ch_sender = crate::layer4::udp::UDP_CHANNEL.read().0.clone();

    // Buffer for IP Fragmentation.
    let mut tmp_pool: HashMap<u16, Vec<Ipv4Packet>> = HashMap::new();

    loop {
        let ipv4_pkt = ipv4_receive.recv().await?;
        if ipv4_pkt.get_destination_address_slice() != MY_IP_ADDRESS {
            continue;
        }

        // Validate checksum.
        if ipv4_pkt.calc_header_checksum() != 0 {
            log::warn!("Detected IPv4 checksum error for packet: {ipv4_pkt:x?}");
            // Todo: Error stats counter を実装してカウントアップする。
            continue;
        }

        // Re-assemble if needed.
        let ipv4_pkt = match reassemble_ipv4::reassemble(&mut tmp_pool, &ipv4_pkt) {
            Ok(v) => v,
            Err(e) => {
                log::trace!("IPv4 packet reassemble failed. {e:?}");
                continue;
            }
        };

        // Todo:  Total length の確認。

        let protcol = Ipv4Protcol::from_u8(ipv4_pkt.get_protcol_u8()).unwrap_or_default();
        match protcol {
            Ipv4Protcol::Icmp => {
                icmp_rx_sender.send(ipv4_pkt)?;
            }
            Ipv4Protcol::Udp => {
                udp_ch_sender.send(ipv4_pkt)?;
            }
            _ => {
                log::warn!("Uninplemented IPv4 protcol: {protcol:?}");
            }
        }
    }
}

pub async fn ipv4_handler() -> anyhow::Result<()> {
    log::info!("Spawned IPv4 handler.");

    tokio::spawn(async {
        super::icmp::icmp_handler().await.unwrap();
    });

    tokio::spawn(async {
        crate::layer4::udp::udp_handler().await.unwrap();
    });

    tokio::spawn(async {
        ipv4_handler_inner().await.unwrap();
    });

    Ok(())
}

pub async fn send_udp(
    udppacket: crate::layer4::udp::UdpPacket,
    target_ip: &Ipv4Addr,
) -> anyhow::Result<()> {
    let bytes = udppacket.to_bytes();
    let ip_pkt = Ipv4PacketMut::new(target_ip.octets(), Ipv4Protcol::Udp, bytes.clone());
    ip_pkt.safely_send().await
}

pub async fn send_tcp(
    tcp_pkt: crate::layer4::tcp::TcpPacket,
    target_ip: &Ipv4Addr,
) -> anyhow::Result<()> {
    let bytes = tcp_pkt.to_bytes();
    let ip_pkt = Ipv4PacketMut::new(target_ip.octets(), Ipv4Protcol::Udp, bytes.clone());
    ip_pkt.safely_send().await
}
