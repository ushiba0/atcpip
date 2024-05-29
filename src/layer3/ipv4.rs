use std::collections::HashMap;
use std::net::Ipv4Addr;

use bit_field::BitField;
use bytes::{BufMut, Bytes, BytesMut};
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rand::Rng;

use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::common::calc_checksum;
use crate::layer2::interface::MY_IP_ADDRESS;

mod reassemble_ipv4;

pub static IPV4_RECEIVER: Lazy<
    parking_lot::RwLock<(broadcast::Sender<Ipv4Packet>, broadcast::Receiver<Ipv4Packet>)>,
> = Lazy::new(|| {
    let (ipv4_rx_sender, ipv4_rx_receiver) = broadcast::channel::<Ipv4Packet>(2);
    RwLock::new((ipv4_rx_sender, ipv4_rx_receiver))
});

const IPV4_HEADER_LEN: usize = 20;
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
    bytes: Bytes,
}

#[derive(Debug, Default, Clone)]
pub struct Ipv4PacketUnverified {
    bytes: BytesMut,
}

impl Ipv4Packet {
    pub fn from_bytes(bytes: &Bytes) -> Self {
        Self {
            bytes: bytes.clone(),
        }
    }

    // crate::impl_get!(get_version_and_header_len, bytes, 0, 1, u8);
    // crate::impl_get!(get_differenciate_service_field, bytes, 1, 2, u8);
    crate::impl_get!(get_total_length, bytes, 2, 4, u16);
    crate::impl_get!(get_identification, bytes, 4, 6, u16);
    crate::impl_get!(get_flags, bytes, 6, 8, u16);
    // crate::impl_get!(get_time_to_live, bytes, 8, 9, u8);
    crate::impl_get!(get_protcol_u8, bytes, 9, 10, u8);
    // crate::impl_get!(get_header_checksum, bytes, 10, 12, u16);
    crate::impl_get_slice!(get_source_address_slice, bytes, 12, 16, [u8; 4]);
    crate::impl_get_slice!(get_destination_address_slice, bytes, 16, 20, [u8; 4]);

    crate::impl_get_bit!(get_fragment_mf_bit, bytes, 6, 5);
    // crate::impl_get_bit!(get_fragment_df_bit, bytes, 6, 6);

    pub fn to_bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    pub async fn send(&self) -> anyhow::Result<usize> {
        crate::layer2::ethernet::send_ipv4(self.clone()).await
    }

    pub fn get_source_address(&self) -> Ipv4Addr {
        self.get_source_address_slice().into()
    }

    pub fn get_destination_address(&self) -> Ipv4Addr {
        self.get_destination_address_slice().into()
    }

    pub fn get_payload(&self) -> Bytes {
        self.bytes.slice(IPV4_HEADER_LEN..)
    }

    pub fn to_unverified(&self) -> Ipv4PacketUnverified {
        let mut bytes = BytesMut::new();
        bytes.put(self.bytes.clone());
        Ipv4PacketUnverified { bytes }
    }

    pub fn calc_header_checksum(&self) -> u16 {
        calc_checksum(&self.bytes[..IPV4_HEADER_LEN])
    }

    fn get_fragment_offset(&self) -> u16 {
        self.get_flags().get_bits(0..13) << 3
    }
}

impl Ipv4PacketUnverified {
    pub fn minimal() -> Self {
        let mut ipv4_pkt = Self {
            bytes: BytesMut::zeroed(IPV4_HEADER_LEN),
        };
        ipv4_pkt
            .set_version_and_header_len(0b0100_0101)
            .set_differenciate_service_field(0)
            .set_time_to_live(64)
            .set_protcol_u8(1) // ICMP
            .set_source_address_slice(crate::layer2::interface::MY_IP_ADDRESS)
            .set_fragment_df_bit(true)
            .set_fragment_mf_bit(false);
        ipv4_pkt
    }

    crate::impl_get!(get_flags, bytes, 6, 8, u16);

    crate::impl_set!(set_version_and_header_len, bytes, 0, 1, u8);
    crate::impl_set!(set_differenciate_service_field, bytes, 1, 2, u8);
    crate::impl_set!(set_total_length, bytes, 2, 4, u16);
    crate::impl_set!(set_identification, bytes, 4, 6, u16);
    crate::impl_set!(set_flags, bytes, 6, 8, u16);
    crate::impl_set!(set_time_to_live, bytes, 8, 9, u8);
    crate::impl_set!(set_protcol_u8, bytes, 9, 10, u8);
    crate::impl_set!(set_header_checksum, bytes, 10, 12, u16);
    crate::impl_set_slice!(set_source_address_slice, bytes, 12, 16, [u8; 4]);
    crate::impl_set_slice!(set_destination_address_slice, bytes, 16, 20, [u8; 4]);

    // crate::impl_get_bit!(get_fragment_mf_bit, bytes, 6, 5);
    // crate::impl_get_bit!(get_fragment_df_bit, bytes, 6, 6);
    crate::impl_set_bit!(set_fragment_mf_bit, bytes, 6, 5);
    crate::impl_set_bit!(set_fragment_df_bit, bytes, 6, 6);

    fn to_ipv4packet(&mut self) -> Ipv4Packet {
        self.build();
        Ipv4Packet {
            bytes: self.clone().bytes.freeze(),
        }
    }

    fn build(&mut self) {
        self.set_header_checksum(0);
        self.set_total_length(self.bytes.len() as u16);
        let checksum = calc_checksum(&self.bytes[..IPV4_HEADER_LEN]);
        self.set_header_checksum(checksum);
    }

    fn set_flagment_offset(&mut self, offset: u16) -> &mut Self {
        debug_assert_eq!(offset % 8, 0);
        let mut flags = self.get_flags();
        flags.set_bits(0..13, offset >> 3);
        self.set_flags(flags);
        self
    }

    pub fn set_payload(&mut self, payload: &Bytes) -> &mut Self {
        self.bytes.resize(IPV4_HEADER_LEN, 0x00);
        self.bytes.put(payload.clone());
        self
    }
}

pub async fn ipv4_handler() {
    log::info!("Spawned IPv4 handler.");
    let mut ipv4_receive = IPV4_RECEIVER.read().1.resubscribe();
    let icmp_rx_sender = crate::layer3::icmp::ICMP_CHANNEL.read().0.clone();

    // Spawn ICMP handler.
    tokio::spawn(async move {
        super::icmp::icmp_handler().await.unwrap();
    });

    // UDP の受信を通知するチャネル.
    let (udp_rx_sender, udp_rx_receiver) = mpsc::channel::<Ipv4Packet>(2);
    // Spawn UDP handler.
    #[allow(clippy::let_underscore_future)]
    let _: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        crate::layer4::udp::udp_handler(udp_rx_receiver).await?;
        Ok(())
    });

    // Buffer for IP Fragmentation.
    let mut tmp_pool: HashMap<u16, Vec<Ipv4Packet>> = HashMap::new();

    loop {
        let ipv4frame = ipv4_receive.recv().await.unwrap();

        if ipv4frame.get_destination_address_slice() != MY_IP_ADDRESS {
            continue;
        }

        // Checksum の確認
        if ipv4frame.calc_header_checksum() != 0 {
            log::warn!("Detected IPv4 checksum error for packet: {ipv4frame:x?}");
            // Todo: Error stats counter を実装してカウントアップする。
            continue;
        }

        // リビルド。
        let ipv4frame = match reassemble_ipv4::reassemble(&mut tmp_pool, &ipv4frame) {
            Ok(v) => v,
            Err(e) => {
                log::trace!("IPv4 packet reassemble failed. {e:?}");
                continue;
            }
        };

        // Todo:  Total length の確認。

        let protcol = Ipv4Protcol::from_u8(ipv4frame.get_protcol_u8()).unwrap_or_default();
        match protcol {
            Ipv4Protcol::Icmp => {
                icmp_rx_sender.send(ipv4frame).unwrap();
            }
            Ipv4Protcol::Udp => {
                udp_rx_sender.send(ipv4frame).await.unwrap();
            }
            _ => {
                log::warn!("Uninplemented IPv4 protcol: {protcol:?}");
            }
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Ipv4FrameUnchecked {
    destination_address: [u8; 4],
    protcol: Ipv4Protcol,
    payload: Bytes,
}

// 外部のサービスが IPv4 を触るときは必ずこの構造体経由で操作するようにしたい。
impl Ipv4FrameUnchecked {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_ipav4addr(mut self, ipv4addr: [u8; 4]) -> Self {
        self.destination_address = ipv4addr;
        self
    }

    // ipv4unchecked の set_payload を Bytes にする。
    pub fn set_payload(mut self, payload: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            payload.len() < IPV4_MAX_PAYLOAD_SIZE,
            "IPv4 payload size exceeds maximum."
        );
        self.payload = Bytes::copy_from_slice(payload);
        Ok(self)
    }

    pub fn set_protcol(mut self, protcol: Ipv4Protcol) -> Self {
        self.protcol = protcol;
        self
    }

    fn build(&self) -> Ipv4Packet {
        if self.payload.len() <= crate::layer2::interface::MTU {
            // フラグメントしなくていいのでそのまま送る。
            let mut pkt = Ipv4PacketUnverified::minimal();
            pkt.set_destination_address_slice(self.destination_address)
                .set_protcol_u8(self.protcol as u8)
                .set_payload(&self.payload);
            pkt.to_ipv4packet()
        } else {
            // フラグメントしてから送る
            unimplemented!()
        }
    }

    pub fn to_safe_ipv4_frames(&self) -> Vec<Ipv4Packet> {
        if self.payload.len() <= crate::layer2::interface::MTU - IPV4_HEADER_LEN {
            // フラグメントしなくていいのでそのまま送る。
            vec![self.build()]
        } else {
            // フラグメントしてから送る。
            let mtu = crate::layer2::interface::MTU;
            let max_payload_size = mtu - IPV4_HEADER_LEN;
            let max_payload_size = max_payload_size & (!0b111); // Round down to the nearest multiple of 8.
            debug_assert_eq!(max_payload_size % 8, 0);

            // Payload を複数 chunk に分割する.
            let mut chunks = self.payload.chunks(max_payload_size);
            let mut ips: Vec<Ipv4Packet> = Vec::new();

            // DF フラグは必ず立てる （デフォルトでたっている）
            // MF フラグは最後のパケットのみ立てない
            // identifier はランダムに作ってしまう。 Todo: identifier を incremental にする。
            let mut flagment_offset = 0;
            let identification = rand::thread_rng().gen::<u16>();
            for chunk in chunks.by_ref() {
                let self_copy = self.clone().set_payload(chunk).unwrap();
                let mut pkt: Ipv4PacketUnverified = self_copy.build().to_unverified();
                pkt.set_fragment_mf_bit(true)
                    .set_flagment_offset(flagment_offset);
                pkt.set_identification(identification);
                flagment_offset = flagment_offset.wrapping_add(chunk.len() as u16);
                ips.push(pkt.to_ipv4packet());
            }

            let last_index = ips.len() - 1;
            ips[last_index] = ips[last_index]
                .clone()
                .to_unverified()
                .set_fragment_mf_bit(false)
                .to_ipv4packet();
            // debug_assert!(!ips.last().unwrap().get_fragment_mf_bit());

            ips
        }
    }

    pub async fn safely_send(&self) -> anyhow::Result<()> {
        for p in self.to_safe_ipv4_frames() {
            p.send().await?;
        }
        Ok(())
    }
}

pub async fn send_udp(
    udppacket: crate::layer4::udp::UdpPacket,
    target_ip: &Ipv4Addr,
) -> anyhow::Result<()> {
    let bytes = udppacket.to_bytes();
    let ip_packet = Ipv4FrameUnchecked::new()
        .set_ipav4addr(target_ip.octets())
        .set_protcol(Ipv4Protcol::Udp)
        .set_payload(&bytes)?;
    ip_packet.safely_send().await
}
