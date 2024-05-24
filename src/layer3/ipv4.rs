use std::collections::HashMap;
use std::ops::Range;

use anyhow::{bail, Context};
use bit_field::BitField;
use bytes::{Bytes, BytesMut};
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use rand::Rng;

use tokio::sync::broadcast::{self, Receiver};
use tokio::sync::Mutex;

const IPV4_HEADER_LEN: usize = 20;
const IPV4_MAX_PAYLOAD_SIZE: usize = 65536;

#[derive(Debug, Default, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(u8)]
pub enum Ipv4Protcol {
    Icmp = 0x01,
    // Reply = 0x0,
    #[default]
    Invalid = 0xff,
}

// サイズが MTU に収まっている。
// length, identification, checksum なども計算済みである。
#[derive(Default, Debug, Clone)]
pub struct Ipv4Frame {
    pub version_and_header_length: u8, // Default: 0b0100_0101
    pub differenciate_service_field: u8,
    pub total_length: u16,
    pub identification: u16,
    // 上位 1 bit: reserved
    //      2 bit: DF 0 = May Fragment, 1 = Don't Fragment.
    //      3 bit: MF 0 = Last Fragment, 1 = More Fragments.
    pub flags: u16, // Default: 0.
    pub time_to_live: u8,
    pub protocol: u8,
    _header_checksum: u16,
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],

    // pub header: Ipv4Header,
    pub payload: Bytes,
}

impl Ipv4Frame {
    fn minimal() -> Self {
        Self {
            version_and_header_length: 0b0100_0101,
            time_to_live: 64,
            protocol: 1, // 1: ICMP.
            source_address: crate::layer2::interface::MY_IP_ADDRESS,
            ..Default::default()
        }
        .set_fragment_df_bit(true)
        .set_fragment_mf_bit(false)
    }

    pub fn from_buffer(buf: &[u8]) -> Self {
        Self {
            version_and_header_length: buf[0],
            differenciate_service_field: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            flags: u16::from_be_bytes([buf[6], buf[7]]),
            time_to_live: buf[8],
            protocol: buf[9],
            _header_checksum: u16::from_be_bytes([buf[10], buf[11]]),
            source_address: [buf[12], buf[13], buf[14], buf[15]],
            destination_address: [buf[16], buf[17], buf[18], buf[19]],
            payload: Bytes::copy_from_slice(&buf[20..]),
        }
    }

    // IPv4 Header を Bytes に変換. checksum, length などは計算せずにシンプルにバイト列に変換する。
    fn get_header_bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&self.version_and_header_length.to_be_bytes());
        bytes.extend_from_slice(&self.differenciate_service_field.to_be_bytes());
        bytes.extend_from_slice(&self.total_length.to_be_bytes());
        bytes.extend_from_slice(&self.identification.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.time_to_live.to_be_bytes());
        bytes.extend_from_slice(&self.protocol.to_be_bytes());
        bytes.extend_from_slice(&self._header_checksum.to_be_bytes());
        bytes.extend_from_slice(&self.source_address);
        bytes.extend_from_slice(&self.destination_address);
        bytes
    }

    // Header checksum を計算したうえでバイト列に変換する。
    fn get_header_bytes_with_checksum(&self) -> Bytes {
        let mut bytes = self.get_header_bytes();
        let checksum = super::icmp::calc_checksum(&bytes).to_be_bytes();
        // let checksum = self.get_checksum().to_be_bytes();
        bytes[10] = checksum[0];
        bytes[11] = checksum[1];
        bytes.freeze()
    }

    // Concatinate header bytes and payload bytes.
    fn to_bytes_inner(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&self.get_header_bytes_with_checksum());
        bytes.extend_from_slice(&self.payload);
        bytes.freeze()
    }

    // Calculate checksum, fill total_length
    // and convert to bytes.
    pub fn build_to_bytes(&mut self) -> Bytes {
        assert_eq!(
            self.version_and_header_length, 0b0100_0101,
            "Panic here because the current implementation assumes an Ipv4 header length of 20."
        );
        self.total_length = (IPV4_HEADER_LEN + self.payload.len()) as u16;
        self.to_bytes_inner()
    }

    // Todo: 今の実装では header のバイト列を生成するときに to_bytes() を 2 回
    // 呼び出しているのでパフォーマンスを気にする場合はメモ化しておく。
    fn get_checksum(&self) -> u16 {
        let bytes = self.get_header_bytes();
        super::icmp::calc_checksum(&bytes)
    }

    #[allow(dead_code)]
    fn get_fragment_df_bit(&self) -> bool {
        self.flags.get_bit(14)
    }

    fn set_fragment_df_bit(mut self, val: bool) -> Self {
        self.flags.set_bit(14, val);
        self
    }

    fn get_fragment_mf_bit(&self) -> bool {
        self.flags.get_bit(13)
    }

    fn set_fragment_mf_bit(mut self, val: bool) -> Self {
        self.flags.set_bit(13, val);
        self
    }

    fn get_fragment_offset(&self) -> u16 {
        self.flags.get_bits(0..13) << 3
    }

    fn set_flagment_offset(mut self, offset: u16) -> Self {
        assert_eq!(offset % 8, 0);
        let offset = offset >> 3;
        self.flags.set_bits(0..13, offset);
        self
    }

    pub async fn send(&self) -> anyhow::Result<usize> {
        crate::layer2::ethernet::send_ipv4(self.clone()).await
    }

    fn set_destinatoin_address(mut self, ip: [u8; 4]) -> Self {
        self.destination_address = ip;
        self
    }

    fn set_protcol(mut self, protcol: Ipv4Protcol) -> Self {
        self.protocol = protcol as u8;
        self
    }

    fn set_payload(mut self, payload: &[u8]) -> Self {
        self.payload = Bytes::copy_from_slice(payload);
        self.total_length = (IPV4_HEADER_LEN + self.payload.len()) as u16;
        self
    }
}

static IPV4_RECEIVER: Lazy<Mutex<Option<Receiver<Ipv4Frame>>>> = Lazy::new(Default::default);

pub async fn ipv4_handler(mut ipv4_receive: Receiver<Ipv4Frame>) {
    *IPV4_RECEIVER.lock().await = Some(ipv4_receive.resubscribe());

    // ICMP の襲来を通知するチャネル.
    let (icmp_rx_sender, icmp_rx_receiver) = broadcast::channel::<Ipv4Frame>(2);

    // Spawn ICMP handler.
    tokio::spawn(async move {
        super::icmp::icmp_handler(icmp_rx_receiver).await;
    });

    // Buffer for IP Fragmentation.
    let mut tmp_pool: HashMap<u16, Vec<Ipv4Frame>> = HashMap::new();

    loop {
        let ipv4frame = ipv4_receive.recv().await.unwrap();

        // Checksum の確認
        if ipv4frame.get_checksum() != 0 {
            log::warn!("Detected IPv4 checksum error for packet: {ipv4frame:x?}");
            // Continue することで Drop する。
            // Todo: Error stats counter を実装してカウントアップする。
            continue;
        }

        // リビルド。
        let ipv4frame = match ipv4_rebuild_fragment(&mut tmp_pool, &ipv4frame) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("IPv4 packet reassemble failed. {e:?}");
                continue;
            }
        };

        // Todo:  Total length の確認。
        // Todo: 自分宛ての IP Address か確かめる。

        let protcol = Ipv4Protcol::from_u8(ipv4frame.protocol).unwrap_or_default();
        match protcol {
            Ipv4Protcol::Icmp => {
                icmp_rx_sender.send(ipv4frame).unwrap();
            }

            _ => {
                log::warn!("Uninplemented.");
            }
        }
    }
}

fn ipv4_rebuild_fragment(
    tmp_pool: &mut HashMap<u16, Vec<Ipv4Frame>>,
    ipv4_frame: &Ipv4Frame,
) -> anyhow::Result<Ipv4Frame> {
    tmp_pool
        .entry(ipv4_frame.identification)
        .and_modify(|val| {
            val.push(ipv4_frame.clone());
        })
        .or_insert(vec![ipv4_frame.clone()]);

    // MF==true のパケットの場合は return する。
    // 現在の実装では MF==false のパケットが来ない限り rebuild しない。
    if ipv4_frame.get_fragment_mf_bit() {
        bail!("MF==true なのでリアセンブルしない。");
    }

    // MF==false のパケットを受け取ったら即 pool から廃棄する。
    let packets = tmp_pool
        .remove(&ipv4_frame.identification)
        .context("No packtes.")?;

    let mut fragment_range_list: Vec<Range<usize>> = Vec::new();
    let mut concatenated_payload = BytesMut::with_capacity(IPV4_MAX_PAYLOAD_SIZE);

    for packet in packets.iter() {
        let data_size = packet.total_length as usize - IPV4_HEADER_LEN;
        let data_offset = packet.get_fragment_offset() as usize;
        let range = data_offset..(data_offset + data_size);
        fragment_range_list.push(range.clone());
        concatenated_payload[range].copy_from_slice(&packet.payload[..data_size]);
    }

    let merged_range = concatenate_ranges(&fragment_range_list)?;
    let reassembled_payload = &concatenated_payload[0..merged_range];
    let reassembled_packet = ipv4_frame.clone().set_payload(reassembled_payload);
    Ok(reassembled_packet)
}

// Range を結合し、そのサイズを返す。
// Range に Hole や被りがあると Err を返す。
fn concatenate_ranges(ranges: &[Range<usize>]) -> anyhow::Result<usize> {
    // ranges を start でソート。
    let mut sorted_ranges = ranges.to_owned();
    sorted_ranges.sort_by_key(|r| r.start);

    if sorted_ranges.first().context("Empty.")?.start != 0 {
        bail!("Range start is not 0.");
    }

    let mut current_end = 0;
    for range in ranges.iter() {
        if range.start == current_end {
            current_end = range.end;
        } else {
            bail!("Range has some hole.")
        }
    }

    log::trace!("IPv4 will be reassembled in range: 0..{current_end}");
    Ok(current_end)
}

/* ======== */

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

    fn build(&self) -> Ipv4Frame {
        if self.payload.len() <= crate::layer2::interface::MTU {
            // フラグメントしなくていいのでそのまま送る。
            Ipv4Frame::minimal()
                .set_destinatoin_address(self.destination_address)
                .set_protcol(self.protcol)
                .set_payload(&self.payload)
        } else {
            // フラグメントしてから送る
            unimplemented!()
        }
    }

    pub fn to_safe_ipv4_frames(&self) -> Vec<Ipv4Frame> {
        if self.payload.len() <= crate::layer2::interface::MTU - IPV4_HEADER_LEN {
            // フラグメントしなくていいのでそのまま送る。
            vec![self.build()]
        } else {
            // フラグメントしてから送る。
            let mtu = crate::layer2::interface::MTU;
            let max_payload_size = mtu - IPV4_HEADER_LEN;
            let max_payload_size = max_payload_size & (!0b111); // 8 で round する。
            debug_assert_eq!(max_payload_size % 8, 0);

            // Payload を複数 chunk に分割する.
            let mut chunks = self.payload.chunks(max_payload_size);
            let mut ips: Vec<Ipv4Frame> = Vec::new();

            // DF フラグは必ず立てる （デフォルトでたっている）
            // MF フラグは最後のパケットのみ立てない
            // identifier はランダムに作ってしまう。 Todo: identifier を incremental にする。
            let mut flagment_offset = 0;
            let identification = rand::thread_rng().gen::<u16>();
            for chunk in chunks.by_ref() {
                let self_copy = self.clone().set_payload(chunk).unwrap();
                let mut safe_ipv4frame = self_copy
                    .build()
                    .set_fragment_mf_bit(true)
                    .set_flagment_offset(flagment_offset);
                safe_ipv4frame.identification = identification;
                flagment_offset = flagment_offset.wrapping_add(chunk.len() as u16);
                ips.push(safe_ipv4frame);
            }

            let last_index = ips.len() - 1;
            ips[last_index] = ips[last_index].clone().set_fragment_mf_bit(false);

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
