use std::collections::{HashMap, HashSet};
use std::ops::Range;

use bit_field::BitField;
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use rand::Rng;

use tokio::sync::broadcast::{self, Receiver};
use tokio::sync::Mutex;

const IPV4_HEADER_LEN: usize = 20;

#[derive(Debug, Default, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(u8)]
pub enum Ipv4Protcol {
    Icmp = 0x01,
    // Reply = 0x0,
    #[default]
    Invalid = 0xff,
}

// #[derive(Default, Debug, Clone, Copy)]
// pub struct Ipv4Header {
//     pub version_and_header_length: u8, // Default: 0b0100_0101
//     pub differenciate_service_field: u8,
//     pub total_length: u16,
//     pub identification: u16,
//     // 上位 1 bit: reserved
//     //      2 bit: DF 0 = May Fragment, 1 = Don't Fragment.
//     //      3 bit: MF 0 = Last Fragment, 1 = More Fragments.
//     pub flags: u16, // Default: 0.
//     pub time_to_live: u8,
//     pub protocol: u8,
//     _header_checksum: u16, // Should always be zero. Checksum can be calc with self.get_checksum().
//     pub source_address: [u8; 4],
//     pub destination_address: [u8; 4],
// }

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
    _header_checksum: u16, // Should always be zero. Checksum can be calc with self.get_checksum().
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],

    // pub header: Ipv4Header,
    pub payload: Vec<u8>,
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
            payload: buf[20..].to_vec(),
        }
    }

    fn header_to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.version_and_header_length.to_be_bytes());
        bytes.extend_from_slice(&self.differenciate_service_field.to_be_bytes());
        bytes.extend_from_slice(&self.total_length.to_be_bytes());
        bytes.extend_from_slice(&self.identification.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.time_to_live.to_be_bytes());
        bytes.extend_from_slice(&self.protocol.to_be_bytes());
        // assert_eq!(self._header_checksum, 0);
        bytes.extend_from_slice(&self._header_checksum.to_be_bytes());
        bytes.extend_from_slice(&self.source_address);
        bytes.extend_from_slice(&self.destination_address);

        bytes
    }

    // Todo: 今の実装では header のバイト列を生成するときに to_bytes() を 2 回
    // 呼び出しているのでパフォーマンスを気にする場合はメモ化しておく。
    fn get_checksum(&self) -> u16 {
        let bytes = self.header_to_bytes();
        super::icmp::calc_checksum(&bytes)
    }

    // Calculate IP header checksum and convert to bytes.
    fn header_build_to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header_to_bytes();
        let checksum = self.get_checksum().to_be_bytes();
        bytes[10] = checksum[0];
        bytes[11] = checksum[1];
        bytes
    }

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
}

impl Ipv4Frame {
    // pub fn minimal() -> Self {
    //     Self {
    //         header: Ipv4Header::minimal(),
    //         payload: Vec::new(),
    //         ..Default::default()
    //     }
    // }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.header_build_to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    pub async fn send(&self) -> anyhow::Result<usize> {
        crate::layer2::ethernet::send_ipv4(self.clone()).await
    }

    // Calculate checksum, fill total_length
    // and convert to bytes.
    pub fn build_to_bytes(&mut self) -> Vec<u8> {
        assert_eq!(
            self.version_and_header_length, 0b0100_0101,
            "Panic here because the current implementation assumes an Ipv4 header length of 20."
        );
        let header_length = IPV4_HEADER_LEN;
        let total_length = header_length + self.payload.len();
        self.total_length = total_length as u16;
        self.to_bytes()
    }

    // pub fn from_buffer(buf: &[u8]) -> Self {
    //     Self {
    //         header: Ipv4Header::from_buffer(&buf[..IPV4_HEADER_LEN]),
    //         payload: buf[IPV4_HEADER_LEN..].to_vec(),
    //         ..Default::default()
    //     }
    // }

    fn set_destinatoin_address(mut self, ip: [u8; 4]) -> Self {
        self.destination_address = ip;
        self
    }

    fn set_protcol(mut self, protcol: Ipv4Protcol) -> Self {
        self.protocol = protcol as u8;
        self
    }

    fn set_payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
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

    // <identifier, Vec<IPv4Frame>>
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
            Some(v) => v,
            None => continue,
        };

        // Todo:  Total length の確認。
        // Todo: 自分宛ての IP Address か確かめる。

        if ipv4frame.get_fragment_df_bit() {
            // 受信側が DF フラグを処理する必要はない。
        }

        if ipv4frame.get_fragment_mf_bit() {
            // 1 ならキューに貯める。
            // 0 なら一旦 identifier をチェックする必要がある。
        }

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
) -> Option<Ipv4Frame> {
    let packets = tmp_pool
        .entry(ipv4_frame.identification)
        .and_modify(|val| {
            val.push(ipv4_frame.clone());
        })
        .or_insert(vec![ipv4_frame.clone()]);

    // mf==false のパケットが来たら rebuild を実行する。
    if packets.last()?.get_fragment_mf_bit() == true {
        return None;
    }

    let mut hs: HashSet<Range<u16>> = HashSet::new();
    let mut concat_data = vec![0u8; 65536];

    // 区間に被りがあるか確認する関数。
    fn test_range(hs: &HashSet<Range<u16>>, ran: &Range<u16>) -> bool {
        let start = ran.start;
        let end = ran.end;
        for hanni in hs {
            if hanni.contains(&start) || hanni.contains(&end) {
                return false;
            }
        }
        true
    }

    for packet in packets.iter() {
        let size = packet.total_length - IPV4_HEADER_LEN as u16;
        let off = packet.get_fragment_offset();
        let range_start = off;
        let range_end = range_start + size;
        let ra = range_start..range_end;

        if test_range(&hs, &ra) {
            // 挿入していいか判断して、OK ならいれる。
            hs.insert(ra);
            concat_data[(range_start as usize)..(range_end as usize)]
                .copy_from_slice(&packet.payload);
        } else {
            log::error!("区間に被りがあるので後で破棄すべき。");
            return None;
        }
    }

    // range をできるだけ結合する。
    fn merge_ranges(ranges: &Vec<Range<u16>>) -> Vec<Range<u16>> {
        if ranges.is_empty() {
            return Vec::new();
        }

        // rangesをstartでソート
        let mut sorted_ranges = ranges.clone();
        sorted_ranges.sort_by_key(|r| r.start);

        let mut merged_ranges = Vec::new();
        let mut current_range = sorted_ranges[0].clone();

        for range in sorted_ranges.into_iter().skip(1) {
            if range.start <= current_range.end {
                // 現在の範囲に結合できる場合、endを更新
                current_range.end = current_range.end.max(range.end);
            } else {
                // 現在の範囲をmerged_rangesに追加し、新しい範囲を設定
                merged_ranges.push(current_range);
                current_range = range.clone();
            }
        }

        // 最後の範囲を追加
        merged_ranges.push(current_range);

        merged_ranges
    }

    let vec_range = hs.into_iter().collect::<Vec<Range<u16>>>();
    let mergd_range = merge_ranges(&vec_range);

    if mergd_range.len() > 1 {
        None
    } else if mergd_range.len() == 1 {
        let payload =
            concat_data[mergd_range[0].start as usize..mergd_range[0].end as usize].to_vec();
        let mut packet1 = packets.first()?.clone();
        packet1.payload = payload;
        Some(packet1)
    } else {
        None
    }
}

/* ======== */

#[derive(Default, Debug, Clone)]
pub struct Ipv4FrameUnchecked {
    destination_address: [u8; 4],
    protcol: Ipv4Protcol,
    payload: Vec<u8>,
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
        let payload = payload.to_vec();
        anyhow::ensure!(payload.len() < 65536, "IPv4 payload size exceeds maximum.");
        self.payload = payload.to_vec();
        Ok(self)
    }

    pub fn set_protcol(mut self, protcol: Ipv4Protcol) -> Self {
        self.protcol = protcol;
        self
    }

    pub fn build(&self) -> Ipv4Frame {
        if self.payload.len() <= crate::layer2::interface::MTU {
            // フラグメントしなくていいのでそのまま送る。
            Ipv4Frame::minimal()
                .set_destinatoin_address(self.destination_address)
                .set_protcol(self.protcol)
                .set_payload(&self.payload)
        } else {
            // フラグメントしてから送る。
            unimplemented!()
        }
    }

    pub fn to_safe_ipv4_frame(&self) -> Vec<Ipv4Frame> {
        if self.payload.len() <= crate::layer2::interface::MTU {
            // フラグメントしなくていいのでそのまま送る。
            vec![self.build()]
        } else {
            // フラグメントしてから送る。
            let mtu = crate::layer2::interface::MTU;
            let max_payload_size = mtu - IPV4_HEADER_LEN as usize;
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
        for p in self.to_safe_ipv4_frame() {
            p.send().await?;
        }
        Ok(())
    }
}
