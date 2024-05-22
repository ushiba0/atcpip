use bitfield::{Bit, BitMut};
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;

use tokio::sync::broadcast::{self, Receiver};
use tokio::sync::Mutex;

#[derive(Debug, Default, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(u8)]
pub enum Ipv4Protcol {
    Icmp = 0x01,
    // Reply = 0x0,
    #[default]
    Invalid = 0xff,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version_and_header_length: u8, // Default: 0b0100_0101
    pub differenciate_service_field: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u16, // Default: 0.
    pub time_to_live: u8,
    pub protocol: u8,
    _header_checksum: u16, // Should always be zero. Checksum can be calc with self.get_checksum().
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
}

// サイズが MTU に収まっている。
// length, identification, checksum なども計算済みである。
#[derive(Default, Debug, Clone)]
pub struct Ipv4Frame {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

impl Ipv4Header {
    fn minimal() -> Self {
        Self {
            version_and_header_length: 0b0100_0101,
            time_to_live: 64,
            protocol: 1, // 1: ICMP.
            source_address: crate::layer2::interface::MY_IP_ADDRESS,
            total_length: 37,
            ..Default::default()
        }
        .set_fragment_df_bit(true)
        .set_fragment_mf_bit(false)
    }

    fn from_buffer(buf: &[u8]) -> Self {
        Self {
            version_and_header_length: buf[0],
            differenciate_service_field: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            // 上位 1 bit: reserved
            //      2 bit: DF 0 = May Fragment, 1 = Don't Fragment.
            //      3 bit: MF 0 = Last Fragment, 1 = More Fragments.
            flags: u16::from_be_bytes([buf[6], buf[7]]),
            time_to_live: buf[8],
            protocol: buf[9],
            _header_checksum: u16::from_be_bytes([buf[10], buf[11]]),
            source_address: [buf[12], buf[13], buf[14], buf[15]],
            destination_address: [buf[16], buf[17], buf[18], buf[19]],
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.version_and_header_length.to_be_bytes());
        bytes.extend_from_slice(&self.differenciate_service_field.to_be_bytes());
        bytes.extend_from_slice(&self.total_length.to_be_bytes());
        bytes.extend_from_slice(&self.identification.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.time_to_live.to_be_bytes());
        bytes.extend_from_slice(&self.protocol.to_be_bytes());
        assert_eq!(self._header_checksum, 0);
        bytes.extend_from_slice(&self._header_checksum.to_be_bytes());
        bytes.extend_from_slice(&self.source_address);
        bytes.extend_from_slice(&self.destination_address);

        bytes
    }

    // Todo: 今の実装では header のバイト列を生成するときに to_bytes() を 2 回
    // 呼び出しているのでパフォーマンスを気にする場合はメモ化しておく。
    fn get_checksum(&self) -> u16 {
        let bytes = self.to_bytes();
        super::icmp::calc_checksum(&bytes)
    }

    // Calculate IP header checksum and convert to bytes.
    fn build_to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        let checksum = self.get_checksum().to_be_bytes();
        bytes[10] = checksum[0];
        bytes[11] = checksum[1];
        bytes
    }

    fn get_fragment_df_bit(&self) -> bool {
        self.flags.bit(14)
    }

    fn set_fragment_df_bit(mut self, val: bool) -> Self {
        self.flags.set_bit(14, val);
        self
    }

    fn get_fragment_mf_bit(&self) -> bool {
        self.flags.bit(13)
    }

    fn set_fragment_mf_bit(mut self, val: bool) -> Self {
        self.flags.set_bit(13, val);
        self
    }
}

impl Ipv4Frame {
    // pub fn minimal() -> Self {
    //     Self {
    //         header: Ipv4Header::minimal(),
    //         payload: Vec::new(),
    //     }
    // }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.header.build_to_bytes());
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
            self.header.version_and_header_length, 0b0100_0101,
            "Panic here because the current implementation assumes an Ipv4 header length of 20."
        );
        let header_length = 20;
        let total_length = header_length + self.payload.len();
        self.header.total_length = total_length as u16;
        self.to_bytes()
    }

    pub fn from_buffer(buf: &[u8]) -> Self {
        Self {
            header: Ipv4Header::from_buffer(&buf[..20]),
            payload: buf[20..].to_vec(),
        }
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

    loop {
        let ipv4frame = ipv4_receive.recv().await.unwrap();

        // Todo: Checksum と Total length の計算.
        // Todo: 自分宛ての IP Address か確かめる。

        if ipv4frame.header.get_fragment_df_bit() {
            // 即上のレイヤに渡す。
        }

        if ipv4frame.header.get_fragment_mf_bit() {
            // 1 ならキューに貯める。
            // 0 なら一旦 identifier をチェックする必要がある。
        }

        let protcol = Ipv4Protcol::from_u8(ipv4frame.header.protocol).unwrap_or_default();
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
            let mut header = Ipv4Header::minimal();
            header.destination_address = self.destination_address;
            header.protocol = self.protcol as u8;
            Ipv4Frame {
                header,
                payload: self.payload.clone(),
            }
        } else {
            // フラグメントしてから送る。
            unimplemented!()
        }
    }
}
