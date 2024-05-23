use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use tokio::sync::broadcast::{self, Receiver};
use tokio::sync::Mutex;

use crate::layer3::ipv4::Ipv4Frame;

#[derive(Debug, Default, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(u8)]
pub enum IcmpType {
    Reply = 0x0,
    Request = 0x08u8,
    #[default]
    Invalid = 0xff,
}

#[derive(Default, Debug, Clone)]
pub struct Icmp {
    pub icmp_type: u8, // 0: Reply, 8: Echo Reqest.
    pub code: u8,
    _checksum: u16, // Should always be zero. Checksum can be calc with self.get_checksum().
    pub identifier: u16,
    pub sequence_number: u16,
    pub data: Vec<u8>, // Timestamp (8 bytes) + Data (40 bytes).
}

impl Icmp {
    pub fn minimal() -> Self {
        Default::default()
    }
    pub fn echo_reqest_minimal() -> Self {
        Self::minimal().set_icmp_type(IcmpType::Request)
    }

    pub fn echo_reply_minimal() -> Self {
        Self::minimal().set_icmp_type(IcmpType::Reply)
    }

    pub fn set_icmp_type(mut self, icmp_type: IcmpType) -> Self {
        self.icmp_type = icmp_type as u8;
        self
    }

    pub fn set_identifier(mut self, identifier: u16) -> Self {
        self.identifier = identifier;
        self
    }

    pub fn set_sequence_number(mut self, sequence_number: u16) -> Self {
        self.sequence_number = sequence_number;
        self
    }

    pub fn set_payload(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.icmp_type.to_be_bytes());
        bytes.extend_from_slice(&self.code.to_be_bytes());
        // assert_eq!(self._checksum, 0);
        bytes.extend_from_slice(&self._checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    fn get_checksum(&self) -> u16 {
        calc_checksum(&self.to_bytes())
    }

    // Calculate checksum, and convert to bytes.
    pub fn build_to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        let checksum = self.get_checksum().to_be_bytes();
        bytes[2] = checksum[0];
        bytes[3] = checksum[1];
        bytes
    }

    pub fn from_buffer(buf: &[u8]) -> Self {
        Self {
            icmp_type: buf[0],
            code: buf[1],
            _checksum: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
            identifier: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
            sequence_number: u16::from_be_bytes(buf[6..8].try_into().unwrap()),
            data: buf[8..].to_vec(),
        }
    }

    // pub fn to_ipv4_frame(&self, ip: [u8; 4]) -> Ipv4Frame {
    //     let mut ipv4_frame = Ipv4Frame::minimal();
    //     ipv4_frame.header.destination_address = ip;
    //     ipv4_frame.payload = self.build_to_bytes();
    //     ipv4_frame
    // }

    pub fn to_ipv4(&self, ip: [u8; 4]) -> anyhow::Result<super::ipv4::Ipv4FrameUnchecked> {
        super::ipv4::Ipv4FrameUnchecked::new()
            .set_ipav4addr(ip)
            .set_protcol(super::ipv4::Ipv4Protcol::Icmp)
            .set_payload(&self.build_to_bytes())
    }
}

pub fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum = 0usize;
    let mut chunks = data.chunks_exact(2);

    // 2 バイトずつ読み取り和を取る.
    for chunk in chunks.by_ref() {
        let part = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(part as usize);
    }

    // data.len() が奇数長の場合は最後の 1 バイトを処理する.
    if let Some(&last_byte) = chunks.remainder().first() {
        let part = u16::from_be_bytes([last_byte, 0]);
        sum = sum.wrapping_add(part as usize);
    }

    // Handle carries.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

async fn send_icmp_echo_reply(
    ipv4_frame: Ipv4Frame,
    icmp_echo_request: Icmp,
) -> anyhow::Result<()> {
    let echo_reply = Icmp::echo_reply_minimal()
        .set_identifier(icmp_echo_request.identifier)
        .set_sequence_number(icmp_echo_request.sequence_number)
        .set_payload(&icmp_echo_request.data);

    echo_reply
        .to_ipv4(ipv4_frame.source_address)?
        .build()
        .send()
        .await?;

    log::trace!("Sent an ICMP Echo Reply: {echo_reply:?}");
    Ok(())
}

pub static ICMP_REPLY_NOTIFIER: Lazy<Mutex<Option<Receiver<Ipv4Frame>>>> =
    Lazy::new(Default::default);

pub async fn icmp_handler(mut icmp_receive: Receiver<Ipv4Frame>) {
    // 必要にであれば icmp_receive をクローンして Global 変数として保存する。
    // いまは必要ないためそうしていない。

    // ICMP の受信を通知するためのチャネル.
    let (icmp_notifier_sender, icmp_notifier_receiver) = broadcast::channel::<Ipv4Frame>(2);
    *ICMP_REPLY_NOTIFIER.lock().await = Some(icmp_notifier_receiver);

    loop {
        let ipv4frame = icmp_receive.recv().await.unwrap();
        let icmp = Icmp::from_buffer(&ipv4frame.payload);

        // Checksum の計算
        if icmp.get_checksum() != 0 {
            log::warn!("Detected ICMP checksum error for packet: {ipv4frame:x?}");
        }

        // Todo: Total length の計算.

        let icmp_type = IcmpType::from_u8(icmp.icmp_type).unwrap_or_default();
        match icmp_type {
            IcmpType::Reply => {
                log::trace!("ICMP Reply Received. : {:x?}", icmp);
                icmp_notifier_sender.send(ipv4frame.clone()).unwrap();
            }
            IcmpType::Request => {
                log::trace!("ICMP Echo Reqest.");
                send_icmp_echo_reply(ipv4frame, icmp).await.unwrap();
            }
            _ => {
                log::warn!("Uninplemented.");
            }
        }
    }
}

#[test]
fn test_icmp_checksum() {
    let echo_reqest = Icmp::echo_reqest_minimal()
        .set_identifier(0x7f16)
        .set_sequence_number(60)
        .set_payload(&vec![0xda; 100]);
    assert_eq!(echo_reqest.get_checksum(), 0xb9ee);
}
