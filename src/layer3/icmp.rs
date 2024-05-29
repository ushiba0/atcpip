use bytes::{Bytes, BytesMut};
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use tokio::sync::broadcast::{self, Receiver};

use crate::common::calc_checksum;
use crate::layer3::ipv4::Ipv4Packet;

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
    pub data: Bytes, // Timestamp (8 bytes) + Data (40 bytes).
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
        self.data = Bytes::copy_from_slice(data);
        self
    }

    fn to_bytes_inner(&self) -> BytesMut {
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&self.icmp_type.to_be_bytes());
        bytes.extend_from_slice(&self.code.to_be_bytes());
        bytes.extend_from_slice(&self._checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    // Calculate checksum, and convert to bytes.
    pub fn build_to_bytes(&self) -> Bytes {
        let mut bytes = self.to_bytes_inner();
        let checksum = calc_checksum(&bytes).to_be_bytes();
        bytes[2] = checksum[0];
        bytes[3] = checksum[1];
        bytes.freeze()
    }

    fn get_checksum(&self) -> u16 {
        calc_checksum(&self.to_bytes_inner())
    }

    pub fn from_buffer(buf: &[u8]) -> Self {
        Self {
            icmp_type: buf[0],
            code: buf[1],
            _checksum: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
            identifier: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
            sequence_number: u16::from_be_bytes(buf[6..8].try_into().unwrap()),
            data: Bytes::copy_from_slice(&buf[8..]),
        }
    }

    pub fn to_ipv4(&self, ip: [u8; 4]) -> anyhow::Result<super::ipv4::Ipv4FrameUnchecked> {
        super::ipv4::Ipv4FrameUnchecked::new()
            .set_ipav4addr(ip)
            .set_protcol(super::ipv4::Ipv4Protcol::Icmp)
            .set_payload(&self.build_to_bytes())
    }
}

async fn send_icmp_echo_reply(
    ipv4_frame: Ipv4Packet,
    icmp_echo_request: Icmp,
) -> anyhow::Result<()> {
    let echo_reply = Icmp::echo_reply_minimal()
        .set_identifier(icmp_echo_request.identifier)
        .set_sequence_number(icmp_echo_request.sequence_number)
        .set_payload(&icmp_echo_request.data);

    echo_reply
        .to_ipv4(ipv4_frame.get_source_address().octets())?
        .safely_send()
        .await?;

    log::trace!(
        "Sent an ICMP Echo Reply to IP {}. ICMP data size: {}.",
        ipv4_frame.get_source_address(),
        icmp_echo_request.data.len()
    );
    Ok(())
}

pub static ICMP_REPLY_NOTIFIER: Lazy<
    parking_lot::RwLock<(
        broadcast::Sender<Ipv4Packet>,
        broadcast::Receiver<Ipv4Packet>,
    )>,
> = Lazy::new(|| {
    let (icmp_notifier_sender, icmp_notifier_receiver) = broadcast::channel::<Ipv4Packet>(2);
    RwLock::new((icmp_notifier_sender, icmp_notifier_receiver))
});

pub async fn icmp_handler(mut icmp_receive: Receiver<Ipv4Packet>) {
    // 必要にであれば icmp_receive をクローンして Global 変数として保存する。
    // いまは必要ないためそうしていない。

    // ICMP の受信を通知するためのチャネル.
    // let (icmp_notifier_sender, icmp_notifier_receiver) = broadcast::channel::<Ipv4Packet>(2);
    // *ICMP_REPLY_NOTIFIER.lock().await = Some(icmp_notifier_receiver);
    let icmp_notifier_sender = ICMP_REPLY_NOTIFIER.read().0.clone();

    loop {
        let ipv4frame = icmp_receive.recv().await.unwrap();
        let icmp = Icmp::from_buffer(&ipv4frame.get_payload());

        // Checksum の計算
        if icmp.get_checksum() != 0 {
            log::warn!("Detected ICMP checksum error for packet: {ipv4frame:x?}");
            continue;
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
        .set_payload(&[0xda; 100]);
    assert_eq!(echo_reqest.get_checksum(), 0xb9ee);
}
