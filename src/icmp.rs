use tokio::sync::broadcast::Receiver;

#[derive(Debug, Default, Clone, Copy)]
#[repr(u8)]
pub enum IcmpType {
    Reply = 0x0,
    #[default]
    Request = 0x08u8,
    Unimplemented = 0xff,
}

impl IcmpType {
    pub fn from_u8(a: u8) -> Self {
        match a {
            0x00 => Self::Reply,
            0x08 => Self::Request,
            _ => Self::Unimplemented,
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Default, Debug, Clone)]
pub struct Icmp {
    pub icmp_type: u8, // 0: Reply, 8: Echo Reqest.
    pub code: u8,
    _checksum: u16, // Should always be zero. Checksum can be calc with self.get_checksum().
    pub identifier: u16,
    pub seqence_number: u16,
    pub data: Vec<u8>, // Timestamp (8 bytes) + Data (40 bytes).
}

impl Icmp {
    pub fn echo_reqest_minimal() -> Self {
        Self {
            icmp_type: IcmpType::Request.as_u8(),
            ..Default::default()
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.icmp_type.to_be_bytes());
        bytes.extend_from_slice(&self.code.to_be_bytes());
        assert_eq!(self._checksum, 0);
        bytes.extend_from_slice(&self._checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.seqence_number.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    fn get_checksum(&self) -> u16 {
        let bytes = self.to_bytes();
        crate::icmp::calc_checksum(&bytes)
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
            _checksum: u16::from_be_bytes([buf[2], buf[3]]),
            identifier: u16::from_be_bytes([buf[4], buf[5]]),
            seqence_number: u16::from_be_bytes([buf[6], buf[7]]),
            data: buf[8..].to_vec(),
        }
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
    ipv4header: crate::ipv4::Ipv4Header,
    icmp: Icmp,
) -> anyhow::Result<()> {
    let mut echo_reply = crate::icmp::Icmp::echo_reqest_minimal();

    echo_reply.icmp_type = IcmpType::Reply.as_u8();
    echo_reply.identifier = icmp.identifier;
    echo_reply.seqence_number = icmp.seqence_number;
    echo_reply.data = icmp.data;

    let mut ipv4_icmp_echo_reply_frame = crate::ipv4::Ipv4Frame::minimal();
    ipv4_icmp_echo_reply_frame.header.destination_address = ipv4header.source_address;
    ipv4_icmp_echo_reply_frame.payload = echo_reply.build_to_bytes();

    ipv4_icmp_echo_reply_frame.send().await.unwrap();
    log::error!("Sent an ICMP Echo Reply: {echo_reply:?}");

    Ok(())
}

pub async fn icmp_handler(mut icmp_receive: Receiver<crate::ipv4::Ipv4Frame>) {
    // 必要にであれば icmp_receive をクローンして Global 変数として保存する。
    // いまは必要ないためそうしていない。

    loop {
        let ipv4frame = icmp_receive.recv().await.unwrap();
        let icmp = crate::icmp::Icmp::from_buffer(&ipv4frame.payload);

        // Todo: Checksum と Total length の計算.

        let icmp_type = IcmpType::from_u8(icmp.icmp_type);
        match icmp_type {
            IcmpType::Reply => {
                log::warn!("ICMP Reply Received. : {:x?}", icmp);
            }
            IcmpType::Request => {
                log::warn!("ICMP Echo Reqest.");
                send_icmp_echo_reply(ipv4frame.header, icmp).await.unwrap();
            }
            _ => {
                log::warn!("Uninplemented.");
            }
        }
    }
}
