#[derive(Debug, Default, Clone, Copy)]
#[repr(u8)]
pub enum IcmpType {
    #[default]
    Request = 0x08u8,
    // Reply = 0x0,
}

impl IcmpType {
    // pub fn from_u16(a: u16) -> Self {
    //     match a {
    //         0x0001u16 => Self::Request,
    //         0x0002u16 => Self::Reply,
    //         _ => {
    //             unreachable!("{a:?}");
    //         }
    //     }
    // }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Default, Debug, Clone)]
pub struct Icmp {
    pub icmp_type: u8, // 0: Reply, 8: Echo Reqest.
    pub code: u8,
    pub checksum: u16,
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
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.seqence_number.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    // Calculate checksum, and convert to bytes.
    pub fn build_to_bytes(&self) -> Vec<u8> {
        assert_eq!(self.checksum, 0);
        let mut bytes = self.to_bytes();
        let checksum = calc_checksum(&bytes);
        let checksum_slice = checksum.to_be_bytes();
        bytes[2] = checksum_slice[0];
        bytes[3] = checksum_slice[1];
        bytes
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
