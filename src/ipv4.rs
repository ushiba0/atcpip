#[derive(Default, Debug, Clone)]
pub struct Ipv4Header {
    pub version_and_header_length: u8, // Default: 0b0100_0101
    pub differenciate_service_field: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u16, // Default: 0.
    pub time_to_live: u8,
    pub protocol: u8,
    _header_checksum: u16, // Should always be zero. Checksum can be calc with
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
}

#[derive(Default, Debug, Clone)]
pub struct Ipv4Frame {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

impl Ipv4Header {
    pub fn minimal() -> Self {
        Self {
            version_and_header_length: 0b0100_0101,
            time_to_live: 64,
            protocol: 1, // 1: ICMP.
            source_address: crate::interface::MY_IP_ADDRESS,
            total_length: 37,
            ..Default::default()
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
        crate::icmp::calc_checksum(&bytes)
    }

    // Calculate IP header checksum and convert to bytes.
    fn build_to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        let checksum = self.get_checksum().to_be_bytes();
        bytes[10] = checksum[0];
        bytes[11] = checksum[1];
        bytes
    }
}

impl Ipv4Frame {
    pub fn minimal() -> Self {
        Self {
            header: Ipv4Header::minimal(),
            payload: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.header.build_to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    pub async fn send(&self) -> anyhow::Result<usize> {
        crate::ethernet::send_ipv4(self.clone()).await
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
}
