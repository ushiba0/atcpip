use bit_field::BitField;
use bytes::{BufMut, Bytes, BytesMut};

use crate::{impl_get, impl_get_bit, impl_set, impl_set_bit};

const TCP_HEADER_SIZE_MINIMAL_BYTES: usize = 20;

// Ref: https://datatracker.ietf.org/doc/html/rfc793
#[derive(Debug, Default, PartialEq, Clone)]
pub struct TcpPacket {
    bytes: Bytes,
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct TcpPacketMut {
    bytes: BytesMut,
}

impl TcpPacket {
    pub fn from_bytes(bytes: &Bytes) -> Self {
        Self {
            bytes: bytes.clone(),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    impl_get!(get_source_port, bytes, 0, 2, u16);
    impl_get!(get_target_port, bytes, 2, 4, u16);
    impl_get!(get_seqence_number, bytes, 4, 8, u32);
    impl_get!(get_ack_number, bytes, 8, 12, u32);
    impl_get_bit!(get_ns_bit, bytes, 12, 0);
    impl_get_bit!(get_cwr_bit, bytes, 13, 7);
    impl_get_bit!(get_ece_bit, bytes, 13, 6);
    impl_get_bit!(get_urg_bit, bytes, 13, 5);
    impl_get_bit!(get_ack_bit, bytes, 13, 4);
    impl_get_bit!(get_psh_bit, bytes, 13, 3);
    impl_get_bit!(get_rst_bit, bytes, 13, 2);
    impl_get_bit!(get_syn_bit, bytes, 13, 1);
    impl_get_bit!(get_fin_bit, bytes, 13, 0);
    impl_get!(get_window_size, bytes, 14, 16, u16);
    impl_get!(get_checksum, bytes, 16, 18, u16);
    impl_get!(get_urgent_pointer, bytes, 18, 20, u16);

    // Returns 4 bit data.
    fn get_header_length_raw(&self) -> u8 {
        self.bytes[12].get_bits(4..8)
    }

    // Returns 4 bit data.
    pub fn get_header_length_bytes(&self) -> u8 {
        self.get_header_length_raw() * 4
    }

    pub fn get_payload(&self) -> Bytes {
        self.bytes.slice(8..)
    }

    pub fn send(&self) {}
}

impl TcpPacketMut {
    pub fn minimal() -> Self {
        Self {
            bytes: BytesMut::zeroed(TCP_HEADER_SIZE_MINIMAL_BYTES),
        }
    }

    pub fn build_mock(&self) -> TcpPacket {
        TcpPacket {
            bytes: self.bytes.clone().freeze(),
        }
    }

    impl_set!(set_source_port, bytes, 0, 2, u16);
    impl_set!(set_target_port, bytes, 2, 4, u16);
    impl_set!(set_seqence_number, bytes, 4, 8, u32);
    impl_set!(set_ack_number, bytes, 8, 12, u32);
    impl_set_bit!(set_ns_bit, bytes, 12, 0);
    impl_set_bit!(set_cwr_bit, bytes, 13, 7);
    impl_set_bit!(set_ece_bit, bytes, 13, 6);
    impl_set_bit!(set_urg_bit, bytes, 13, 5);
    impl_set_bit!(set_ack_bit, bytes, 13, 4);
    impl_set_bit!(set_psh_bit, bytes, 13, 3);
    impl_set_bit!(set_rst_bit, bytes, 13, 2);
    impl_set_bit!(set_syn_bit, bytes, 13, 1);
    impl_set_bit!(set_fin_bit, bytes, 13, 0);
    impl_set!(set_window_size, bytes, 14, 16, u16);
    impl_set!(set_checksum, bytes, 16, 18, u16);
    impl_set!(set_urgent_pointer, bytes, 18, 20, u16);

    // Input: 4 bit data. Number of words.
    fn set_header_length_raw(&mut self, value: u8) -> &mut Self {
        debug_assert!((5..=15).contains(&value), "Invalid TCP header len: {value}");
        self.bytes[12].set_bits(4..8, value & 0b1111);
        self
    }

    pub fn set_header_length_bytes(&mut self, value: u8) -> &mut Self {
        debug_assert_eq!(value % 4, 0, "Value is not multiple of word.");
        self.set_header_length_raw(value / 4);
        self
    }

    fn calc_checksum(&self) -> u16 {
        let mut bm = BytesMut::new();
        bm.put_slice(&crate::layer2::interface::MY_IP_ADDRESS);
        bm.put_slice(&[192, 168, 1, 142]);
        bm.put_u16(0);
        bm.put_u16(6); // TCP Protcol number.
        bm.put_u16(self.bytes.len() as u16); // Packet length.
        bm.put(self.bytes.clone());
        let b = bm.freeze();
        crate::common::calc_checksum(&b)
    }

    pub fn calc_and_set_checksum(&mut self) -> &mut Self {
        self.set_checksum(0);
        let checksum = self.calc_checksum();
        self.set_checksum(checksum);
        self
    }
}
