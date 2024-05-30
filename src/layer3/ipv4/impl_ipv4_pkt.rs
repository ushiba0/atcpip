use std::net::Ipv4Addr;

use bit_field::BitField;
use bytes::{Bytes, BytesMut};

use crate::common::calc_checksum;

use super::{Ipv4Packet, Ipv4PacketMut};

impl Ipv4Packet {
    pub fn from_bytes(bytes: &Bytes) -> Self {
        let mut header = bytes.clone();
        let payload = header.split_off(super::IPV4_HEADER_LEN);
        Self { header, payload }
    }

    // crate::impl_get!(get_version_and_header_len, header, 0, 1, u8);
    // crate::impl_get!(get_differenciate_service_field, header, 1, 2, u8);
    crate::impl_get!(get_total_length, header, 2, 4, u16);
    crate::impl_get!(get_identification, header, 4, 6, u16);
    crate::impl_get!(get_flags, header, 6, 8, u16);
    // crate::impl_get!(get_time_to_live, header, 8, 9, u8);
    crate::impl_get!(get_protcol_u8, header, 9, 10, u8);
    // crate::impl_get!(get_header_checksum, header, 10, 12, u16);
    crate::impl_get_slice!(get_source_address_slice, header, 12, 16, [u8; 4]);
    crate::impl_get_slice!(get_destination_address_slice, header, 16, 20, [u8; 4]);

    crate::impl_get_bit!(get_fragment_mf_bit, header, 6, 5);
    // crate::impl_get_bit!(get_fragment_df_bit, header, 6, 6);

    pub fn to_bytes(&self) -> Bytes {
        let mut res = BytesMut::new();
        res.extend_from_slice(&self.header);
        res.extend_from_slice(&self.payload);
        res.freeze()
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

    pub fn get_payload(&self) -> &Bytes {
        &self.payload
    }

    pub fn to_unverified(&self) -> Ipv4PacketMut {
        let mut header = BytesMut::with_capacity(super::IPV4_HEADER_LEN);
        header.extend_from_slice(&self.header);
        Ipv4PacketMut {
            header,
            payload: self.payload.clone(),
        }
    }

    pub fn calc_header_checksum(&self) -> u16 {
        calc_checksum(&self.header)
    }

    pub fn get_fragment_offset(&self) -> u16 {
        self.get_flags().get_bits(0..13) << 3
    }
}
