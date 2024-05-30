use bit_field::BitField;
use bytes::{Bytes, BytesMut};

use crate::{common::calc_checksum, layer3::ipv4::IPV4_MAX_PAYLOAD_SIZE};

use super::{Ipv4Packet, Ipv4PacketMut, Ipv4Protcol, IPV4_HEADER_LEN};

impl Ipv4PacketMut {
    pub fn new(destination_address: [u8; 4], protcol: Ipv4Protcol, payload: Bytes) -> Self {
        debug_assert!(
            payload.len() < IPV4_MAX_PAYLOAD_SIZE,
            "IPv4 payload size exceeds maximum."
        );
        let mut pkt = Self::minimal();
        pkt.set_destination_address_slice(destination_address)
            .set_protcol_u8(protcol as u8)
            .set_payload(&payload);
        pkt
    }

    fn minimal() -> Self {
        let mut ipv4_pkt = Self {
            header: BytesMut::zeroed(IPV4_HEADER_LEN),
            payload: Bytes::new(),
        };
        ipv4_pkt
            .set_version_and_header_len(0b0100_0101)
            .set_differenciate_service_field(0)
            .set_time_to_live(64)
            .set_protcol_u8(1) // ICMP
            .set_source_address_slice(crate::layer2::interface::MY_IP_ADDRESS)
            .set_fragment_df_bit(true)
            .set_fragment_mf_bit(false);
        ipv4_pkt
    }

    crate::impl_get!(get_flags, header, 6, 8, u16);

    crate::impl_set!(set_version_and_header_len, header, 0, 1, u8);
    crate::impl_set!(set_differenciate_service_field, header, 1, 2, u8);
    crate::impl_set!(set_total_length, header, 2, 4, u16);
    crate::impl_set!(set_identification, header, 4, 6, u16);
    crate::impl_set!(set_flags, header, 6, 8, u16);
    crate::impl_set!(set_time_to_live, header, 8, 9, u8);
    crate::impl_set!(set_protcol_u8, header, 9, 10, u8);
    crate::impl_set!(set_header_checksum, header, 10, 12, u16);
    crate::impl_set_slice!(set_source_address_slice, header, 12, 16, [u8; 4]);
    crate::impl_set_slice!(set_destination_address_slice, header, 16, 20, [u8; 4]);

    // crate::impl_get_bit!(get_fragment_mf_bit, header, 6, 5);
    // crate::impl_get_bit!(get_fragment_df_bit, header, 6, 6);
    crate::impl_set_bit!(set_fragment_mf_bit, header, 6, 5);
    crate::impl_set_bit!(set_fragment_df_bit, header, 6, 6);

    fn to_fragmented(&self) -> Vec<Ipv4Packet> {
        super::fragment_ipv4::do_fragment(self)
    }

    pub fn convert_to_ipv4packet(&mut self) -> Ipv4Packet {
        let header = self.header.clone();
        Ipv4Packet {
            header: header.freeze(),
            payload: self.payload.clone(),
        }
    }

    pub fn build(&mut self) {
        self.set_header_checksum(0);
        self.set_total_length((self.header.len() + self.payload.len()) as u16);
        let checksum = calc_checksum(&self.header);
        self.set_header_checksum(checksum);
    }

    pub fn set_flagment_offset(&mut self, offset: u16) -> &mut Self {
        debug_assert_eq!(offset % 8, 0);
        let mut flags = self.get_flags();
        flags.set_bits(0..13, offset >> 3);
        self.set_flags(flags);
        self
    }

    pub fn set_payload(&mut self, payload: &Bytes) -> &mut Self {
        self.payload = payload.clone();
        self
    }

    pub async fn safely_send(&self) -> anyhow::Result<()> {
        for p in self.to_fragmented() {
            p.send().await?;
        }
        Ok(())
    }
}
