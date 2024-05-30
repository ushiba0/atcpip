use rand::Rng;

use super::{Ipv4Packet, Ipv4PacketMut, IPV4_HEADER_LEN};

use crate::layer2::interface::MTU;

// For simplicity, even if the packet length is within the MTU, it will go through the fragmentation code path.
pub fn do_fragment(ipv4_mut: &Ipv4PacketMut) -> Vec<Ipv4Packet> {
    debug_assert!(
        ipv4_mut.payload.len() <= super::IPV4_MAX_PAYLOAD_SIZE,
        "IPv4 payload size exceeds the maximum."
    );
    let max_payload_size = (MTU - IPV4_HEADER_LEN) & (!0b111); // Round down to the nearest multiple of 8.

    let mut packets: Vec<Ipv4Packet> = Vec::new();
    let mut payload = ipv4_mut.payload.clone();
    let mut flagment_offset = 0u16;
    let identification = rand::thread_rng().gen::<u16>();

    loop {
        if payload.len() > max_payload_size {
            // Fragment the payload.
            let fragmented_payload = payload.split_to(max_payload_size);
            let mut pkt = Ipv4PacketMut {
                header: ipv4_mut.header.clone(),
                payload: fragmented_payload,
            };
            pkt.set_fragment_mf_bit(true)
                .set_flagment_offset(flagment_offset)
                .set_identification(identification);
            pkt.build();
            packets.push(pkt.convert_to_ipv4packet());
        } else {
            // The packet length is within the MTU, so it will not fragment.
            let mut pkt = Ipv4PacketMut {
                header: ipv4_mut.header.clone(),
                payload: payload.clone(),
            };
            pkt.set_fragment_mf_bit(false)
                .set_flagment_offset(flagment_offset)
                .set_identification(identification);
            pkt.build();
            packets.push(pkt.convert_to_ipv4packet());
            return packets;
        }
        flagment_offset = flagment_offset.wrapping_add(max_payload_size as u16);
    }
}
