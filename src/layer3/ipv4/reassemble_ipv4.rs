use std::collections::HashMap;

use anyhow::{ensure, Context};
use bytes::{BufMut, BytesMut};

use super::Ipv4Packet;

pub fn reassemble(
    tmp_pool: &mut HashMap<u16, Vec<Ipv4Packet>>,
    ipv4_frame: &Ipv4Packet,
) -> anyhow::Result<Ipv4Packet> {
    // 全てのパケットは一旦 tmp_pool にいれる。
    tmp_pool
        .entry(ipv4_frame.get_identification())
        .and_modify(|val: &mut Vec<Ipv4Packet>| {
            val.push(ipv4_frame.clone());
        })
        .or_insert(vec![ipv4_frame.clone()]);

    // MF==true のパケットの場合は return する。
    // 現在の実装では MF==false のパケットが来ない限り rebuild しない。
    ensure!(!ipv4_frame.get_fragment_mf_bit(), "MF==true");

    // MF==false のパケットを受け取ったら即 pool から廃棄する。
    let mut packets = tmp_pool
        .remove(&ipv4_frame.get_identification())
        .context("No packtes.")?;
    packets.sort_by_cached_key(|r| r.get_fragment_offset());

    ensure!(packets.first().unwrap().get_fragment_offset() == 0);

    let mut concatenated_payload = BytesMut::with_capacity(1500);
    let mut prev_range_end = 0usize;

    for packet in packets.iter() {
        let data_size = packet.get_total_length() as usize - super::IPV4_HEADER_LEN;
        let data_offset = packet.get_fragment_offset() as usize;
        let range = data_offset..(data_offset + data_size);
        if prev_range_end == range.start {
            concatenated_payload.put(packet.get_payload().slice(0..data_size));
            prev_range_end = range.end;
        } else {
            anyhow::bail!("Hole or dup.");
        }
    }

    let mut pkt_unverified = ipv4_frame.clone().to_unverified();
    pkt_unverified.set_payload(&concatenated_payload.freeze());

    Ok(pkt_unverified.convert_to_ipv4packet())
}
