use std::collections::HashMap;
use std::ops::Range;

use anyhow::{ensure, Context};
use bytes::{Bytes, BytesMut};

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
    let packets = tmp_pool
        .remove(&ipv4_frame.get_identification())
        .context("No packtes.")?;

    let mut fragment_range_list: Vec<Range<usize>> = Vec::new();
    let mut concatenated_payload = BytesMut::zeroed(super::IPV4_MAX_PAYLOAD_SIZE);

    for packet in packets.iter() {
        let data_size = packet.get_total_length() as usize - super::IPV4_HEADER_LEN;
        let data_offset = packet.get_fragment_offset() as usize;
        let range = data_offset..(data_offset + data_size);
        fragment_range_list.push(range.clone());
        concatenated_payload[range].copy_from_slice(&packet.get_payload()[..data_size]);
    }

    let merged_range = concatenate_ranges(&fragment_range_list)?;
    let reassembled_payload = Bytes::copy_from_slice(&concatenated_payload[merged_range]);

    let mut pkt_unverified = ipv4_frame.clone().to_unverified();
    pkt_unverified.set_payload(&reassembled_payload);

    Ok(pkt_unverified.to_ipv4packet())
}

// Range を結合し、そのサイズを返す。
// Range に Hole や被りがあると Err を返す。
fn concatenate_ranges(ranges: &[Range<usize>]) -> anyhow::Result<Range<usize>> {
    // ranges を start でソートし、ひと繋がりの range であるか確認する。
    let mut sorted_ranges = ranges.to_owned();
    sorted_ranges.sort_by_key(|r| r.start);

    ensure!(sorted_ranges.first().context("Empty.")?.start == 0, "Range start != 0.");

    let mut current_end = 0;
    for range in ranges.iter() {
        ensure!(range.start == current_end, "Range has a hole or dup.");
        current_end = range.end;
    }

    Ok(0..current_end)
}
