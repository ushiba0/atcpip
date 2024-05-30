use std::net::Ipv4Addr;

use anyhow::Result;
use rand::Rng;

pub async fn main(ipv4addr: Ipv4Addr, port: u16) -> Result<()> {
    let mut tcp_pkt = crate::layer4::tcp::TcpPacketMut::minimal();

    for _ in 0..100000 {
        tcp_pkt
            .set_source_port(rand::thread_rng().gen::<u16>())
            // .set_source_port(1122)
            .set_target_port(port)
            .set_syn_bit(true)
            .set_header_length_bytes(20)
            .set_seqence_number(1);
        tcp_pkt.calc_and_set_checksum();

        let pkt = tcp_pkt.build_mock();

        crate::layer3::ipv4::send_tcp(pkt.clone(), &ipv4addr).await?;
        tokio::task::yield_now().await;
    }
    Ok(())
}
