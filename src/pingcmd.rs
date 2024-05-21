use std::net::Ipv4Addr;

use rand::Rng;
use tokio::time::{sleep, timeout, Duration};

use crate::layer3::icmp::{Icmp, IcmpType, ICMP_REPLY_NOTIFIER};

const ICMP_ECHO_REPLY_TIMEOUT_MS: u64 = 1000;

pub async fn main(ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut echo_reqest = Icmp::echo_reqest_minimal();

    let random_identifier = rand::thread_rng().gen();
    echo_reqest.identifier = random_identifier;
    echo_reqest.seqence_number = 0;
    echo_reqest.data = vec![0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70];

    let mut ipv4_icmp_echo_req_frame = crate::layer3::ipv4::Ipv4Frame::minimal();
    ipv4_icmp_echo_req_frame.header.destination_address = ip.octets();
    ipv4_icmp_echo_req_frame.payload = echo_reqest.build_to_bytes();

    log::debug!("ICMP Echo Request packet: {:x?}", ipv4_icmp_echo_req_frame);

    // Send ICMP Echo request packet every 1 sec.
    tokio::spawn(async move {
        let mut seq_origin = 1u16;
        loop {
            let seq_num = seq_origin;
            seq_origin = seq_origin.wrapping_add(1);
            let mut echo_req = echo_reqest.clone();
            echo_req.seqence_number = seq_num;

            let time_ping_send = std::time::Instant::now();
            // Spawn ICMP Echo Reply listener.
            tokio::spawn(icmp_echo_reply_listener_with_timeout(
                ip.octets(),
                random_identifier,
                seq_num,
                time_ping_send,
                ICMP_ECHO_REPLY_TIMEOUT_MS,
            ));

            // log::trace!("Send icmp echo request: {:x?}", ipv4_icmp_echo_req_frame);
            // ipv4_icmp_echo_req_frame.send().await.unwrap();
            log::trace!(
                "Send icmp echo request: {:x?}",
                echo_req.to_ipv4_frame(ip.octets())
            );
            echo_req.to_ipv4_frame(ip.octets()).send().await.unwrap();
            sleep(Duration::from_millis(1000)).await;
        }
    });

    sleep(Duration::from_millis(10 * 1000)).await;
    Ok(())
}

/*
   Echo reply の場合、Echo request と同一 identifier と seq number を返せばいい。
   https://datatracker.ietf.org/doc/html/rfc792
   The identifier and sequence number may be used by the echo sender
   to aid in matching the replies with the echo requests.  For
   example, the identifier might be used like a port in TCP or UDP to
   identify a session, and the sequence number might be incremented
   on each echo request sent.  The echoer returns these same values
   in the echo reply.

*/

// 指定した identifier, seqence_number の ICMP Echo Reply をタイムアウト付きで待ち受ける。
// 受診した場合は標準出力に結果を流す。
async fn icmp_echo_reply_listener_with_timeout(
    ip: [u8; 4],
    identifier: u16,
    seqence_number: u16,
    timestamp_icmp_sent: std::time::Instant,
    timeout_ms: u64,
) {
    log::trace!("Listening ICMP Echo Reply with id:{identifier}, seq:{seqence_number}");
    let res = timeout(Duration::from_millis(timeout_ms), async {
        let mut icmp_notifier_receiver = crate::unwrap_or_yield!(ICMP_REPLY_NOTIFIER, resubscribe);
        loop {
            let ipv4frame: crate::layer3::ipv4::Ipv4Frame =
                icmp_notifier_receiver.recv().await.unwrap();
            let icmp = Icmp::from_buffer(&ipv4frame.payload);
            if icmp.icmp_type == IcmpType::Reply as u8
                && ipv4frame.header.source_address == ip
                && icmp.identifier == identifier
                && icmp.seqence_number == seqence_number
            {
                let elapsed_ms= timestamp_icmp_sent.elapsed().as_micros() as f64 / 1000.0;
                println!("Echo reply from {ip:?}, id: {identifier}  seq: {seqence_number}  time: {elapsed_ms:.3} ms");
                break;
            }
        }
    })
    .await;
    match res {
        Ok(a) => log::trace!("ICMP Echo OK! {:?}", a),
        Err(e) => log::warn!("ICMP Echo timeout! {:?}", e),
    }
}
