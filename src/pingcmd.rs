use std::net::Ipv4Addr;

use anyhow::Result;
use rand::Rng;
use tokio::{
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};

use crate::layer3::icmp::{Icmp, IcmpType, ICMP_REPLY_NOTIFIER};

pub async fn main(ipv4addr: Ipv4Addr, count: usize, timeout_ms: u64) -> Result<()> {
    // stop_count == 0: Loop forever.
    // stop_count > 0: Stops after <stop_count> reply.
    let stop_count = if count == 0 { usize::MAX } else { count };
    let ip = ipv4addr.octets();
    let mut echo_reqest = Icmp::echo_reqest_minimal();
    echo_reqest.data = vec![0xda; 100];
    // echo_reqest.data = vec![0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70];

    // let  echo_req_test: crate::layer3::ipv4::Ipv4FrameUnchecked = echo_reqest.to_ipv4(ip)?;
    // let echo_req_checked = echo_req_test.build();
    // echo_req_checked.send().await.unwrap();
    // echo_req_test.

    // Send ICMP Echo request packet every 1 sec.
    let handle: JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut seq_num = 0u16;
        let mut id_num = rand::thread_rng().gen::<u16>();

        for _ in 0..stop_count {
            seq_num = seq_num.wrapping_add(1);
            id_num = id_num.wrapping_add(1);
            echo_reqest.sequence_number = seq_num;
            echo_reqest.identifier = id_num;
            let ipv4_frame = echo_reqest.to_ipv4(ip)?;
            let ipv4_frame = ipv4_frame.build();

            // Spawn ICMP Echo Reply listener.
            tokio::spawn(icmp_echo_reply_listener_with_timeout(
                ip,
                id_num,
                seq_num,
                std::time::Instant::now(),
                timeout_ms,
            ));

            log::trace!("Sending icmp echo request: {ipv4_frame:x?}");
            ipv4_frame.send().await?;
            sleep(Duration::from_millis(1000)).await;
        }
        Ok(())
    });

    handle.await??;
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
// PNET_RX_TIMEOUT_MICROSEC が 100 ms だと、指定したタイムアウト時刻より大幅に長く、
// タイムアウトに 100ms かかることがある。
async fn icmp_echo_reply_listener_with_timeout(
    ip: [u8; 4],
    identifier: u16,
    seqence_number: u16,
    timestamp_icmp_sent: std::time::Instant,
    timeout_ms: u64,
) {
    log::trace!("Listening ICMP Echo Reply with id:{identifier}, seq:{seqence_number}, timeout:{timeout_ms}");
    let res = timeout(Duration::from_millis(timeout_ms), async {
        let mut icmp_notifier_receiver = crate::unwrap_or_yield!(ICMP_REPLY_NOTIFIER, resubscribe);
        loop {
            let ipv4frame = icmp_notifier_receiver.recv().await.unwrap();
            let icmp = Icmp::from_buffer(&ipv4frame.payload);
            if icmp.icmp_type == IcmpType::Reply as u8
                && ipv4frame.header.source_address == ip
                && icmp.identifier == identifier
                && icmp.sequence_number == seqence_number
            {
                let elapsed_ms= timestamp_icmp_sent.elapsed().as_micros() as f64 / 1000.0;
                println!("Echo reply from {ip:?}, id: {identifier}  seq: {seqence_number}  time: {elapsed_ms:.3} ms");
                break;
            } else {
                log::error!("怪しいパケット受信");
            }
        }
    })
    .await;
    match res {
        Ok(a) => log::trace!("ICMP Echo OK! {:?}", a),
        Err(e) => {
            log::warn!("ICMP Echo timeout! {:?}", e);
            println!("Timeout!");
        }
    }
}
