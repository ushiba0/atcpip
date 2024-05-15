use std::net::Ipv4Addr;

use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::Sender;
use tokio::time::{timeout, Duration};

use crate::ethernet::EthernetFrame;

async fn wait_arp_reply(mut arp_receiver: Receiver<crate::arp::Arp>) -> anyhow::Result<()> {
    loop {
        let arp = arp_receiver.recv().await?;
        if arp.opcode == crate::arp::ArpOpCode::Reply.as_u16() {
            println!(
                "ARP REPLY: {:?} is at {:x?}",
                arp.sender_ip_address, arp.sender_mac_address
            );
            //return Ok(());
        }
    }
}

pub async fn main(ip: Ipv4Addr) -> anyhow::Result<()> {
    // let mut req = crate::arp::Arp::request_minimal();
    let mut echo_reqest = crate::icmp::Icmp::echo_reqest_minimal();

    echo_reqest.identifier = 7;
    echo_reqest.seqence_number = 13;
    echo_reqest.data = vec![0,1,2,3,4,5,6,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

    echo_reqest.fill_checksum();

    let mut ipv4_icmp_echo_req_frame = crate::ipv4::Ipv4Frame::minimal();
    ipv4_icmp_echo_req_frame.header.destination_address = ip.octets() ;
    ipv4_icmp_echo_req_frame.payload = echo_reqest.to_bytes();


    log::debug!("ICMP Echo Request packet: {:x?}", ipv4_icmp_echo_req_frame);

    // Send ARP request packet every 1 sec.
    tokio::spawn(async move {
        loop {
            // iface_send.send(_e.clone()).unwrap();
            log::error!("Send icmp echo request: {:x?}", ipv4_icmp_echo_req_frame);
            ipv4_icmp_echo_req_frame.send().await;
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    });

    let arp_receiver = loop {
        if crate::arp::ARP_RECEIVER.lock().await.is_some() {
            break crate::arp::ARP_RECEIVER
                .lock()
                .await
                .as_ref()
                .unwrap()
                .resubscribe();
        }
    };

    let f = timeout(Duration::from_millis(10000), wait_arp_reply(arp_receiver)).await;

    match f {
        Ok(v) => v,
        Err(_) => Err(anyhow::anyhow!("Timeout.")),
    }
}
