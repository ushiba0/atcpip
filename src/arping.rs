use std::net::Ipv4Addr;

use tokio::sync::broadcast::Receiver;
use tokio::time::{timeout, Duration};

async fn wait_arp_reply(mut arp_receiver: Receiver<crate::layer2::arp::Arp>) -> anyhow::Result<()> {
    loop {
        let arp = arp_receiver.recv().await?;
        if arp.opcode == crate::layer2::arp::ArpOpCode::Reply as u16 {
            println!(
                "ARP REPLY: {:?} is at {:x?}",
                arp.sender_ip_address, arp.sender_mac_address
            );
        }
    }
}

pub async fn main(ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut req = crate::layer2::arp::Arp::request_minimal();
    let my_mac = crate::unwrap_or_yield!(crate::interface::MY_MAC_ADDRESS, clone);

    req.ethernet_header.destination_mac_address = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    req.ethernet_header.source_mac_address = my_mac;

    req.sender_mac_address = my_mac;
    req.sender_ip_address = crate::interface::MY_IP_ADDRESS;
    req.target_mac_address = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    req.target_ip_address = ip.octets();

    let e = req.to_ethernet_frame();
    log::debug!("Arp request packet: {:x?}", e);

    // Send ARP request packet every 1 sec.
    tokio::spawn(async move {
        loop {
            e.send().await.unwrap();
            println!("Sent ARP Request.");
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    });
    
    let arp_receiver = crate::unwrap_or_yield!(crate::layer2::arp::ARP_RECEIVER, resubscribe);
    let f = timeout(Duration::from_millis(10000), wait_arp_reply(arp_receiver)).await;

    match f {
        Ok(v) => v,
        Err(_) => Err(anyhow::anyhow!("Timeout.")),
    }
}
