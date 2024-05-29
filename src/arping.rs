use std::net::Ipv4Addr;

use tokio::time::Duration;

async fn wait_arp_reply() -> anyhow::Result<()> {
    let mut arp_receiver = crate::layer2::arp::ARP_RECEIVER.read().1.resubscribe();
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
    let mut req = crate::layer2::arp::Arp::minimal();
    req.ethernet_header.destination_mac_address = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    req.target_ip_address = ip.octets();
    req.opcode = crate::layer2::arp::ArpOpCode::Request as u16;

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

    wait_arp_reply().await?;
    Ok(())
}
