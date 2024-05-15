use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use pnet::datalink::{Config, DataLinkReceiver, DataLinkSender};

use tokio::sync::Mutex;

use crate::ethernet::EthernetFrame;

pub static MY_MAC_ADDRESS: Lazy<Mutex<Option<[u8; 6]>>> = Lazy::new(|| Mutex::new(None));
pub const MY_IP_ADDRESS: [u8; 4] = [192, 168, 1, 237];
pub const PNET_TXRX_TIMEOUT: u64 = 1000; // 1000 ms of timeout.

pub async fn get_channel() -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let interfaces = pnet::datalink::interfaces();
    log::trace!("Network interfaces on this host: {:?}", interfaces);

    let interface = interfaces
        .into_iter()
        .find(|e| e.name == "ens192")
        .context("Interface not found.")?;

    let mac = interface.mac.context("MAC address is not set.")?.octets();
    *MY_MAC_ADDRESS.lock().await = Some(mac);

    let timeout_duration = std::time::Duration::from_millis(PNET_TXRX_TIMEOUT);
    let config = Config {
        read_timeout: Some(timeout_duration),
        write_timeout: Some(timeout_duration),
        ..Default::default()
    };

    // Ref: https://docs.rs/pnet/latest/pnet/index.html
    use pnet::datalink::Channel::Ethernet;
    let (tx, rx) = match pnet::datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("Channel type invlid.")),
        Err(e) => return Err(anyhow!("Datalink channel error: {e}")),
    };
    Ok((tx, rx))
}

pub static SEND_HANDLE: Lazy<Mutex<Option<tokio::sync::broadcast::Sender<EthernetFrame>>>> =
    Lazy::new(|| Mutex::new(None));

pub async fn send_to_pnet(ethernet_frame: EthernetFrame) -> anyhow::Result<usize> {
    SEND_HANDLE
        .lock()
        .await
        .as_ref()
        .unwrap()
        .send(ethernet_frame)
        .context("Send to pnet tx handler error.")
}

pub async fn spawn_tx_handler(
    mut iface_recv: tokio::sync::broadcast::Receiver<EthernetFrame>,
    iface_send: tokio::sync::broadcast::Sender<EthernetFrame>,
    mut tx: Box<dyn DataLinkSender>,
    mut rx: Box<dyn DataLinkReceiver>,
) {
    *SEND_HANDLE.lock().await = Some(iface_send);

    // Datalink Rx.
    tokio::spawn(async move {
        log::debug!("Spawned Datalink Rx handler.");

        // ARP packet が来たら、この channel で上のレイヤに通知する。
        use tokio::sync::broadcast;
        let (arp_rx_sender, arp_rx_receiver) = broadcast::channel::<crate::arp::Arp>(2);

        // ARP handler.
        tokio::spawn(async move {
            crate::arp::arp_handler(arp_rx_receiver).await;
        });

        loop {
            tokio::task::yield_now().await;
            // rx.next() はパケットが届かない場合は 1000 ms (PNET_TXRX_TIMEOUT) で timeout する。
            // 逆にここで 1000 ms のブロックが発生する可能性がある。
            if let Ok(buf) = rx.next() {
                let eth_frame = EthernetFrame::new(buf);

                // EtherType を見て Arp handler, IPv4 handler に渡す。
                match crate::ethernet::EtherType::from_u16(eth_frame.header.ethernet_type) {
                    crate::ethernet::EtherType::Arp => {
                        let arp = eth_frame.to_arp().unwrap();
                        arp_rx_sender.send(arp).unwrap();
                    }
                    crate::ethernet::EtherType::Ipv4 => {
                        // Not implemented.
                    }
                    _ => {}
                }
            }
        }
    });

    // Datalink Tx.
    tokio::spawn(async move {
        log::debug!("Spawned Datalink Tx handler.");
        while let Ok(eth_frame) = iface_recv.recv().await {
            let packet = eth_frame.build_to_packet();
            tx.send_to(&packet, None);
            log::trace!("Sent {packet:x?}");
        }
    });
}
