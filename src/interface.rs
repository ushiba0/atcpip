use anyhow::{anyhow, Context};
use once_cell::sync::Lazy;
use pnet::datalink::{Config, DataLinkReceiver, DataLinkSender};

use tokio::sync::broadcast;
use tokio::sync::Mutex;

use crate::layer2::ethernet::{EthernetFrame,EtherType};
use crate::layer3::ipv4::Ipv4Frame;

pub static MY_MAC_ADDRESS: Lazy<Mutex<Option<[u8; 6]>>> = Lazy::new(|| Mutex::new(None));
pub const MY_IP_ADDRESS: [u8; 4] = [192, 168, 1, 237];
const PNET_TX_TIMEOUT_MICROSEC: u64 = 1000 * 10; // 10 ms.
const PNET_RX_TIMEOUT_MICROSEC: u64 = 1000 * 100; // 100 ms.
static SEND_HANDLE: Lazy<Mutex<Option<tokio::sync::broadcast::Sender<EthernetFrame>>>> =
    Lazy::new(|| Mutex::new(None));

async fn get_channel() -> anyhow::Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let interfaces = pnet::datalink::interfaces();
    log::trace!("Network interfaces on this host: {:?}", interfaces);

    let interface = interfaces
        .into_iter()
        .find(|e| e.name == "ens192")
        .context("Interface not found.")?;

    let mac = interface.mac.context("MAC address is not set.")?.octets();
    *MY_MAC_ADDRESS.lock().await = Some(mac);

    use std::time::Duration;
    let config = Config {
        read_timeout: Some(Duration::from_micros(PNET_RX_TIMEOUT_MICROSEC)),
        write_timeout: Some(Duration::from_micros(PNET_TX_TIMEOUT_MICROSEC)),
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

pub async fn send_to_pnet(ethernet_frame: EthernetFrame) -> anyhow::Result<usize> {
    SEND_HANDLE
        .lock()
        .await
        .as_ref()
        .unwrap()
        .send(ethernet_frame)
        .context("[send_to_pnet] Send to pnet tx error.")
}

pub async fn spawn_tx_handler() {
    let (iface_send, mut iface_recv) = broadcast::channel::<EthernetFrame>(2);
    let (mut tx, mut rx) = get_channel().await.unwrap();

    *SEND_HANDLE.lock().await = Some(iface_send);

    // Datalink Rx.
    tokio::spawn(async move {
        log::info!("Spawned Datalink Rx handler.");

        // ARP ハンドラスレッドを spawn し、 ARP ハンドラスレッドに通知する用の Sender を返す。
        let arp_rx_sender = {
            use crate::layer2::arp::{Arp, arp_handler};
            // ARP packet が来たら、この channel で上のレイヤに通知する。
            let (arp_rx_sender, arp_rx_receiver) = broadcast::channel::<Arp>(2);

            // Spawn ARP handler.
            tokio::spawn(async move {
                arp_handler(arp_rx_receiver).await;
            });
            arp_rx_sender
        };

        // IPv4 ハンドラスレッドを spawn し、 IPv4 ハンドラスレッドに通知する用の Sender を返す。
        let ipv4_rx_sender = {
            // Ipv4 の受信を上のレイヤに伝えるチャネル.
            let (ipv4_rx_sender, ipv4_rx_receiver) =
                broadcast::channel::<Ipv4Frame>(2);

            // Spawn IPv4 handler.
            tokio::spawn(async move {
                crate::layer3::ipv4::ipv4_handler(ipv4_rx_receiver).await;
            });
            ipv4_rx_sender
        };

        loop {
            tokio::task::yield_now().await;
            // rx.next() はパケットが届かない場合は PNET_RX_TIMEOUT_MICROSEC ms で timeout する。
            // 逆にここで PNET_RX_TIMEOUT_MICROSEC ms のブロックが発生する可能性がある。
            if let Ok(buf) = rx.next() {
                let eth_frame = EthernetFrame::new(buf);

                // EtherType を見て Arp handler, IPv4 handler に渡す。
                match EtherType::from_u16(eth_frame.header.ethernet_type) {
                    EtherType::Arp => {
                        let arp = eth_frame.to_arp().unwrap();
                        arp_rx_sender.send(arp).unwrap();
                    }
                    EtherType::Ipv4 => {
                        let ipv4frame = Ipv4Frame::from_buffer(&eth_frame.payload);
                        ipv4_rx_sender.send(ipv4frame).unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    // Datalink Tx.
    tokio::spawn(async move {
        log::info!("Spawned Datalink Tx handler.");
        while let Ok(eth_frame) = iface_recv.recv().await {
            let packet = eth_frame.build_to_packet();
            tx.send_to(&packet, None);
        }
    });
}
