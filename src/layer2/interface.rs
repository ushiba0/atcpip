use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use pnet::datalink::{Config, DataLinkReceiver, DataLinkSender};

use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::layer2::ethernet::EthernetFrame;

pub static MY_MAC_ADDRESS: Lazy<Mutex<Option<[u8; 6]>>> = Lazy::new(|| Mutex::new(None));
pub const MY_IP_ADDRESS: [u8; 4] = [192, 168, 1, 237];
pub const DEFAULT_GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];
pub const MTU: usize = 1500;
const PNET_TX_TIMEOUT_MICROSEC: u64 = 1000 * 10; // 10 ms.
const PNET_RX_TIMEOUT_MICROSEC: u64 = 1000; // 1 ms
static SEND_HANDLE: Lazy<Mutex<Option<tokio::sync::broadcast::Sender<EthernetFrame>>>> =
    Lazy::new(|| Mutex::new(None));

const BUFFER_SIZE_DATALINK_SEND_CHANNEL: usize = 8;
const BUFFER_SIZE_ETH_SEND_CHANNEL: usize = 2;

async fn get_channel() -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
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
        Ok(_) => anyhow::bail!("Channel type invlid."),
        Err(e) => anyhow::bail!("Datalink channel error: {e}"),
    };
    Ok((tx, rx))
}

pub async fn send_to_pnet(ethernet_frame: EthernetFrame) -> Result<usize> {
    SEND_HANDLE
        .lock()
        .await
        .as_ref()
        .unwrap()
        .send(ethernet_frame.clone())
        .context(format!(
            "[send_to_pnet] Send to pnet tx error. {:?}, payload size: {}",
            ethernet_frame.header,
            ethernet_frame.payload.len()
        ))
}

pub async fn spawn_tx_handler() {
    let (iface_send, iface_recv) =
        broadcast::channel::<EthernetFrame>(BUFFER_SIZE_DATALINK_SEND_CHANNEL);
    let (tx, rx) = get_channel().await.unwrap();

    *SEND_HANDLE.lock().await = Some(iface_send);

    let (eth_rx_sender, eth_rx_receiver) =
        mpsc::channel::<EthernetFrame>(BUFFER_SIZE_ETH_SEND_CHANNEL);
    // Spawn esthernet handler.
    tokio::spawn(async move {
        super::ethernet::ethernet_handler(eth_rx_receiver).await;
    });

    // Spawn datalink Rx handler.
    tokio::spawn(async move {
        datalink_rx_handler(rx, eth_rx_sender).await.unwrap();
    });

    // Spawn datalink Tx handler.
    tokio::spawn(async move {
        datalink_tx_handler(tx, iface_recv).await.unwrap();
    });
}

async fn datalink_rx_handler(
    mut rx: Box<dyn DataLinkReceiver>,
    eth_sender: mpsc::Sender<EthernetFrame>,
) -> Result<()> {
    log::info!("Spawned Datalink Rx handler.");
    loop {
        tokio::task::yield_now().await;
        // rx.next() はパケットが届かない場合は PNET_RX_TIMEOUT_MICROSEC ms で timeout する。
        // 逆にここで PNET_RX_TIMEOUT_MICROSEC ms のブロックが発生する可能性がある。
        if let Ok(buf) = rx.next() {
            let eth_frame = EthernetFrame::from_slice(buf);
            eth_sender.send(eth_frame).await?;
        } else {
            // Timed out.
        }
    }
}

async fn datalink_tx_handler(
    mut tx: Box<dyn DataLinkSender>,
    mut iface_recv: Receiver<EthernetFrame>,
) -> Result<()> {
    log::info!("Spawned Datalink Tx handler.");
    loop {
        let eth_frame = iface_recv.recv().await?;
        let bytes = eth_frame.build_to_packet();
        let res = tx
            .send_to(&bytes, None)
            .context("DataLinkSender returned None.");
        match res {
            Ok(v) => match v {
                Ok(_) => {}
                Err(e) => {
                    log::error!("[datalink_tx_handler] {e:?}");
                }
            },
            Err(e) => {
                log::error!("[datalink_tx_handler] {e:?}");
            }
        }
    }
}
