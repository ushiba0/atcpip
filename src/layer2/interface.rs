use std::borrow::Borrow;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use pnet::datalink::{Config, DataLinkReceiver, DataLinkSender};

use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::layer2::ethernet::EthernetFrame;

pub static MY_MAC_ADDRESS: Lazy<[u8; 6]> = Lazy::new(|| {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|e| e.name == INTERFACE_NAME)
        .unwrap();
    let mac = interface.mac.unwrap().octets();
    log::info!("Initialized MAC ADDRESS {mac:x?}.");
    mac
});

static SEND_HANDLE2: Lazy<
    parking_lot::RwLock<(
        broadcast::Sender<EthernetFrame>,
        broadcast::Receiver<EthernetFrame>,
    )>,
> = Lazy::new(|| {
    let (iface_send, iface_recv) =
        broadcast::channel::<EthernetFrame>(BUFFER_SIZE_DATALINK_SEND_CHANNEL);
    RwLock::new((iface_send, iface_recv))
});

pub const MY_IP_ADDRESS: [u8; 4] = [192, 168, 1, 237];
pub const DEFAULT_GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];
pub const MTU: usize = 1500;
pub const INTERFACE_NAME: &str = "ens192";
const PNET_TX_TIMEOUT_MICROSEC: u64 = 1000 * 10; // 10 ms.
const PNET_RX_TIMEOUT_MICROSEC: u64 = 1000; // 1 ms

const BUFFER_SIZE_DATALINK_SEND_CHANNEL: usize = 8;
const BUFFER_SIZE_ETH_SEND_CHANNEL: usize = 2;

async fn get_channel() -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let interfaces = pnet::datalink::interfaces();
    log::trace!("Network interfaces on this host: {:?}", interfaces);

    let interface = interfaces
        .into_iter()
        .find(|e| e.name == INTERFACE_NAME)
        .context("Interface not found.")?;

    // let mac = interface.mac.context("MAC address is not set.")?.octets();
    // *MY_MAC_ADDRESS.lock().await = Some(mac);

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
    SEND_HANDLE2
        .read()
        .borrow()
        .0
        .send(ethernet_frame.clone())
        .context("error")
}

pub async fn spawn_tx_handler() {
    let (tx, rx) = get_channel().await.unwrap();

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
        datalink_tx_handler(tx).await.unwrap();
    });
}

async fn datalink_rx_handler(
    mut rx: Box<dyn DataLinkReceiver>,
    eth_sender: mpsc::Sender<EthernetFrame>,
) -> Result<()> {
    log::info!("Spawned Datalink Rx handler.");
    loop {
        // rx.next() は blocking なメソッドなので yield しなければならない。
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

async fn datalink_tx_handler(mut tx: Box<dyn DataLinkSender>) -> Result<()> {
    log::info!("Spawned Datalink Tx handler.");
    let mut iface_recv = SEND_HANDLE2.read().borrow().1.resubscribe();

    loop {
        let eth_frame = match iface_recv.recv().await {
            Ok(v) => v,
            Err(e) => {
                log::error!("[datalink_tx_handler] {e:?}");
                continue;
            }
        };
        let bytes = eth_frame.build_to_packet();
        let res = tx.send_to(&bytes, None).context("None.");
        match res {
            Ok(v) => match v {
                Ok(_) => {}
                Err(e) => log::error!("[datalink_tx_handler] {e:?}"),
            },
            Err(e) => log::error!("[datalink_tx_handler] {e:?}"),
        }
    }
}
