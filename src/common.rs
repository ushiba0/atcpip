#[macro_export]
macro_rules! unwrap_or_yield {
    ($global_var:expr, $method:ident) => {
        loop {
            let a = $global_var.lock().await;
            match a.as_ref() {
                Some(value) => break value.$method(),
                None => tokio::task::yield_now().await,
            }
        }
    };
}

pub fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum = 0usize;
    let mut chunks = data.chunks_exact(2);

    // 2 バイトずつ読み取り和を取る.
    for chunk in chunks.by_ref() {
        let part = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(part as usize);
    }

    // data.len() が奇数長の場合は最後の 1 バイトを処理する.
    if let Some(&last_byte) = chunks.remainder().first() {
        let part = u16::from_be_bytes([last_byte, 0]);
        sum = sum.wrapping_add(part as usize);
    }

    // Handle carries.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
