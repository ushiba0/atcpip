pub const BUFFER_SIZE_DEFAULT: usize = 4;

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

#[macro_export]
macro_rules! impl_get {
    ($name:ident, $field:ident, $start:expr, $end:expr, $type:ty) => {
        pub fn $name(&self) -> $type {
            let bytes: &[u8] = &self.$field[$start..$end];
            <$type>::from_be_bytes(bytes.try_into().unwrap())
        }
    };
}

#[macro_export]
macro_rules! impl_get_slice {
    ($name:ident, $field:ident, $start:expr, $end:expr, $type:ty) => {
        pub fn $name(&self) -> $type {
            self.$field[$start..$end].try_into().unwrap()
        }
    };
}

#[macro_export]
macro_rules! impl_get_bit {
    ($fn_name:ident, $var:ident, $byte_idx:expr, $bit_idx:expr) => {
        fn $fn_name(&self) -> bool {
            self.$var[$byte_idx].get_bit($bit_idx)
        }
    };
}

#[macro_export]
macro_rules! impl_set {
    ($name:ident, $field:ident, $start:expr, $end:expr, $type:ty) => {
        pub fn $name(&mut self, value: $type) -> &mut Self {
            self.$field[$start..$end].copy_from_slice(&value.to_be_bytes());
            self
        }
    };
}

#[macro_export]
macro_rules! impl_set_slice {
    ($name:ident, $field:ident, $start:expr, $end:expr, $type:ty) => {
        pub fn $name(&mut self, value: $type) -> &mut Self {
            self.$field[$start..$end].copy_from_slice(&value);
            self
        }
    };
}

#[macro_export]
macro_rules! impl_set_bit {
    ($fn_name:ident, $var:ident, $byte_idx:expr, $bit_idx:expr) => {
        fn $fn_name(&mut self, value: bool) -> &mut Self {
            self.$var[$byte_idx].set_bit($bit_idx, value);
            self
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
