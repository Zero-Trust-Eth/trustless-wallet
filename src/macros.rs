/// Convert a byte slice to a boolean vector
#[macro_export]
macro_rules! bytes_to_bools {
    ($bytes:expr) => {{
        let mut result = Vec::with_capacity($bytes.len() * 8);
        for &byte in $bytes {
            for i in 0..8 {
                result.push(((byte >> (7 - i)) & 1) == 1);
            }
        }
        result
    }};
}

/// Convert a boolean slice to a byte vector
#[macro_export]
macro_rules! bools_to_bytes {
    ($bools:expr) => {{
        let mut result = Vec::with_capacity(($bools.len() + 7) / 8);
        for chunk in $bools.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1u8 << (7 - (i % 8));
                }
            }
            result.push(byte);
        }
        result
    }};
}
