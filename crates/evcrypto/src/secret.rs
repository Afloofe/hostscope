use core::fmt;

use zeroize::Zeroize;

#[derive(Clone)]
pub struct Secret32([u8; 32]);

impl Secret32 {

    pub fn new(mut bytes: [u8; 32]) -> Self {
        let s = Secret32(bytes);
        bytes.zeroize();
        s
    }

    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(redacted)")
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn wipe(mut v: Vec<u8>) {
    v.zeroize();
}

pub fn wipe_bytes(b: &mut [u8]) {
    b.zeroize();
}
