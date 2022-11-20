use crate::constants::PRIVATE_KEY_LENGTH;
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PrivateKey([u8; PRIVATE_KEY_LENGTH]);

#[wasm_bindgen]
impl PrivateKey {
    pub fn new(btyes: &[u8]) -> PrivateKey {
        PrivateKey((*btyes).try_into().unwrap())
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PrivateKey {
    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_LENGTH] {
        self.0
    }

    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PRIVATE_KEY_LENGTH] {
        &(self.0)
    }
}

mod tests {
    use super::*;
    #[test]
    fn test_private_key() {
        let private_key = PrivateKey([0; PRIVATE_KEY_LENGTH]);
        assert_eq!(private_key.to_bytes(), [0; PRIVATE_KEY_LENGTH]);
        assert_eq!(private_key.as_bytes(), &[0; PRIVATE_KEY_LENGTH]);
    }
}
