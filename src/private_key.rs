use secp256k1::constants::SECRET_KEY_SIZE;
use std::{convert::TryInto, fmt, str::FromStr};
use wasm_bindgen::prelude::*;

use crate::error::Error;

#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct PrivateKey([u8; SECRET_KEY_SIZE]);

#[wasm_bindgen]
impl PrivateKey {
    pub fn from_bytes(btyes: &[u8]) -> Result<PrivateKey, Error> {
        PrivateKey::try_from(btyes)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PrivateKey {
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &(self.0)
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(Error::InvalidPrivateKey);
        }
        let byte_array: [u8; SECRET_KEY_SIZE] =
            bytes.try_into().map_err(|_| Error::InvalidPrivateKey)?;
        Ok(PrivateKey(byte_array))
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = Error;

    fn try_from(slice: Vec<u8>) -> Result<Self, Self::Error> {
        if slice.len() != SECRET_KEY_SIZE {
            return Err(Error::InvalidPrivateKey);
        }
        let byte_array: [u8; SECRET_KEY_SIZE] =
            slice.try_into().map_err(|_| Error::InvalidPrivateKey)?;
        Ok(PrivateKey(byte_array))
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&bs58::encode(&self.0).into_string())
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let slice = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::Base58Decode)?;
        PrivateKey::try_from(slice)
    }
}
