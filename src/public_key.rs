use core::fmt;
use secp256k1::{constants::PUBLIC_KEY_SIZE, ecdsa::Signature, Message, Secp256k1};
use sha2::{Digest, Sha256};
use std::{convert::TryInto, str::FromStr};
use wasm_bindgen::prelude::*;

use crate::error::Error;

#[derive(Debug)]
#[wasm_bindgen]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

#[wasm_bindgen]
impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        PublicKey::try_from(bytes)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let secp = Secp256k1::verification_only();

        let digest = Sha256::digest(message);
        let msg = Message::from_digest_slice(digest.as_slice()).map_err(Error::from)?;

        let si = Signature::from_compact(signature).map_err(Error::from)?;

        secp.verify_ecdsa(
            &msg,
            &si,
            &secp256k1::PublicKey::from_slice(&self.0).map_err(Error::from)?,
        )
        .map_err(Error::from)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &(self.0)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(Error::InvalidPublicKey);
        }
        let byte_array: [u8; PUBLIC_KEY_SIZE] =
            bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
        Ok(PublicKey(byte_array))
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = Error;

    fn try_from(slice: Vec<u8>) -> Result<Self, Self::Error> {
        if slice.len() != PUBLIC_KEY_SIZE {
            return Err(Error::InvalidPublicKey);
        }
        let byte_array: [u8; PUBLIC_KEY_SIZE] =
            slice.try_into().map_err(|_| Error::InvalidPublicKey)?;
        Ok(PublicKey(byte_array))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&bs58::encode(&self.0).into_string())
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let slice = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::Base58Decode)?;
        PublicKey::try_from(slice)
    }
}
