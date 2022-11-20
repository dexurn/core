use std::convert::TryInto;

use ed25519_dalek::Verifier;

use crate::{constants::PUBLIC_KEY_LENGTH, private::PrivateKey};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

#[wasm_bindgen]
impl PublicKey {
    pub fn new(private_key: &PrivateKey) -> PublicKey {
        let sign_public_key = ed25519_dalek::PublicKey::from(
            &ed25519_dalek::SecretKey::from_bytes(private_key.as_bytes()).unwrap(),
        );
        let encription_public_key =
            crypto_box::PublicKey::from(&crypto_box::SecretKey::from(private_key.to_bytes()));
        
        let public_key: Vec<u8> = [
            *sign_public_key.as_bytes(),
            *encription_public_key.as_bytes(),
        ]
        .concat();


        PublicKey(
            (*public_key)
                .try_into()
                .expect("PublicKey with incorrect length!"),
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> PublicKey {
        PublicKey((*bytes).try_into().unwrap())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        let (sign_public_key, _) = self.extract();
        let sign_public_key = ed25519_dalek::PublicKey::from_bytes(&sign_public_key).unwrap();
        match sign_public_key.verify(
            message,
            &ed25519_dalek::Signature::from_bytes(signature).unwrap(),
        ) {
            Ok(_) => Ok(()),
            Err(_) => Err("Signature is not valid!".to_string()),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PublicKey {
    pub fn extract(&self) -> ([u8; 32], [u8; 32]) {
        let sign_public_key = &self.0[0..32];
        let encription_public_key = &self.0[32..64];

        (
            (*sign_public_key)
                .try_into()
                .expect("PublicKey with incorrect length!"),
            (*encription_public_key)
                .try_into()
                .expect("PublicKey with incorrect length!"),
        )
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0
    }

    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        &(self.0)
    }
}

mod tests {
    use super::*;
    use crate::constants::PRIVATE_KEY_LENGTH;
    #[test]
    fn test_public_key() {
        let private_key = PrivateKey::new(&[0; PRIVATE_KEY_LENGTH]);
        let public_key = PublicKey::new(&private_key);
        assert_eq!(public_key.to_bytes(), public_key.to_bytes());
        assert_eq!(public_key.as_bytes(), public_key.as_bytes());
    }

    #[test]
    fn test_extract() {
        let private_key = PrivateKey::new(&[0; PRIVATE_KEY_LENGTH]);
        let public_key = PublicKey::new(&private_key);
        let (sign_public_key, encription_public_key) = public_key.extract();
        assert_eq!(
            sign_public_key,
            ed25519_dalek::PublicKey::from(
                &ed25519_dalek::SecretKey::from_bytes(private_key.as_bytes()).unwrap(),
            )
            .to_bytes()
        );
        assert_eq!(
            encription_public_key,
            *crypto_box::PublicKey::from(&crypto_box::SecretKey::from(private_key.to_bytes()))
                .as_bytes()
        );
    }
}
