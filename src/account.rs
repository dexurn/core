use crate::error::Error;
use crate::{private::PrivateKey, public::PublicKey};
use bip39::rand::thread_rng;
use bip39::rand::Rng;
use bip39::Mnemonic;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use secp256k1::ecdh;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use sha2::Digest;
use sha2::Sha256;
use std::str::{self, FromStr};
use tiny_hderive::bip32::ExtendedPrivKey;
use wasm_bindgen::prelude::*;

#[derive(Debug)]
#[wasm_bindgen]
pub struct Account {
    private_key: PrivateKey,
    public_key: PublicKey,
    mnemonic: Mnemonic,
}

#[wasm_bindgen]
impl Account {
    pub fn new(password: &str, index: u8) -> Result<Account, Error> {
        let mnemonic = Mnemonic::generate(24).map_err(Error::from)?;
        let seed = mnemonic.to_seed(password);

        let mut path = String::from("m/44'/501'/0'/0/");
        path.push_str(index.to_string().as_str());

        let ext = ExtendedPrivKey::derive(&seed, path.as_str()).map_err(|_| Error::Unknown)?;
        let keypair =
            Keypair::from_seckey_slice(&Secp256k1::new(), &ext.secret()).map_err(Error::from)?;

        let private_key = PrivateKey::from_bytes(&keypair.secret_bytes())?;
        let public_key = PublicKey::from_bytes(&keypair.public_key().serialize())?;

        Ok(Account {
            private_key,
            public_key,
            mnemonic,
        })
    }

    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn from_phrase(phrase: &str, password: &str, index: u8) -> Result<Account, Error> {
        let mnemonic = Mnemonic::from_str(phrase).map_err(Error::from)?;
        let seed = mnemonic.to_seed(password);

        let mut path = String::from("m/44'/501'/0'/0/");
        path.push_str(index.to_string().as_str());

        let ext = ExtendedPrivKey::derive(&seed, path.as_str()).map_err(|_| Error::Unknown)?;
        let keypair =
            Keypair::from_seckey_slice(&Secp256k1::new(), &ext.secret()).map_err(Error::from)?;

        let private_key = PrivateKey::from_bytes(&keypair.secret_bytes())?;
        let public_key = PublicKey::from_bytes(&keypair.public_key().serialize())?;

        Ok(Account {
            private_key,
            public_key,
            mnemonic,
        })
    }

    pub fn create_account(&self, password: &str, index: u8) -> Result<Account, Error> {
        let seed = self.mnemonic.to_seed(password);

        let mut path = String::from("m/44'/501'/0'/0/");
        path.push_str(index.to_string().as_str());

        let ext = ExtendedPrivKey::derive(&seed, path.as_str()).map_err(|_| Error::Unknown)?;
        let keypair =
            Keypair::from_seckey_slice(&Secp256k1::new(), &ext.secret()).map_err(Error::from)?;

        let private_key = PrivateKey::from_bytes(&keypair.secret_bytes())?;
        let public_key = PublicKey::from_bytes(&keypair.public_key().serialize())?;

        Ok(Account {
            private_key,
            public_key,
            mnemonic: self.mnemonic.clone(),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let secp = Secp256k1::signing_only();

        let digest = Sha256::digest(message);
        let msg = Message::from_digest_slice(digest.as_slice()).map_err(Error::from)?;

        let signature = secp.sign_ecdsa(
            &msg,
            &SecretKey::from_slice(&self.private_key.to_bytes()).map_err(Error::from)?,
        );
        Ok(signature.serialize_compact().to_vec())
    }

    pub fn encrypt(&self, message: &[u8], public_key: &[u8]) -> Result<EncryptedData, Error> {
        let secret_key = SecretKey::from_slice(self.private_key.as_bytes()).map_err(Error::from)?;
        let pub_key = secp256k1::PublicKey::from_slice(public_key).map_err(Error::from)?;

        let shared_key = ecdh::shared_secret_point(&pub_key, &secret_key);
        let shared_key = &shared_key[..32];

        let cipher = XChaCha20Poly1305::new(shared_key.into());

        let binding = thread_rng().gen::<[u8; 24]>();
        let nonce = XNonce::from_slice(&binding);

        let cipher_text = cipher
            .encrypt(nonce, message)
            .map_err(|_| Error::BadEncryption)?;

        Ok(EncryptedData {
            nonce: nonce.to_vec(),
            cipher_text: cipher_text.to_vec(),
        })
    }

    pub fn decrypt(
        &self,
        cipher_text: &[u8],
        public_key: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let secret_key =
            SecretKey::from_slice(self.private_key.as_bytes()).map_err(|_| Error::BadDecryption)?;
        let pub_key = secp256k1::PublicKey::from_slice(public_key).map_err(Error::from)?;

        let shared_key = ecdh::shared_secret_point(&pub_key, &secret_key);
        let shared_key = &shared_key[..32];

        let cipher = XChaCha20Poly1305::new(shared_key.into());

        let decrypted_message = cipher
            .decrypt(XNonce::from_slice(nonce), cipher_text)
            .map_err(|_| Error::BadDecryption)?;

        Ok(decrypted_message)
    }

    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.to_vec()
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct EncryptedData {
    nonce: Vec<u8>,
    cipher_text: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedData {
    pub fn get_nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    pub fn get_cipher_text(&self) -> Vec<u8> {
        self.cipher_text.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::Account;

    #[test]
    fn test_sign_and_verify() {
        let account = Account::new("very_secure_password", 0).unwrap();
        let message = b"Hello, world!";
        let signature = account.sign(message).unwrap();
        assert_eq!(account.public_key.verify(message, &signature), Ok(()));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let alice = Account::new("very_secure_alice_password", 0).unwrap();
        let bob = Account::new("very_secure_bob_password", 0).unwrap();

        let message = b"Hello, world!";
        let encrypte_data = alice.encrypt(message, bob.public_key.as_bytes()).unwrap();
        let decrypted = bob
            .decrypt(
                &encrypte_data.cipher_text,
                alice.public_key.as_bytes(),
                &encrypte_data.nonce,
            )
            .unwrap();
        assert_eq!(message, decrypted.as_slice());
    }
}
