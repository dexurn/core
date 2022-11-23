use crate::{private::PrivateKey, public::PublicKey};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use crypto_box::aead::{Aead, AeadCore, Nonce};
use std::{convert::TryInto, str};
use tiny_hderive::bip32::ExtendedPrivKey;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Account {
    private_key: PrivateKey,
    public_key: PublicKey,
    mnemonic: Mnemonic,
}

#[wasm_bindgen]
pub struct EncryptedData {
    nonce: Vec<u8>,
    cipher: Vec<u8>,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str, index: u8) -> Account {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let seed = Seed::new(&mnemonic, password);
        let seed_bytes: &[u8] = seed.as_bytes();

        let mut path = String::from("m/44'/501'/0'/0/");
        path.push_str(index.to_string().as_str());

        let ext = ExtendedPrivKey::derive(seed_bytes, path.as_str()).unwrap();

        let private_key = PrivateKey::new(&ext.secret());
        let public_key = PublicKey::new(&private_key);

        Account {
            private_key,
            public_key,
            mnemonic,
        }
    }

    pub fn phrase(&self) -> String {
        self.mnemonic.phrase().to_string()
    }

    pub fn from_phrase(phrase: &str, password: &str, index: u8) -> Account {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, password);
        let seed_bytes: &[u8] = seed.as_bytes();

        let mut path = String::from("m/44'/501'/0'/0/");
        path.push_str(index.to_string().as_str());

        let ext = ExtendedPrivKey::derive(seed_bytes, path.as_str()).unwrap();

        let private_key = PrivateKey::new(&ext.secret());
        let public_key = PublicKey::new(&private_key);

        Account {
            private_key,
            public_key,
            mnemonic,
        }
    }

    pub fn create_account(&self, password: &str, index: u8) -> Account {
        let seed = Seed::new(&self.mnemonic, password);
        let seed_bytes: &[u8] = seed.as_bytes();

        let mut path = String::from("m/44'/501'/0'/0/");
        path.push_str(index.to_string().as_str());

        let ext = ExtendedPrivKey::derive(seed_bytes, path.as_str()).unwrap();

        let private_key = PrivateKey::new(&ext.secret());
        let public_key = PublicKey::new(&private_key);

        Account {
            private_key,
            public_key,
            mnemonic: self.mnemonic.clone(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let secret_key = ed25519_dalek::SecretKey::from_bytes(self.private_key.as_bytes()).unwrap();
        let public_key = ed25519_dalek::PublicKey::from(&secret_key);

        let keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair {
            secret: secret_key,
            public: public_key,
        };

        let signature = ed25519_dalek::Signer::sign(&keypair, message);
        signature.to_bytes().to_vec()
    }

    pub fn encrypt(&self, message: &[u8], public_key: &[u8]) -> EncryptedData {
        let bytes_pub_key: [u8; 32] = (*public_key).try_into().unwrap();
        let acc_box = crypto_box::ChaChaBox::new(
            &crypto_box::PublicKey::from(bytes_pub_key),
            &crypto_box::SecretKey::from(*self.private_key.as_bytes()),
        );
        let nonce = crypto_box::ChaChaBox::generate_nonce(&mut crypto_box::rand_core::OsRng);

        let cipher_text = acc_box.encrypt(&nonce, &message[..]).unwrap();

        EncryptedData {
            nonce: nonce.to_vec(),
            cipher: cipher_text.to_vec(),
        }
    }

    pub fn decrypt(
        &self,
        cipher_text: &[u8],
        public_key: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, String> {
        let bytes_pub_key: [u8; 32] = (*public_key).try_into().unwrap();

        let acc_box = crypto_box::ChaChaBox::new(
            &crypto_box::PublicKey::from(bytes_pub_key),
            &crypto_box::SecretKey::from(*self.private_key.as_bytes()),
        );
        let nonce = Nonce::<crypto_box::ChaChaBox>::from_slice(nonce);

        match acc_box.decrypt(&nonce, &cipher_text[..]) {
            Ok(m) => Ok(m),
            Err(_) => Err("Decryption failed!".to_string()),
        }
    }

    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.to_vec()
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }
}

impl Account {
    pub fn as_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn as_public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

mod tests {
    use super::*;
    use crate::constants::PRIVATE_KEY_LENGTH;
    #[test]
    fn test_sign_and_verify() {
        let account = Account::new("very_secure_password", 0);
        let message = b"Hello, world!";
        let signature = account.sign(message);
        assert_eq!(account.public_key.verify(message, &signature), Ok(()));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let alice = Account::new("very_secure_alice_password", 0);
        let bob = Account::new("very_secure_bob_password", 0);

        let message = b"Hello, world!";
        let encrypte_data = alice.encrypt(message, &bob.public_key.extract().1);
        let decrypted = bob
            .decrypt(
                &encrypte_data.cipher,
                &alice.public_key.extract().1,
                &encrypte_data.nonce,
            )
            .unwrap();
        assert_eq!(message, decrypted.as_slice());
    }
}
