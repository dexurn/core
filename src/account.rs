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

/// Represents a dexurn account with private and public keys generated from a mnemonic phrase.
///
/// An `Account` instance can be used to sign messages and encrypt/decrypt data. The account is created based on
/// a BIP39 mnemonic and uses secp256k1 for key generation.
///
/// # Examples
///
/// ```rust
/// use dex_core::account::Account;
///
/// // Create a new account with a password and index
/// let account = Account::new("my_password", 0).unwrap();
/// println!("Mnemonic: {}", account.phrase());
/// println!("Public Key: {:?}", account.public_key());
/// ```
#[derive(Debug)]
#[wasm_bindgen]
pub struct Account {
    private_key: PrivateKey,
    public_key: PublicKey,
    mnemonic: Mnemonic,
}

#[wasm_bindgen]
impl Account {
    /// Creates a new `Account` using a randomly generated mnemonic, password, and derivation index.
    ///
    /// # Arguments
    ///
    /// * `password`
    /// * `index` - A derivation index used to generate different keys from the same mnemonic.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if the account cannot be created due to invalid parameters or cryptographic failures.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dex_core::account::Account;
    ///
    /// let account = Account::new("my_password", 0).unwrap();
    /// ```
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

    /// Returns the mnemonic phrase associated with this account.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dex_core::account::Account;
    ///
    /// let account = Account::new("my_password", 0).unwrap();
    /// let phrase = account.phrase();
    /// println!("Mnemonic Phrase: {}", phrase);
    /// ```
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Creates an `Account` from an existing mnemonic phrase, password, and derivation index.
    ///
    /// This function allows you to recreate an account from a known mnemonic, which is useful for
    /// restoring accounts.
    ///
    /// # Arguments
    ///
    /// * `phrase` - The mnemonic phrase as a string.
    /// * `password`
    /// * `index` - The derivation index used to derive the account.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if the mnemonic is invalid or if cryptographic operations fail.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dex_core::account::Account;
    ///
    /// let account = Account::from_phrase("abandon abandon abandon ...", "my_password", 0).unwrap();
    /// ```
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

    /// Derives a new account from the current mnemonic using derivation index.
    ///
    /// This method creates a new account with a different keypair by changing the index, allowing for
    /// multiple accounts to be generated from a single mnemonic.
    ///
    /// # Arguments
    ///
    /// * `password`
    /// * `index` - The new index to derive a different account.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if the account cannot be created due to invalid parameters or cryptographic failures.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let account = existing_account.create_account("my_password", 1).unwrap();
    /// ```
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

    /// Signs a message with the account's private key and returns the signature.
    ///
    /// The message is hashed using SHA-256 before signing.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign as a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if signing fails due to invalid input or cryptographic issues.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let message = b"Hello, world!";
    /// let signature = account.sign(message).unwrap();
    /// println!("Signature: {:?}", signature);
    /// ```
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

    /// Encrypts a message using the recipient's public key and the account's private key.
    ///
    /// The encryption uses XChaCha20Poly1305 with a randomly generated nonce.
    ///
    /// # Arguments
    ///
    /// * `message` - The plaintext message to encrypt as a byte slice.
    /// * `public_key` - The recipient's public key as a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if encryption fails due to invalid input or cryptographic issues.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let encrypted_data = account.encrypt(b"message", &recipient_public_key).unwrap();
    /// ```
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

    /// Decrypts a message using the account's private key and the sender's public key.
    ///
    /// The decryption uses XChaCha20Poly1305 with the nonce provided.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - The encrypted data containing the nonce and ciphertext.
    /// * `public_key` - The sender's public key as a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if decryption fails due to invalid input or cryptographic issues.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let decrypted_message = account.decrypt(&encrypted_data, &sender_public_key).unwrap();
    /// ```
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

    /// Returns the account's private key as a byte vector.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let private_key = account.private_key();
    /// println!("Private Key: {:?}", public_key);
    /// ```
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.to_vec()
    }

    /// Returns the account's public key as a byte vector.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let public_key = account.public_key();
    /// println!("Public Key: {:?}", public_key);
    /// ```
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }
}

#[derive(Debug)]
#[wasm_bindgen]
/// Represents encrypted data, including the nonce and the ciphertext.
///
/// This struct holds the results of an encryption operation. The `nonce` is a unique value used
/// to ensure that the same plaintext encrypted multiple times will yield different ciphertexts.
/// The `cipher_text` is the result of the encryption process.
///
/// # Examples
///
/// ```ignore
/// // Access the nonce and ciphertext
/// let nonce = encrypted_data.get_nonce();
/// let cipher_text = encrypted_data.get_cipher_text();
/// ```
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
