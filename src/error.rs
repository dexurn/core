use wasm_bindgen::prelude::*;

#[derive(Debug, PartialEq)]
#[wasm_bindgen]
pub enum Error {
    IncorrectSignature,
    InvalidMessage,
    InvalidPublicKey,
    InvalidSignature,
    InvalidPrivateKey,
    InvalidSharedSecret,
    InvalidRecoveryId,
    InvalidTweak,
    NotEnoughMemory,
    InvalidPublicKeySum,
    InvalidParityValue,
    InvalidEllSwift,
    BadWordCount,
    UnknownWord,
    BadEntropyBitCount,
    InvalidChecksum,
    BadEncryption,
    BadDecryption,
    Unknown,
}

impl From<bip39::Error> for Error {
    fn from(value: bip39::Error) -> Self {
        match value {
            bip39::Error::BadWordCount(_) => Error::BadWordCount,
            bip39::Error::UnknownWord(_) => Error::UnknownWord,
            bip39::Error::BadEntropyBitCount(_) => Error::BadEntropyBitCount,
            bip39::Error::InvalidChecksum => Error::InvalidChecksum,
            bip39::Error::AmbiguousLanguages(_) => Error::Unknown,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(value: secp256k1::Error) -> Self {
        match value {
            secp256k1::Error::IncorrectSignature => Error::IncorrectSignature,
            secp256k1::Error::InvalidMessage => Error::InvalidMessage,
            secp256k1::Error::InvalidPublicKey => Error::InvalidPublicKey,
            secp256k1::Error::InvalidSignature => Error::InvalidSignature,
            secp256k1::Error::InvalidSecretKey => Error::InvalidPrivateKey,
            secp256k1::Error::InvalidSharedSecret => Error::InvalidSharedSecret,
            secp256k1::Error::InvalidRecoveryId => Error::InvalidRecoveryId,
            secp256k1::Error::InvalidTweak => Error::InvalidTweak,
            secp256k1::Error::NotEnoughMemory => Error::NotEnoughMemory,
            secp256k1::Error::InvalidPublicKeySum => Error::InvalidPublicKeySum,
            secp256k1::Error::InvalidParityValue(_) => Error::InvalidParityValue,
            secp256k1::Error::InvalidEllSwift => Error::InvalidEllSwift,
        }
    }
}
