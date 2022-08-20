pub mod utils;

use secp256k1::{PublicKey, SecretKey};
use secp256k1::rand::{thread_rng};

pub struct EthereumKeypair {
    secret_key: SecretKey,
    public_key: PublicKey,
    address: EthereumAddress
}

pub struct EthereumAddress([u8;20]);

impl ToString for EthereumAddress {
    fn to_string(&self) -> String {
        let mut base = String::from("0x");
        base.push_str(&hex::encode(self.0));
        base
    }
}

impl EthereumKeypair {
    pub fn from_secret_key_string(private_key: String) -> Result<Self, String> {
        let trimmed = match private_key.strip_prefix("0x") {
            Some(t) => t,
            None => private_key.as_str()
        };
        if trimmed.len() != 64 {
            return Err("Incorrect private key length".to_string())
        }
        let decoded = match hex::decode(trimmed) {
            Ok(t) => t,
            Err(e) => return Err(e.to_string())
        };
        if decoded.len() != 32 {
            return Err("Incorrect private key length".to_string())
        }
        Ok(Self::from_secret_key(&decoded[0..32]))
    }

    pub fn from_secret_key(x: &[u8]) -> Self {
        let secret_key = SecretKey::from_slice(x).expect("Provided invalid private key.");
        let public_key = secret_key.public_key(secp256k1::SECP256K1);
        let address = utils::get_address_from_public_key(&public_key);
        Self {
            secret_key, public_key, address: EthereumAddress(address.try_into().expect("Wrong address length"))
        }
    }

    pub fn generate_new<T : secp256k1::rand::Rng + ?Sized>(rng_core: &mut T) -> Self {
        let (secret_key, public_key) = secp256k1::generate_keypair(rng_core);
        let address = utils::get_address_from_public_key(&public_key);
        Self {
            secret_key, public_key, address: EthereumAddress(address.try_into().expect("Wrong address length"))
        }
    }

    pub fn generate_new_with_thread_rng() -> Self {
        Self::generate_new(&mut thread_rng())
    }

    pub fn get_address(&self) -> &EthereumAddress {
        &self.address
    }

    pub fn export_secret_key_as_hex_string(&self) -> String {
        self.secret_key.display_secret().to_string()
    }

    pub fn export_public_key_as_hex_string(&self) -> String {
        self.public_key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::EthereumKeypair;

    #[test]
    #[should_panic]
    fn from_secret_key_string_0() {
        EthereumKeypair::from_secret_key_string("this is not a private key, probably".to_string()).unwrap();
    }

    #[test]
    fn from_secret_key_string_1() {
        let key = EthereumKeypair::from_secret_key_string(
            "742a504d9674cf3c3a6f2ade3b3780660559209ee45279c230a534ca35187b9e".to_string()
        ).unwrap();
        assert_eq!(
            key.export_secret_key_as_hex_string(),
            "742a504d9674cf3c3a6f2ade3b3780660559209ee45279c230a534ca35187b9e".to_string()
        );
        assert_eq!(
            key.get_address().to_string(),
            "0x55555556e84ad25e7d3288da2122f0784e27213d".to_string()
        );
    }

    #[test]
    fn generate_new() {
        let key = EthereumKeypair::generate_new_with_thread_rng();
        assert!(key.address.to_string().starts_with("0x"));
    }
}