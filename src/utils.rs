use secp256k1::PublicKey;
use sha3::Keccak256;
use sha3::Digest;

pub fn get_address_from_public_key(pubkey: &PublicKey) -> Vec<u8> {
    let pubkey_bytes = &pubkey.serialize_uncompressed()[1..65];
    let mut hasher = Keccak256::new();
    hasher.update(pubkey_bytes);
    hasher.finalize()[12..32].to_vec()
}