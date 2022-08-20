# ethereum-crypto
Basic functionality for ethereum private-public key pairs and addresses

### Usage
`EthereumKeypair` can be constructed via private key string or generated randomly.  
You can export private key with `export_secret_key_as_hex_string` function.  
And you can get an `Address([u8;20])` which has `ToString` trait, so `to_string` function would get you an ethereum address.  
`utils::get_address_from_public_key` function is also public.