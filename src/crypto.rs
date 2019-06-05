extern crate secp256k1;
extern crate rand;
extern crate hex;
extern crate sha2;

use rand::OsRng;
use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, Message};

pub fn key_gen(){
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    println!("Secret Key: {:?}", secret_key.to_string());
    println!("Public Key: {:?}", public_key.to_string());
}

pub fn sign_content(args: Vec<String>){    
    let secp = Secp256k1::new();
    let mut hasher = Sha256::new();
    //Decoding Private Keys into Decimal and Encoding Message into Hex
    let private_key_decoded = hex::decode(&args[2]).expect("Decoding failed!");
    let encoded_message = hex::encode(&args[3]);
    println!("Encoded Message: {:?}", encoded_message);
    //Retrieving Private Key from Slice
    let private_key = SecretKey::from_slice(&secp, &private_key_decoded).expect("Should match 32 bytes PK");
    //Hashing Message using Sha256 before sign
    hasher.input(encoded_message);
    let message_hash = hasher.result();
    println!("Hash for Encoded Message: {:?}", message_hash);
    let message = Message::from_slice(&message_hash).expect("32 bytes");;
    let signature = secp.sign(&message, &private_key);
    println!("Signature: {:?}", signature.to_string());

}
