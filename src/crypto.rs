extern crate secp256k1;
extern crate rand;
extern crate hex;
extern crate sha2;

use rand::OsRng;
use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey,  Message, Signature};

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
    let message = Message::from_slice(&message_hash).expect("32 bytes");
    let signature = secp.sign(&message, &private_key);
    let signature_hex = hex::encode(signature.serialize_der(&secp));
    println!("Signature: {:?}", signature_hex);
}

pub fn verify_content(args: Vec<String>){
    let secp = Secp256k1::new();
    let mut hasher = Sha256::new();
    //Retrieving Public Key and Verify Signature
    let public_key_decoded = hex::decode(&args[2]).expect("Decoding failed!");
    let signature_decoded = hex::decode(&args[4]).expect("Decoding Signature failed!");
    let encoded_message = hex::encode(&args[3]);
    //Hashing Message using Sha256 before verification
    hasher.input(encoded_message);
    let message_hash = hasher.result();
    println!("Hash for Encoded Message: {:?}", message_hash);    
    //Retrieving Message, Public Key and Signature
    let message = Message::from_slice(&message_hash).expect("32 bytes");
    let public_key = PublicKey::from_slice(&secp, &public_key_decoded).expect("Should match 32 bytes Public Key");
    let signature = Signature::from_der(&secp, &signature_decoded).expect("DER signature");
    let is_valid = secp.verify(&message, &signature, &public_key).is_ok();
    println!("Is Valid: {:?}", is_valid);
}

pub fn mine_content(args: Vec<String>){    
    let secp = Secp256k1::new();
    let mut hasher = Sha256::new();
    //Generating Private Key from Args
    let private_key_decoded = hex::decode(&args[2]).expect("Decoding failed!");
    //Retrieving Private Key from Slice
    let private_key = SecretKey::from_slice(&secp, &private_key_decoded).expect("Should match 32 bytes PK");
    //Set nonce at 0
    let mut nonce : u128 = 0;
    let difficulty : u8 = args[4].parse::<u8>().unwrap();
    //We need to verify how many bytes we need to compare in the mining process
    //also we need to take the remain
    //This process is intented to creacte a Consensus Protocol, we don't need too much efficiency on this
    let bytes : u8 = difficulty / 2;
    let bytes_remains : u8 = difficulty % 2;
    hasher.input(hex::encode(args[3].to_string() + &nonce.to_string()));
    let mut hash = hasher.result();
    let mut mined : bool = check_difficulty(bytes, bytes_remains, &hash);
    while !mined{
        nonce += 1;
        hasher = Sha256::new();
        hasher.input(hex::encode(args[3].to_string() + &nonce.to_string()));
        hash = hasher.result();
        mined = check_difficulty(bytes, bytes_remains, &hash);
    }
    //Generating Message for Signature:
    let message = Message::from_slice(&hash).expect("32 bytes");
    let signature = secp.sign(&message, &private_key).serialize_der(&secp);
    println!("Check Mining: {:?} Nonce: {:?} Hash: {:?} Signature: {:?}", mined, nonce, hash, signature);
    
}

fn check_difficulty(bytes:u8, remain:u8, hash:&[u8]) -> bool {
    let hash_vec = hash.to_vec();
    for i in 0..bytes{
        if hash_vec[i as usize] > 0 as u8 {
            return false;
        }
    }

    if remain > 0 {
        return hash_vec[bytes as usize] <= 0x0f as u8;
    }
    return true;
}
