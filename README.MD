# Crypto Testing using Rust

This project is under construction by the moment!

## Objectives:

- Explore the capabilities of Rust
- Implement Asymetric Encryption using `secp256k1`
- Implement Digital Signature using `ecdsa`
- Implement Hash Functions using `sha256`
- Implement `PoW` using all the building blocks described before


### Usage 

- Generate Private/Public Key pair:
>` cargo run keygen`
- Sign a Message:
>` cargo run sign <PrivateKey> <Message>`
- Verify a Signature
>` cargo run verify <PublicKey> <Message> <Signature>`
- Mine Transaction:
>` cargo run mine <PrivateKey> <Message> <Difficulty>`