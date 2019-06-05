/*
    This is for testing purpose!
    We'll use this project to:
        - Keygenerator for Private/Public keys
        - Sign/Verify content using ECDSA
        - Implement PoW
*/

use std::env;
mod crypto;

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];
    println!("Command: {:?}", command);
    match command.as_ref() {
        "keygen" =>
            crypto::key_gen(),
        "sign" =>
            crypto::sign_content(args),
        _ => println!("Unrecognized command: {:?}", command)
    }
}
