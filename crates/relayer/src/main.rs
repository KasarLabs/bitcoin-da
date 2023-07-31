use relayer::pay_to_taproot_script;
use bitcoin::secp256k1::PublicKey;

fn main() {
    // Assuming you have a valid public key.
    let taproot_key = PublicKey::from_slice(&[0x02]).unwrap();
    
    match pay_to_taproot_script(&taproot_key) {
        Ok(script) => {
            // Do something with the script
            println!("Pay-to-taproot script: {:?}", script);
        },
        Err(err) => {
            // Handle the error
            eprintln!("Error: {}", err);
        }
    }
}