use bitcoin::secp256k1::PublicKey;
use relayer::pay_to_taproot_script;

#[test]
fn test_relayer_write() {
    let new_relayer = relayer::Relayer::new_relayer(&relayer::Config::new(
        "localhost::18332".to_owned(),
        "rpcuser".to_owned(),
        "rpcpass".to_owned(),
        true,
        true,
    ));

    match new_relayer {
        Ok(relayer) => {
            let bytes: &[u8] = b"rollkit-btc: gm";
            if let Err(error) = relayer.write(bytes) {
                eprintln!("Write failed: {}", error);
            } else {
                println!("done");
            }
        }
        Err(error) => eprintln!("Relayer failed: {}", error),
    }
}

#[test]
fn test_relayer_read() {
    let new_relayer = relayer::Relayer::new_relayer(&relayer::Config::new(
        "localhost::18332".to_owned(),
        "rpcuser".to_owned(),
        "rpcpass".to_owned(),
        true,
        true,
    ));

    match new_relayer {
        Ok(relayer) => {
            let bytes: &[u8] = b"rollkit-btc: gm";
            match relayer.write(bytes) {
                Ok(bytes_written) => println!("Number of bytes written: {}", bytes_written), // Translated
                Err(error) => {
                    eprintln!("Error while writing: {}", error); // Translated
                    return;
                }
            }

            let height: u64 = 146;
            match relayer.read(height) {
                Ok(blobs) => {
                    for blob in blobs {
                        match hex::decode(blob) {
                            Ok(got) => {
                                if let Ok(s) = String::from_utf8(got) {
                                    println!("{}", s);
                                } else {
                                    println!("Unable to convert to UTF-8 string."); // Translated
                                }
                            }
                            Err(err) => {
                                println!("{}", err);
                                return;
                            }
                        }
                    }
                }
                Err(_) => {
                    eprintln!("Failed to read");
                    return;
                }
            }
        }
        Err(error) => eprintln!("Failed Relayer: {}", error),
    }
}

fn main() {
    // Assuming you have a valid public key.
    let taproot_key = PublicKey::from_slice(&[0x02]).unwrap().x_only_public_key();

    match pay_to_taproot_script(&taproot_key.0) {
        Ok(script) => {
            // Do something with the script
            println!("Pay-to-taproot script: {:?}", script);
        }
        Err(err) => {
            // Handle the error
            eprintln!("Error: {}", err);
        }
    }
}
