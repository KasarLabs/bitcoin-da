use bitcoin::{error, secp256k1::PublicKey};
use hex;
use relayer::Relayer;
use relayer::{pay_to_taproot_script, Config};

#[test]
fn test_relayer_write() {
    let new_relayer = Relayer::new_relayer(&Config::new(
        "localhost::18332".to_owned(),
        "rpcuser".to_owned(),
        "rpcpass".to_owned(),
        true,
        true,
    ));
    match new_relayer {
        Ok(relayer) => {
            let bytes: &[u8] = b"rollkit-btc: gm";
            let result = relayer.write(bytes);
            match result {
                Err(error) => {
                    eprintln!("Write failed : {}", error);
                    return;
                }
                _ => {
                    println!("done");
                }
            }
        }
        Err(error) => {
            eprintln!("Relayer failed : {}", error)
        }
    }

    #[test]
    fn test_relayer_read() {
        let new_relayer = Relayer::new_relayer(&Config::new(
            "localhost::18332".to_owned(),
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
            true,
            true,
        ));
        match new_relayer {
            Ok(relayer) => {
                let bytes: &[u8] = b"rollkit-btc: gm";
                let result = relayer.write(bytes);
                match result {
                    Ok(bytes_written) => {
                        println!("Nombre d'octets écrits : {}", bytes_written);
                    }
                    Err(error) => {
                        eprintln!("Erreur lors de l'écriture : {}", error);
                        return;
                    }
                }

                let height: u64 = 146;
                let reader = relayer.read(height);
                match reader {
                    Ok(blobs) => {
                        for blob in blobs {
                            let decoded_blob = hex::decode(blob);

                            match decoded_blob {
                                Ok(got) => {
                                    if let Ok(s) = String::from_utf8(got) {
                                        println!("{}", s);
                                    } else {
                                        println!("Impossible de convertir en chaîne UTF-8.");
                                    }
                                }
                                Err(err) => {
                                    println!("{}", err);
                                    return;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("Failed to read");
                        return;
                    }
                }
            }
            Err(error) => {
                eprintln!("Failed Relayer : {}", error);
                return;
            }
        }
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
