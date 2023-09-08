#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::address::AddressType;
    use bitcoin::hash_types::Txid;
    use bitcoin::key::PrivateKey;
    use bitcoin::opcodes;
    use bitcoin::script as txscript;
    use bitcoin::secp256k1::KeyPair;
    use bitcoin::secp256k1::XOnlyPublicKey;
    use bitcoin::secp256k1::{All, Secp256k1};
    use bitcoin::taproot::LeafVersion;
    use bitcoin::taproot::TaprootBuilder;
    use bitcoin::BlockHash;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::Transaction;
    use bitcoin::Witness;
    use bitcoin::{Address, Network};
    use bitcoin::{TxIn, TxOut};
    use bitcoin_hashes::sha256d;
    use bitcoincore_rpc::RpcApi;

    use bitcoin_da::*;

    #[test]
    fn test_chunk_slice() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let chunk_size = 3;
        let chunks = chunk_slice(&data, chunk_size);

        assert_eq!(chunks.len(), 4); // Expect 4 chunks for 10 items with chunk size 3

        assert_eq!(chunks[0], &[1, 2, 3]); // First chunk
        assert_eq!(chunks[1], &[4, 5, 6]); // Second chunk
        assert_eq!(chunks[2], &[7, 8, 9]); // Third chunk
        assert_eq!(chunks[3], &[10]); // Fourth chunk

        // Test with empty data
        let data: Vec<u8> = vec![];
        let chunks = chunk_slice(&data, chunk_size);

        assert_eq!(chunks.len(), 0); // Expect 0 chunks for empty data
    }

    #[test]
    fn test_extract_push_data() {
        let mock_script = vec![
            opcodes::OP_FALSE.to_u8(),   // OP_0
            opcodes::all::OP_IF.to_u8(), // OP_IF
            opcodes::all::OP_PUSHBYTES_5.to_u8(),
            0x62,
            0x6c,
            0x6f,
            0x63,
            0x6b,                     // OP_PUSHBYTES_5 "block"
            opcodes::OP_TRUE.to_u8(), // OP_PUSHNUM_1
            opcodes::all::OP_PUSHBYTES_12.to_u8(),
            0x62,
            0x6c,
            0x6f,
            0x63,
            0x6b,
            0x5f,
            0x68,
            0x65,
            0x69,
            0x67,
            0x68,
            0x74,                      // OP_PUSHBYTES_12 "block_height"
            opcodes::OP_FALSE.to_u8(), // OP_0
            opcodes::all::OP_PUSHBYTES_17.to_u8(),
            0x62,
            0x61,
            0x72,
            0x6b,
            0x48,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x2c,
            0x20,
            0x77,
            0x6f,
            0x72,
            0x6c,
            0x64,
            0x21,                               // OP_PUSHBYTES_17 "barkHello, world!"
            opcodes::all::OP_ENDIF.to_u8(),     // OP_ENDIF
            opcodes::all::OP_PUSHNUM_1.to_u8(), // OP_PUSHNUM_1
        ];

        let res = extract_push_data(mock_script);
        // single data chunk
        assert_eq!(res, Some(b"barkHello, world!".to_vec()));

        let mock_script_2 = vec![
            opcodes::OP_FALSE.to_u8(),   // OP_0
            opcodes::all::OP_IF.to_u8(), // OP_IF
            opcodes::all::OP_PUSHBYTES_5.to_u8(),
            0x62,
            0x6c,
            0x6f,
            0x63,
            0x6b,                     // OP_PUSHBYTES_5 "block"
            opcodes::OP_TRUE.to_u8(), // OP_PUSHNUM_1
            opcodes::all::OP_PUSHBYTES_12.to_u8(),
            0x62,
            0x6c,
            0x6f,
            0x63,
            0x6b,
            0x5f,
            0x68,
            0x65,
            0x69,
            0x67,
            0x68,
            0x74,                      // OP_PUSHBYTES_12 "block_height"
            opcodes::OP_FALSE.to_u8(), // OP_0
            opcodes::all::OP_PUSHBYTES_17.to_u8(),
            0x62,
            0x61,
            0x72,
            0x6b,
            0x48,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x2c,
            0x20,
            0x77,
            0x6f,
            0x72,
            0x6c,
            0x64,
            0x21, // OP_PUSHBYTES_17 "barkHello, world!"
            opcodes::all::OP_PUSHBYTES_17.to_u8(),
            0x62,
            0x61,
            0x72,
            0x6b,
            0x48,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x2c,
            0x20,
            0x77,
            0x6f,
            0x72,
            0x6c,
            0x64,
            0x21,
            opcodes::all::OP_ENDIF.to_u8(),     // OP_ENDIF
            opcodes::all::OP_PUSHNUM_1.to_u8(), // OP_PUSHNUM_1
        ];

        let res2 = extract_push_data(mock_script_2);
        // 2 data chunk
        assert_eq!(res2, Some(b"barkHello, world!barkHello, world!".to_vec()));
    }

    #[test]
    fn test_create_taproot_address() {
        let embedded_data = b"Hello, world!";
        // let network = Network::Regtest; // Change this as necessary.
        let network = Network::Signet;

        let secp = &Secp256k1::<All>::new();
        let internal_pkey = PrivateKey::from_wif(INTERNAL_PRIVATE_KEY).unwrap();

        let key_pair = KeyPair::from_secret_key(secp, &internal_pkey.inner);
        let (x_pub_key, _) = XOnlyPublicKey::from_keypair(&key_pair);

        let builder: txscript::Builder = build_script(embedded_data);

        let pk_script = builder.as_script();
        let mut taproot_builder = TaprootBuilder::new();
        taproot_builder = taproot_builder.add_leaf(0, pk_script.into()).unwrap();
        let tap_tree = taproot_builder.finalize(secp, x_pub_key).unwrap();
        let output_key = tap_tree.output_key();
        match create_taproot_address(embedded_data, network) {
            Ok(address) => {
                assert!(
                    address.payload.matches_script_pubkey(
                        pay_to_taproot_script(&output_key.to_inner())
                            .unwrap()
                            .as_script()
                    ),
                    "Script does not match"
                );
                assert!(
                    address.is_related_to_xonly_pubkey(&output_key.to_inner()),
                    "Wrong pub key"
                );
                assert!(address.address_type() == Some(AddressType::P2tr)); // sanity check
                assert!(address.network == network);
            }
            Err(e) => {
                panic!("create_taproot_address failed with error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_commit_tx() {
        let relayer = Relayer::new(&Config::new(
            // "YOUR_NODE_IP:38332".to_owned(), // SIGNET
            "localhost:8332".to_owned(), // REGNET
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
        ))
        .unwrap();
        let embedded_data = b"Hello, world!";
        let network = Network::Regtest;
        // let network = Network::Signet;

        let test_addr: Address = create_taproot_address(embedded_data, network).unwrap();
        println!("Test address: {}", test_addr);
        match relayer.commit_tx(&test_addr) {
            Ok(txid) => {
                println!("Commit Txid: {}", txid);
            }
            Err(e) => panic!("Test failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_reveal() {
        // Create data and relayer
        let embedded_data = b"Hello, world!";
        let relayer = Relayer::new(&Config::new(
            // "YOUR_NODE_IP:38332".to_owned(), // SIGNET
            "localhost:8332".to_owned(), // REGNET
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
        ))
        .unwrap();
        // get network, should be regtest
        let blockchain_info = relayer.client.get_blockchain_info().unwrap();
        let network_name = &blockchain_info.chain;
        let network = Network::from_core_arg(network_name)
            .map_err(|_| BitcoinError::InvalidNetwork)
            .unwrap();
        assert_eq!(network, Network::Regtest);
        // assert_eq!(network, Network::Signet);

        // append id to data
        let mut data_with_id = Vec::from(&PROTOCOL_ID[..]);
        data_with_id.extend_from_slice(embedded_data);
        // create address with data in script
        let address = create_taproot_address(&data_with_id, network).unwrap();
        // do first transaction -> commit
        match relayer.commit_tx(&address) {
            Ok(txid) => {
                // from commit txid get the good utxo/output
                let (commit_idx, commit_output) =
                    find_commit_idx_output_from_txid(&txid, &relayer.client).unwrap();
                // build pubkey, it is the same used to create the address
                let secp = &Secp256k1::<All>::new();
                let internal_prkey = PrivateKey::from_wif(INTERNAL_PRIVATE_KEY).unwrap();
                let internal_pub_key = internal_prkey.public_key(secp);
                let x_pub_key: XOnlyPublicKey = XOnlyPublicKey::from(internal_pub_key.inner);
                // build inscription script
                let builder: txscript::Builder = build_script(&data_with_id);
                let pk_script = builder.as_script();
                // build taproot tree
                let mut taproot_builder = TaprootBuilder::new();
                taproot_builder = taproot_builder.add_leaf(0, pk_script.into()).unwrap();
                let tap_tree = taproot_builder.finalize(secp, x_pub_key).unwrap();
                let output_key = tap_tree.output_key();
                // build reveal transaction
                let mut tx = Transaction {
                    version: 2,
                    lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint {
                            txid,
                            vout: commit_idx as u32,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: bitcoin::Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    output: Vec::new(),
                };
                // outputkey should match commit_output and p2tr_script
                let p2tr_script = pay_to_taproot_script(&output_key.to_inner()).unwrap();
                assert_eq!(p2tr_script, commit_output.script_pubkey);
                // min relay fee and build output
                let tx_out = TxOut {
                    value: 1000, // in satoshi
                    script_pubkey: p2tr_script,
                };
                tx.output.push(tx_out);

                // control block to pass to the witness.
                let control_block = tap_tree
                    .control_block(&((pk_script.into()), LeafVersion::TapScript))
                    .ok_or(BitcoinError::ControlBlockErr)
                    .unwrap();

                // Assemble the witness
                // Add script and control block to the witness field of the input
                tx.input[0].witness.push(pk_script.as_bytes());
                tx.input[0].witness.push(control_block.serialize());

                let txid = relayer.client.send_raw_transaction(&tx);
                match txid {
                    Ok(txid) => {
                        println!("Reveal Txid: {}", txid);
                    }
                    Err(e) => panic!("Reveal failed with error: {:?}", e),
                }
            }
            Err(e) => panic!("Commit failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_reveal2() {
        let embedded_data = b"Hello, world!";
        let relayer = Relayer::new(&Config::new(
            // "YOUR_NODE_IP:38332".to_owned(), // SIGNET
            "localhost:8332".to_owned(), // REGNET
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
        ))
        .unwrap();
        // get network, should be regtest
        let blockchain_info = relayer.client.get_blockchain_info().unwrap();
        let network_name = &blockchain_info.chain;
        let network = Network::from_core_arg(network_name)
            .map_err(|_| BitcoinError::InvalidNetwork)
            .unwrap();
        assert_eq!(network, Network::Regtest);
        // append id to data
        let mut data_with_id = Vec::from(&PROTOCOL_ID[..]);
        data_with_id.extend_from_slice(embedded_data);
        // create address with data in script
        let address = create_taproot_address(&data_with_id, network).unwrap();
        // do first transaction -> commit
        match relayer.commit_tx(&address) {
            Ok(txid) => match relayer.reveal_tx(&data_with_id, &txid) {
                Ok(txid) => {
                    println!("Reveal Txid: {}", txid);
                    println!("Successful Reveal");
                }
                Err(e) => panic!("Reveal failed with error: {:?}", e),
            },
            Err(e) => panic!("Commit failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_write() {
        let embedded_data = b"Hello, world!";
        let relayer = Relayer::new(&Config::new(
            // "YOUR_NODE_IP:38332".to_owned(), // SIGNET
            "localhost:8332".to_owned(), // REGNET
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
        ))
        .unwrap();
        // get network, should be regtest
        let blockchain_info = relayer.client.get_blockchain_info().unwrap();
        let network_name = &blockchain_info.chain;
        let network = Network::from_core_arg(network_name)
            .map_err(|_| BitcoinError::InvalidNetwork)
            .unwrap();
        // assert_eq!(network, Network::Regtest);
        assert_eq!(network, Network::Signet);

        match relayer.write(embedded_data) {
            Ok(txid) => {
                println!("Txid: {}", txid);
                println!("Successful write");
            }
            Err(e) => panic!("Write failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_read_height() {
        let relayer = Relayer::new(&Config::new(
            // "YOUR_NODE_IP:38332".to_owned(), // SIGNET
            "localhost:8332".to_owned(), // REGNET
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
        ))
        .unwrap();
        let height = 112; // change to whatever height that contains a tx
        match relayer.read_height(height) {
            Ok(data) => {
                // Change this line to whatever data you want.
                // "bark" is appended to the beginning of the data
                assert_eq!(data, b"barkHello, world!".to_vec());
                println!("Successful read");
            }
            Err(e) => panic!("Read failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_read_transaction() {
        let relayer = Relayer::new(&Config::new(
            "localhost:8332".to_owned(),
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
        ))
        .unwrap();

        let tx_hash = "a3df602b6e04ae7a2572ef825399c1f5b25bbcee9fe9883997247b327af15bd5";
        let hash = sha256d::Hash::from_str(tx_hash).unwrap();
        let txid: Txid = Txid::from_raw_hash(hash);
        let block_hash = "567e7046d6efc52ea754da016539c0dc508bfb7981f1e4b4d521d4141423e385";
        let block: BlockHash = BlockHash::from_str(block_hash).unwrap();

        match relayer.read_transaction(&txid, Some(&block)) {
            Ok(data) => {
                assert_eq!(data, b"barkbarkHello, world!".to_vec());
            }
            Err(e) => panic!("Read_transaction failed with error: {:?}", e),
        }
    }
}
