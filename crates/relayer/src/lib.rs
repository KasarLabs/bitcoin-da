use bitcoin::amount::Amount;
use bitcoin::blockdata::script::Builder;
use bitcoin::hash_types::Txid;

use bitcoin::address::AddressType;
use bitcoin::key::PrivateKey;
use bitcoin::opcodes;
use bitcoin::script as txscript;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::KeyPair;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TapTree;
use bitcoin::taproot::TaprootBuilder;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::Witness;
use bitcoin::{Address, Network};
use bitcoin::{TxIn, TxOut};
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client as RpcClient;
use bitcoincore_rpc::Error;
use bitcoincore_rpc::RpcApi;
use core::fmt;

// Implement all functionnalities for Write/Read

const PROTOCOL_ID: [u8; 4] = [0x62, 0x61, 0x72, 0x6b]; // 'bark' in ASCII

// Sample data and keys for testing.
// bob key pair is used for signing reveal tx
// internal key pair is used for tweaking
// const BOB_PRIVATE_KEY: &str = "5JoQtsKQuH8hC9MyvfJAqo6qmKLm8ePYNucs7tPu2YxG12trzBt";
const INTERNAL_PRIVATE_KEY: &str = "5JGgKfRy6vEcWBpLJV5FXUfMGNXzvdWzQHUM1rVLEUJfvZUSwvS";

#[derive(Debug)]
pub enum BitcoinError {
    InvalidAddress,
    SendToAddressError,
    BadAmount,
    PrivateKeyErr,
    InvalidTxHash,
    ControlBlockErr,
    TransactionErr,
    RevealErr,
    InvalidNetwork,
}

// Implement the Display trait for custom error
impl fmt::Display for BitcoinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BitcoinError::InvalidAddress => write!(f, "Invalid address"),
            BitcoinError::SendToAddressError => write!(f, "Send to address error"),
            BitcoinError::BadAmount => write!(f, "Amount parsing error"),
            BitcoinError::PrivateKeyErr => write!(f, "Private key error"),
            BitcoinError::InvalidTxHash => write!(f, "Invalid transaction hash"),
            BitcoinError::ControlBlockErr => write!(f, "Control block error"),
            BitcoinError::TransactionErr => write!(f, "Transaction error"),
            BitcoinError::RevealErr => write!(f, "Reveal error"),
            BitcoinError::InvalidNetwork => write!(f, "Invalid network"),
        }
    }
}

// chunk_slice splits input slice into max chunk_size length slices
pub fn chunk_slice(slice: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut i = 0;
    while i < slice.len() {
        let end = i + chunk_size;

        // necessary check to avoid slicing beyond
        // slice capacity
        let end = if end > slice.len() { slice.len() } else { end };

        chunks.push(&slice[i..end]);
        i = end;
    }

    chunks
}

fn build_script(embedded_data: &[u8]) -> txscript::Builder {
    let mut builder = txscript::Builder::new();
    builder = builder
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(PushBytesBuf::try_from("block".as_bytes().to_vec()).unwrap())
        .push_int(1)
        .push_slice(PushBytesBuf::try_from("block_height".as_bytes().to_vec()).unwrap()) // replace by actual block height
        .push_opcode(opcodes::OP_0);
    let chunks = chunk_slice(embedded_data, 520);
    for chunk in chunks {
        builder = builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).unwrap());
    }
    builder = builder.push_opcode(opcodes::all::OP_ENDIF);
    let builder: txscript::Builder = builder.push_opcode(opcodes::OP_TRUE);

    builder
}

// create_taproot_address returns an address committing to a Taproot script with
// a single leaf containing the spend path with the script
pub fn create_taproot_address(
    embedded_data: &[u8],
    network: Network,
) -> Result<Address, BitcoinError> {
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
    Ok(Address::p2tr_tweaked(output_key, network))
}

pub fn pay_to_taproot_script(taproot_key: &XOnlyPublicKey) -> Result<ScriptBuf, String> {
    let builder = Builder::new()
        .push_opcode(opcodes::all::OP_PUSHNUM_1)
        .push_slice(taproot_key.serialize())
        .into_script();
    Ok(builder)
}

fn find_commit_idx_output_from_txid(
    txid: &Txid,
    client: &RpcClient,
) -> Result<(usize, TxOut), BitcoinError> {
    let raw_commit: Transaction = client.get_raw_transaction(txid, None).unwrap();
    let mut commit_idx = None;
    let mut commit_output = None;
    // look for the good UTXO
    for (i, out) in raw_commit.output.iter().enumerate() {
        // fee amount
        if out.value == 100000 {
            commit_idx = Some(i);
            commit_output = Some(out);
            break;
        }
    }
    let commit_idx = commit_idx.ok_or(BitcoinError::TransactionErr).unwrap();
    let commit_output = commit_output.ok_or(BitcoinError::TransactionErr).unwrap();
    Ok((commit_idx, commit_output.clone()))
}

// Relayer is a bitcoin client wrapper which provides reader and writer methods
// to write binary blobs to the blockchain.
pub struct Relayer {
    client: RpcClient,
}

impl Relayer {
    // NewRelayer creates a new Relayer instance with the provided Config.
    //TO TEST
    pub fn new_relayer(config: &Config) -> Result<Self, Error> {
        // Set up the connection to the bitcoin RPC server.
        // NOTE: for testing bitcoind can be used in regtest with the following params -
        // bitcoind -chain=regtest -rpcport=18332 -rpcuser=rpcuser -rpcpassword=rpcpass -fallbackfee=0.000001 -txindex=1
        let auth = Auth::UserPass(config.user.clone(), config.pass.clone());
        let client = RpcClient::new(&config.host, auth)?;

        Ok(Relayer { client })
    }

    // close shuts down the client.
    pub fn close(&self) {
        let shutdown = self.client.stop();
        match shutdown {
            Ok(stop_message) => {
                println!("Shutdown client : {}", stop_message);
            }
            Err(error) => {
                println!("Failed to stop client : {}", error);
            }
        }
    }

    // commitTx commits an output to the given taproot address, such that the
    // output is only spendable by posting the embedded data on chain, as part of
    // the script satisfying the tapscript spend path that commits to the data. It
    // returns the hash of the commit transaction and error, if any.
    pub fn commit_tx(&self, addr: &Address) -> Result<Txid, BitcoinError> {
        match addr.address_type() {
            Some(AddressType::P2tr) => {
                // fee to cover the cost
                let amount = Amount::from_btc(0.001).map_err(|_| BitcoinError::BadAmount)?;
                let hash: Txid = self
                    .client
                    .send_to_address(addr, amount, None, None, None, None, None, None)
                    .map_err(|_| BitcoinError::SendToAddressError)?;
                Ok(hash)
            }
            _ => Err(BitcoinError::InvalidAddress),
        }
    }

    // revealTx spends the output from the commit transaction and as part of the
    // script satisfying the tapscript spend path, posts the embedded data on
    // chain. It returns the hash of the reveal transaction and error, if any.
    pub fn reveal_tx(
        &self,
        embedded_data: &[u8],
        commit_hash: &Txid,
    ) -> Result<Txid, BitcoinError> {
        let (commit_idx, commit_output) =
            find_commit_idx_output_from_txid(commit_hash, &self.client).unwrap();
        // build pubkey, it is the same used to create the address
        let secp = &Secp256k1::<All>::new();
        let internal_prkey = PrivateKey::from_wif(INTERNAL_PRIVATE_KEY).unwrap();
        let internal_pub_key = internal_prkey.public_key(secp);
        let x_pub_key: XOnlyPublicKey = XOnlyPublicKey::from(internal_pub_key.inner);
        // build inscription script
        let builder: txscript::Builder = build_script(embedded_data);
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
                    txid: *commit_hash,
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
            value: 50000, // in satoshi
            script_pubkey: p2tr_script,
        };
        tx.output.push(tx_out);

        // control block to pass to the witness.
        let control_block = tap_tree
            .control_block(&((pk_script.into()), LeafVersion::TapScript))
            .ok_or(BitcoinError::ControlBlockErr)
            .unwrap();

        // Assemble the witness
        // Add script witness data (OP_FALSE as we want the false path), script, and control block to the witness field of the input
        tx.input[0].witness.push(pk_script.as_bytes());
        tx.input[0].witness.push(control_block.serialize());

        let txid = self.client.send_raw_transaction(&tx);
        match txid {
            Ok(hash) => Ok(hash),
            Err(_err) => Err(BitcoinError::RevealErr),
        }
    }

    pub fn read_transaction(&self, hash: &Txid) -> Result<Vec<u8>, BitcoinError> {
        let tx = match self.client.get_raw_transaction(hash, None) {
            Ok(bytes) => bytes,
            Err(_err) => return Err(BitcoinError::InvalidTxHash),
        };

        if tx.input[0].witness.len() > 1 {
            let witness = &tx.input[0].witness;
            let witness = witness[1].to_vec(); // Convert &[u8] to Vec<u8>
            let push_data = match extract_push_data(0, witness) {
                Some(data) => data,
                None => return Err(BitcoinError::InvalidTxHash),
            };

            let protocol_id_ref: &[u8] = &PROTOCOL_ID;
            if push_data.starts_with(protocol_id_ref) {
                return Ok(push_data[PROTOCOL_ID.len()..].to_vec());
            }
        }

        Err(BitcoinError::InvalidTxHash)
    }

    pub fn read(&self, height: u64) -> Result<Vec<Vec<u8>>, Box<dyn core::fmt::Debug>> {
        let hash = self.client.get_block_hash(height);

        match hash {
            Ok(block_hash) => {
                println!("Succeed to get the blockhash : {}", block_hash);
            }
            Err(error) => {
                panic!("read: failed to get block hash : {}", error);
            }
        }

        let block = self.client.get_block(&hash.unwrap());

        match block {
            Ok(_) => {
                println!("Succeed to get the block");
            }
            Err(error) => {
                panic!("read: failed to get block : {}", error);
            }
        }

        let mut data = Vec::new();

        for tx in block.unwrap().txdata.iter() {
            if let Some(witness) = tx.input[0].witness.nth(1) {
                if let Some(push_data) = extract_push_data(0, witness.to_vec()) {
                    // Skip PROTOCOL_ID
                    if push_data.starts_with(&PROTOCOL_ID) {
                        data.push(push_data[PROTOCOL_ID.len()..].to_vec());
                    }
                }
            }
        }
        Ok(data)
    }

    pub fn write(&self, data: &[u8]) -> Result<Txid, BitcoinError> {
        let blockchain_info = self.client.get_blockchain_info().unwrap();
        let network_name = &blockchain_info.chain;

        let network = Network::from_core_arg(network_name)
            .map_err(|_| BitcoinError::InvalidNetwork)
            .unwrap();
        // append id to data
        let mut data_with_id = Vec::from(&PROTOCOL_ID[..]);
        data_with_id.extend_from_slice(data);
        // create address with data in script
        let address: Address = create_taproot_address(&data_with_id, network)?;
        // Perform commit transaction with fees which create the UTXO
        let hash: Txid = self.commit_tx(&address)?;
        // Spend the UTXO and reveal the scipt hence data.
        let hash2: Txid = self.reveal_tx(&data_with_id, &hash)?;
        Ok(hash2)
    }
}

pub struct Config {
    host: String,
    user: String,
    pass: String,
    http_post_mode: bool,
    disable_tls: bool,
}

impl Config {
    // Constructor to create a new Config instance
    pub fn new(
        host: String,
        user: String,
        pass: String,
        http_post_mode: bool,
        disable_tls: bool,
    ) -> Self {
        Config {
            host,
            user,
            pass,
            http_post_mode,
            disable_tls,
        }
    }
}

#[derive(Default)]
pub struct TemplateMatch {
    expect_push_data: bool,
    max_push_datas: usize,
    opcode: u8,
    extracted_data: Vec<u8>,
}

pub fn extract_push_data(version: u8, pk_script: Vec<u8>) -> Option<Vec<u8>> {
    let template = [
        TemplateMatch {
            opcode: opcodes::OP_FALSE.to_u8(),
            ..Default::default()
        },
        TemplateMatch {
            opcode: opcodes::all::OP_IF.to_u8(),
            ..Default::default()
        },
        TemplateMatch {
            expect_push_data: true,
            max_push_datas: 10,
            ..Default::default()
        },
        TemplateMatch {
            opcode: opcodes::all::OP_ENDIF.to_u8(),
            ..Default::default()
        },
        TemplateMatch {
            expect_push_data: true,
            max_push_datas: 1,
            ..Default::default()
        },
        TemplateMatch {
            opcode: opcodes::all::OP_CHECKSIG.to_u8(),
            ..Default::default()
        },
    ];

    let mut template_offset = 0;

    let ver = LeafVersion::from_consensus(version);

    match ver {
        Ok(_) => {
            println!("Succeed to get the version");
        }
        Err(error) => {
            panic!("extract_push_data: failed to get version : {}", error);
        }
    }

    let node_info = NodeInfo::new_leaf_with_ver(ScriptBuf::from_bytes(pk_script), ver.unwrap());

    let tap_tree_from_node_info = TapTree::try_from(node_info);

    match tap_tree_from_node_info {
        Ok(tap_tree) => {
            let tokenizer = TapTree::script_leaves(&tap_tree);

            for op in tokenizer {
                if template_offset >= template.len() {
                    return None;
                }

                let tpl_entry = &template[template_offset];

                //To be reviewed on testing
                let first_opcode = op.script().first_opcode();
                match first_opcode {
                    Some(opcode) => {
                        if !tpl_entry.expect_push_data && opcode.to_u8() != tpl_entry.opcode {
                            return None;
                        }
                        template_offset += 1;
                    }
                    None => panic!("extract_push_data: non existing first opcode"),
                }
            }

            Some(template[2].extracted_data.clone())
        }
        Err(_) => panic!("extract_push_data: failed to get tap tree"),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

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
    fn test_create_taproot_address() {
        let embedded_data = b"Hello, world!";
        let network = Network::Regtest; // Change this as necessary.
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
                println!("Taproot address: {}", address);
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
        let relayer = Relayer::new_relayer(&Config::new(
            "localhost:8332".to_owned(),
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
            false,
            false,
        ))
        .unwrap();
        let embedded_data = b"Hello, world!";
        let network = Network::Regtest;
        let test_addr: Address = create_taproot_address(embedded_data, network).unwrap();

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
        let relayer = Relayer::new_relayer(&Config::new(
            "localhost:8332".to_owned(),
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
            false,
            false,
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
        println!("Taproot address: {}", address);
        // do first transaction -> commit
        match relayer.commit_tx(&address) {
            Ok(txid) => {
                println!("Commit Txid: {}", txid);
                // from commit txid get the good utxo/output
                let (commit_idx, commit_output) =
                    find_commit_idx_output_from_txid(&txid, &relayer.client).unwrap();
                println!("commit_output: {}", commit_output.script_pubkey);
                // build pubkey, it is the same used to create the address
                let secp = &Secp256k1::<All>::new();
                let internal_prkey = PrivateKey::from_wif(INTERNAL_PRIVATE_KEY).unwrap();
                let internal_pub_key = internal_prkey.public_key(secp);
                let x_pub_key: XOnlyPublicKey = XOnlyPublicKey::from(internal_pub_key.inner);
                println!("x_only_pub_key: {}", x_pub_key);
                // build inscription script
                let builder: txscript::Builder = build_script(&data_with_id);
                let pk_script = builder.as_script();
                println!("pk_script: {}", pk_script);
                // build taproot tree
                let mut taproot_builder = TaprootBuilder::new();
                taproot_builder = taproot_builder.add_leaf(0, pk_script.into()).unwrap();
                let tap_tree = taproot_builder.finalize(secp, x_pub_key).unwrap();
                let output_key = tap_tree.output_key();
                println!("output_key: {}", output_key);
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
                println!("p2tr_script: {}", p2tr_script);
                assert_eq!(p2tr_script, commit_output.script_pubkey);
                // min relay fee and build output
                let tx_out = TxOut {
                    value: 50000, // in satoshi
                    script_pubkey: p2tr_script,
                };
                tx.output.push(tx_out);

                // control block to pass to the witness.
                let control_block = tap_tree
                    .control_block(&((pk_script.into()), LeafVersion::TapScript))
                    .ok_or(BitcoinError::ControlBlockErr)
                    .unwrap();

                println!("control_block: {:?}", control_block);
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
        let relayer = Relayer::new_relayer(&Config::new(
            "localhost:8332".to_owned(),
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
            false,
            false,
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
        println!("Taproot address: {}", address);
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
        let relayer = Relayer::new_relayer(&Config::new(
            "localhost:8332".to_owned(),
            "rpcuser".to_owned(),
            "rpcpass".to_owned(),
            false,
            false,
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
        match relayer.write(&data_with_id) {
            Ok(txid) => {
                println!("Txid: {}", txid);
                println!("Successful write");
            }
            Err(e) => panic!("Write failed with error: {:?}", e),
        }
    }
}
