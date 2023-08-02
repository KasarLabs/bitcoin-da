use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytes;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, schnorr};
use bitcoin::hash_types::Txid;
use bitcoin::taproot::TapLeaf;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoincore_rpc::Client as RpcClient;
use bitcoincore_rpc::Error;
use bitcoincore_rpc::Auth;
use bitcoin::consensus::encode::deserialize;
use bitcoincore_rpc::RpcApi;
use bitcoin::script as txscript;
use bitcoin::key::PrivateKey;
use bitcoin::opcodes;
use bitcoin::address::AddressType;
use bitcoin::amount::Amount;
use bitcoin::blockdata::script::Builder;
use bitcoin::{Address, Network};
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TapTree;
use bitcoin::ScriptBuf;

use core::fmt;
use std::str::FromStr;

// Implement all functionnalities for Write/Read

const PROTOCOL_ID: [u8; 4] = [0x62, 0x61, 0x72, 0x6b]; // 'bark' in ASCII

// Sample data and keys for testing.
// bob key pair is used for signing reveal tx
// internal key pair is used for tweaking
const BOB_PRIVATE_KEY: &str = "5JoQtsKQuH8hC9MyvfJAqo6qmKLm8ePYNucs7tPu2YxG12trzBt";
const INTERNAL_PRIVATE_KEY: &str = "5JGgKfRy6vEcWBpLJV5FXUfMGNXzvdWzQHUM1rVLEUJfvZUSwvS";

// chunk_slice splits input slice into max chunk_size length slices
fn chunk_slice(slice: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut i = 0;
    while i < slice.len() {
        let end = i + chunk_size;

        // necessary check to avoid slicing beyond
        // slice capacity
        let end = if end > slice.len() {
            slice.len()
        } else {
            end
        };

        chunks.push(&slice[i..end]);
        i = end;
    }

    chunks
}

// create_taproot_address returns an address committing to a Taproot script with
// a single leaf containing the spend path with the script:
// <embedded data> OP_DROP <pubkey> OP_CHECKSIG
// TODO
fn create_taproot_address(embedded_data: &[u8]) -> Result<String, bitcoin::key::Error> {
    let priv_key = PrivateKey::from_wif(BOB_PRIVATE_KEY);
    match priv_key {
        Ok(priv_key) => {
            let secp = & Secp256k1::<All>::new();
            let pub_key = priv_key.public_key(secp);
            let mut builder = txscript::Builder::new();
            builder = builder.push_opcode(opcodes::OP_0);
            builder = builder.push_opcode(opcodes::all::OP_IF);
            let chunks = chunk_slice(embedded_data, 520);
            for chunk in chunks {
                // try to use PushBytes::from(chunk)
                builder = builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).unwrap());
            }
            builder = builder.push_opcode(opcodes::all::OP_ENDIF);
            builder = builder.push_slice(&pub_key.inner.serialize());
            builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
            let pk_script = builder.as_script();
            
            // let tap_leaf = TapLeaf::Script(pk_script.to_owned(), LeafVersion::TapScript);
            let mut taproot_builder = TaprootBuilder::new();
            taproot_builder = taproot_builder.add_leaf(0, ScriptBuf::from_bytes(pk_script.to_bytes())).unwrap();

            let internal_pkey = PrivateKey::from_wif(INTERNAL_PRIVATE_KEY).unwrap();
            let internal_pub_key = internal_pkey.public_key(secp);
            let tap_tree = taproot_builder.finalize(secp, XOnlyPublicKey::from(internal_pub_key.inner)).unwrap();
            let output_key = tap_tree.output_key();

            return Ok(
                Address::p2tr_tweaked(output_key, Network::Bitcoin).to_string()
            );
        },
        Err(err) => {
            return Err(err);
        }
    }
}

// pay_to_taproot_script creates a pk script for a pay-to-taproot output key.
// TODO
pub fn pay_to_taproot_script(taproot_key: &PublicKey) -> Result<Vec<u8>, String> {
    let builder = txscript::Builder::new();

    // OP_1 is equivalent to OP_TRUE in Bitcoin Script.
    builder.clone().push_opcode(bitcoin::blockdata::opcodes::OP_TRUE);

    builder.clone().push_slice(&taproot_key.serialize());

    let script = builder.into_script();
    let script_bytes = script.as_bytes();

    Ok(script_bytes.to_vec())
}

// Relayer is a bitcoin client wrapper which provides reader and writer methods
// to write binary blobs to the blockchain.
struct Relayer {
    client: RpcClient,
}

impl Relayer {
    // NewRelayer creates a new Relayer instance with the provided Config.
    //TO TEST
    fn NewRelayer(config: &Config) -> Result<Self, Error> {
        // Set up the connection to the bitcoin RPC server.
        let auth = Auth::UserPass(config.user.clone(), config.pass.clone());
        let client = RpcClient::new(&config.host, auth)?;

        Ok(Relayer { client })
    }

    // close shuts down the client.
    fn close(&self) {
        //TODO
    }

    // commitTx commits an output to the given taproot address, such that the
    // output is only spendable by posting the embedded data on chain, as part of
    // the script satisfying the tapscript spend path that commits to the data. It
    // returns the hash of the commit transaction and error, if any.
    fn commit_tx(&self, addr: &str) -> Result<Txid, Error> {
        //TODO
    }

    // revealTx spends the output from the commit transaction and as part of the
    // script satisfying the tapscript spend path, posts the embedded data on
    // chain. It returns the hash of the reveal transaction and error, if any.  
    fn reveal_tx(&self, embedded_data: &[u8], commit_hash: &Txid) -> Result<Txid, Error> {
        //TODO
    }


    fn ReadTransaction(client: &RpcClient, hash: &Txid) -> Result<Option<Vec<u8>>, Error> {
        let raw_tx = client.get_raw_transaction(hash, None)?;
    
        if let Ok(tx) = deserialize(&raw_tx) {  //TODO: find a way to deserialize
            if let Some(witness) = tx.input[0].witness.get(1) {
                if let Some(push_data) = ExtractPushData(0, witness) {
                    // Skip PROTOCOL_ID
                    if push_data.starts_with(PROTOCOL_ID) {
                        return Ok(Some(push_data[PROTOCOL_ID.len()..].to_vec()));
                    }
                }
            }
        }
    
        Ok(None)
    }

    fn Read(&self, height: u64) -> Result<Vec<Vec<u8>>, Box<dyn core::fmt::Debug>> {
        let hash = self.client.get_block_hash(height as u64)?;
        let block = self.client.get_block(&BlockHash::from(hash))?;
        let mut data = Vec::new();

        for tx in block.txdata.iter() {
            if let Some(witness) = tx.input[0].witness.nth(1) { //Verify that this is the right way to get the witness
                if let Some(push_data) = ExtractPushData(0, witness) {
                    // Skip PROTOCOL_ID
                    if push_data.starts_with(PROTOCOL_ID) {
                        data.push(push_data[PROTOCOL_ID.len()..].to_vec());
                    }
                }
            }
        }
        Ok(data)
    }

    fn Write(&self, data: &[u8]) -> Result<Txid, Box<dyn std::error::Error>> {
        let mut data_with_protocol_id = PROTOCOL_ID.to_vec();
        data_with_protocol_id.extend_from_slice(data);
    
        let address = create_taproot_address(&data_with_protocol_id)?;
        let commit_hash = self.commit_tx(&address)?;
        let reveal_hash = self.reveal_tx(data, &commit_hash)?;
    
        Ok(reveal_hash)
    }
    
}

struct Config {
    host: String,
    user: String,
    pass: String,
    http_post_mode: bool,
    disable_tls: bool,
}

impl Config {
    // Constructor to create a new Config instance
    fn new(host: String, user: String, pass: String, http_post_mode: bool, disable_tls: bool) -> Self {
        Config {
            host,
            user,
            pass,
            http_post_mode,
            disable_tls,
        }
    }
}

struct TemplateMatch {
    expect_push_data: bool,
    max_push_datas: usize,
    opcode: u8,
    extracted_data: Vec<u8>,
}

fn ExtractPushData(version: u16, pk_script: &[u8]) -> Option<Vec<u8>> {
    //TODO
    None
}
