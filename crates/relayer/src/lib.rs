use bitcoin::{BlockHash, error};
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::hash_types::Txid;
use bitcoin::taproot::{TaprootBuilder, TaprootBuilderError};
use bitcoincore_rpc::Client as RpcClient;
use bitcoincore_rpc::Error;
use bitcoincore_rpc::Auth;
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

pub enum BitcoinError {
    InvalidAddress,
    SendToAddressError,
    BadAmount,
    PrivateKeyErr,
    InvalidTxHash,
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
pub fn create_taproot_address(embedded_data: &[u8]) -> Result<String, BitcoinError> {
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
                let data = PushBytesBuf::try_from(chunk.to_vec());
                match data {
                    Ok(data) => builder = builder.push_slice(data),
                    Err(error) => eprintln!("create_taproot_address: failed to get PushBytesBuf from chunk : {}", error),
                }
                
            }
            builder = builder.push_opcode(opcodes::all::OP_ENDIF);
            builder = builder.push_slice(&pub_key.inner.serialize());
            builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
            let pk_script = builder.as_script();
            
            // let tap_leaf = TapLeaf::Script(pk_script.to_owned(), LeafVersion::TapScript);
            let taproot_builder = TaprootBuilder::new();
            let taproot_builder_added_leaf = taproot_builder.add_leaf(0, ScriptBuf::from_bytes(pk_script.to_bytes()));

            let internal_pkey = PrivateKey::from_wif(INTERNAL_PRIVATE_KEY);
            match internal_pkey {
                Ok(internal_pkey) => {
                    let internal_pub_key = internal_pkey.public_key(secp);
                    match taproot_builder_added_leaf {
                        Ok(taproot_builder_added_leaf) => {
                            let tap_tree = taproot_builder_added_leaf.finalize(secp, XOnlyPublicKey::from(internal_pub_key.inner));
                            match tap_tree {
                                Ok(tap_tree) => {
                                    let output_key = tap_tree.output_key();
                
                                    Ok(Address::p2tr_tweaked(output_key, Network::Bitcoin).to_string())
                                }
                                Err(_) => panic!("create_taproot_address : failed finalize traproot builder added leaf"),
                            }
                            
                        }
                        Err(_) => panic!("create_taproot_address : failed taproot_builder_added_leaf"),
                    }
                    
                } 
                Err(_) => Err(BitcoinError::PrivateKeyErr),
            }
            
        },
        _ => Err(BitcoinError::PrivateKeyErr),
    }
}

// pay_to_taproot_script creates a pk script for a pay-to-taproot output key.
// TODO
pub fn pay_to_taproot_script(taproot_key: &PublicKey) -> Result<Vec<u8>, String> {
    let builder = Builder::new();

    // OP_1 is equivalent to OP_TRUE in Bitcoin Script.
    builder
        .clone()
        .push_opcode(bitcoin::blockdata::opcodes::OP_TRUE);

    builder.clone().push_slice(&taproot_key.serialize());

    let script = builder.into_script();
    let script_bytes = script.as_bytes();

    Ok(script_bytes.to_vec())
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
            Ok(stopMessage) => {
                println!("Shutdown client : {}", stopMessage);
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
    pub fn commit_tx(&self, addr: &str) -> Result<Txid, BitcoinError> {
        let address: Address = Address::from_str(addr)
            .map_err(|_| BitcoinError::InvalidAddress)?
            .assume_checked();
        // .require_network(Network::Bitcoin)
        match address.address_type() {
            Some(AddressType::P2tr) => {
                // fee to cover the cost
                let amount = Amount::from_btc(0.0001).map_err(|_| BitcoinError::BadAmount)?;
                let hash: Txid = self
                    .client
                    .send_to_address(&address, amount, None, None, None, None, None, None)
                    .map_err(|_| BitcoinError::SendToAddressError)?;
                Ok(hash)
            }
            _ => Err(BitcoinError::InvalidAddress),
        }
    }

    // revealTx spends the output from the commit transaction and as part of the
    // script satisfying the tapscript spend path, posts the embedded data on
    // chain. It returns the hash of the reveal transaction and error, if any.
    pub fn reveal_tx(&self, embedded_data: &[u8], commit_hash: &Txid) -> Result<Txid, BitcoinError> {
        //TODO
        todo!();
    }

    pub fn read_transaction(&self, hash: &Txid) -> Result<Vec<u8>, BitcoinError> {
        let tx = match self.client.get_raw_transaction(hash, None) {
            Ok(bytes) => bytes,
            Err(err) => return Err(BitcoinError::InvalidTxHash),
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
        
        let block = self.client.get_block(&BlockHash::from(hash.unwrap()));
        
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
        // append id to data
        let mut data_with_id = Vec::from(&PROTOCOL_ID[..]);
        data_with_id.extend_from_slice(data);
        // create address with data in script
        let address: String = create_taproot_address(&data_with_id)?;
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
        TemplateMatch { opcode: opcodes::OP_FALSE.to_u8(), ..Default::default() },
        TemplateMatch { opcode: opcodes::all::OP_IF.to_u8(), ..Default::default() },
        TemplateMatch { expect_push_data: true, max_push_datas: 10, ..Default::default() },
        TemplateMatch { opcode: opcodes::all::OP_ENDIF.to_u8(), ..Default::default() },
        TemplateMatch { expect_push_data: true, max_push_datas: 1, ..Default::default() },
        TemplateMatch { opcode: opcodes::all::OP_CHECKSIG.to_u8(), ..Default::default() },
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
            let mut tokenizer = TapTree::script_leaves(&tap_tree);

            while let Some(op) = tokenizer.next() {
        
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
                    },
                    None => panic!("extract_push_data: non existing first opcode"),
                }
            }
        
            Some(template[2].extracted_data.clone())
        }
        Err(_) => panic!("extract_push_data: failed to get tap tree"),
    }
}