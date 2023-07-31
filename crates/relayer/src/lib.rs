use bitcoin::secp256k1::PublicKey;
use bitcoin::hash_types::Txid;
use bitcoin::blockdata::script::Builder;
use bitcoincore_rpc::Client as RpcClient;
use bitcoincore_rpc::Error;
use bitcoincore_rpc::Auth;


// Implement all functionnalities for Write/Read

const PROTOCOL_ID: &[u8] = &[0x72, 0x6f, 0x6c, 0x6c];

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
fn create_taproot_address(embedded_data: &[u8]) -> Result<String, String> {
    // Step 1: Decode bobPrivateKey as WIF

    // Step 2: Get the corresponding public key from the WIF private key

    // Step 3: Build the Taproot script with a single leaf

    // Step 4: Get the corresponding internal public key from internalPrivateKey

    // Step 5: Build the Taproot script tree

    // Step 6: Generate the Taproot output key

    // Step 7: Generate the Bech32m address

    // Step 8: Return the generated Taproot address

    Ok("Nothing for now".to_string())
}

// pay_to_taproot_script creates a pk script for a pay-to-taproot output key.
// TODO
pub fn pay_to_taproot_script(taproot_key: &PublicKey) -> Result<Vec<u8>, String> {
    let builder = Builder::new();

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