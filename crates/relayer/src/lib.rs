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

// createTaprootAddress returns an address committing to a Taproot script with
// a single leaf containing the spend path with the script:
// <embedded data> OP_DROP <pubkey> OP_CHECKSIG
fn create_taproot_address(embedded_data: &[u8]) -> Result<String, String> {

    Ok("Nothing for now".to_string())
    
}
