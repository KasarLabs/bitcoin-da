# Bitcoin-da-rs

This crate allows to use bitcoin as a data availability layer.

It provides `write` and `read` functions. This can be included in any sequencer written in rust.

This repo is rust adaptation of rollkit's [bitcoin-da](https://github.com/rollkit/bitcoin-da).

## Prerequisites

- Install `bitcoind` & `bitcoin-cli`

- Launch a Bitcoin daemon

To launch a bitcoin daemon, run the following command:

```shell
bitcoind -conf=path_to/bitcoin.conf
```

If you don't already have a wallet, create one by doing:

```shell
bitcoin-cli createwallet test
```

Then mine some blocks:

```shell
bitcoin-cli -regtest -generate 150
```

## Building

The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:KasarLabs/da.git
cd da
cargo build
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more
detailed instructions.

## Example

```rs
fn test_write() {
        let embedded_data = b"Hello, world!";
        let relayer = Relayer::new(&Config::new(
            "localhost:8332".to_owned(),
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
        match relayer.write(&embedded_data) {
            Ok(txid) => {
                println!("Txid: {}", txid);
                println!("Successful write");
            }
            Err(e) => panic!("Write failed with error: {:?}", e),
        }
    }
```

## Tests

You can run tests with:

```
cargo test
```

## License

This project is licensed under the Apache 2.0 license.

See [LICENSE](./LICENSE) for more information.
