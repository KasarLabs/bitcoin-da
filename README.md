<!-- markdownlint-disable -->
<div align="center">
<img src="https://i.ibb.co/kM9JL7p/Barknet-tbg.png" height="256" style="border-radius: 15px;">
</div>
<div align="center">
<br />
<!-- markdownlint-restore -->

[![Project license](https://img.shields.io/github/license/kasarlabs/bitcoin-da.svg?style=flat-square)](LICENSE)
[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/kasarlabs/bitcoin-da/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
<a href="https://twitter.com/KasarLabs">
<img src="https://img.shields.io/twitter/follow/KasarLabs?style=social"/>
</a>
<a href="https://github.com/kasarlabs/bitcoin-da">
<img src="https://img.shields.io/github/stars/kasarlabs/bitcoin-da?style=social"/>
</a>
</div>

# 🧙‍♂️ Bitcoin-da-rs

This crate allows to use bitcoin as a data availability layer.

It offers both `write` and `read` functions. This can be incorporated into any sequencer written in Rust and has been specifically designed for [Madara](https://github.com/keep-starknet-strange/madara).

This repo is rust adaptation of rollkit's [bitcoin-da](https://github.com/rollkit/bitcoin-da).

The code isn't production ready. It is highly experimental.

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

Please refer to the [cargo documentation](https://doc.rust-lang.org/stable/cargo/) for more
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

Before running the test, you must have a bitcoin node running either on regtest or signet.
Then you need to change the rpc url accordingly.
You also need to comment/uncomment the required network in each test function.

## License

This project is licensed under the Apache 2.0 license.

See [LICENSE](./LICENSE) for more information.

## Contributors ✨

This project is a collaboration between [Kasar](https://twitter.com/kasarlabs) and [Taproot Wizards](https://twitter.com/TaprootWizards) 🧙‍♂️

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/0xEniotna"><img src="https://avatars.githubusercontent.com/u/101047205?v=4?s=100" width="100px;" alt="Antoine"/><br /><sub><b>Antoine</b></sub></a><br /><a href="https://github.com/kasarlabs/bitcoin-da/commits?author=0xEniotna" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/antiyro"><img src="https://avatars.githubusercontent.com/u/74653697?v=4?s=100" width="100px;" alt="Antiyro"/><br /><sub><b>Antiyro</b></sub></a><br /><a href="https://github.com/kasarlabs/bitcoin-da/commits?author=antiyro" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/betacodd"><img src="https://avatars.githubusercontent.com/u/97968794?v=4?s=100" width="100px;" alt="Betacod"/><br /><sub><b>Betacod</b></sub></a><br /><a href="https://github.com/kasarlabs/bitcoin-da/commits?author=betacodd" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/sparqet"><img src="https://avatars.githubusercontent.com/u/37338401?v=4?s=100" width="100px;" alt="Sparqet"/><br /><sub><b>Sparqet</b></sub></a><br /><a href="https://github.com/kasarlabs/bitcoin-da/commits?author=Sparqet" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/axelizsak"><img src="https://avatars.githubusercontent.com/u/98711930?v=4?s=100" width="100px;" alt="Axel Izsak"/><br /><sub><b>Axel Izsak</b></sub></a><br /><a href="https://github.com/kasarlabs/bitcoin-da/commits?author=axelizsak" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/zarboq"><img src="https://avatars.githubusercontent.com/u/37303126?v=4?s=100" width="100px;" alt="Zarboq"/><br /><sub><b>Zarboq</b></sub></a><br /><a href="https://github.com/kasarlabs/bitcoin-da/commits?author=zarboq" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>