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

This crate allows Bitcoin to function as a data availability layer, supporting both `write` and `read` operations. It's been developed with Rust sequencers in mind, particularly for integration with [Madara](https://github.com/keep-starknet-strange/madara). It's modeled after rollkit's [bitcoin-da](https://github.com/rollkit/bitcoin-da).

⚠️ **Disclaimer**: The code is currently in its experimental phase and is not recommended for production use.

## Prerequisites

Before you can proceed with using or testing this crate, there are a few setup steps you need to follow:

- **Installation**: Ensure `bitcoind` & `bitcoin-cli` are installed.

- **Setting up a Bitcoin Daemon**:

  - Start a bitcoin daemon with:
    ```shell
    bitcoind -conf=path_to/bitcoin.conf
    ```

  - If you're setting up for the first time and don't have a wallet yet:
    ```shell
    bitcoin-cli createwallet test
    ```

  - Mine some blocks (especially useful for regtest):
    ```shell
    bitcoin-cli -regtest -generate 150
    ```

**Note**: These steps are for both manual and automatic testing. For both cases you will still need to start `bitcoind` separately. Additionally, automated tests will only handle some `bitcoin-cli` operations such as `loadwallet` and setting the `test` label for the wallet in use.

## Building the Library

```shell
git clone git@github.com:KasarLabs/da.git
cd da
cargo build
```

For more detailed instructions on building Rust projects, refer to the [cargo documentation](https://doc.rust-lang.org/stable/cargo/).

## Example Usage

Here's a simple example to demonstrate how to use the library:

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

## Automated Testing with the Provided Script

This repo comes with an automation script (`run_tests.sh`) which simplifies the testing process by handling node operations and test configurations. The script assumes a bitcoin node is already running.

### Preparations:

- Grant the script execute permissions:
  ```bash
  chmod +x run_tests.sh
  ```

1. **Setup**: Ensure a Bitcoin node is running on the desired network (`regtest` or `signet`), and modify the RPC URL in your configuration as necessary. Depending on the test, you might also need to comment/uncomment the required network in the test function.

2. **Command Usage**:

```bash
./run_tests.sh -l [log level] -b [backtrace] -t [test name] -L
```

- `-l` Log level (`info`, `debug`, or `none`).
- `-b` Enable(1)/Disable(0) backtrace.
- `-t` Specify a test name (optional).
- `-L` Include tests that take a long time to complete in signet due to time it takes to complete a block. These tests run fast in regtest.

### Examples:

Run all tests with `debug` logs and backtrace:

```bash
./run_tests.sh -l debug -b 1
```

Run the `test_example` with `info` logs:

```bash
./run_tests.sh -l info -t test_example
```

## Manual Tests

If you prefer manual testing:

1. **Setup**: Ensure a Bitcoin node is running on the desired network (`regtest` or `signet`), and modify the RPC URL in your configuration as necessary. Depending on the test, you might also need to comment/uncomment the required network in the test function.

2. **Running Tests**:

  - **regtest**:
    ```shell
    cargo test --features regtest
    ```

  - **Signet**:
    ```shell
    cargo test --features signet
    ```

  - **With Logs**:
    ```shell
    RUST_LOG=debug cargo test
    ```

  - **Logs + Backtrace**:
    ```shell
    RUST_LOG=debug RUST_BACKTRACE=1 cargo test --features regtest -- --nocapture
    ```

## License

This project is under the Apache 2.0 license. Detailed information can be found in [LICENSE](./LICENSE).

## Contributors ✨

Collaborative work by [Kasar](https://twitter.com/kasarlabs) and [Taproot Wizards](https://twitter.com/TaprootWizards) 🧙‍♂️.

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