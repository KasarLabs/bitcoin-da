# bitcoin_rs

To launch a bitcoin daemon, run the following command:

```shell
bitcoind -conf=path_to/bitcoin.conf -fallbackfee=0.00001
```

Then mine some blocks (you need to have a bitcoin-cli wallet):

```shell
bitcoin-cli -regtest -generate 150
```

bitcoin.conf file:

```shell
##
## bitcoin.conf configuration file. Lines beginning with # are comments.
##
daemon=1
regtest=1

listen=0
debug=1
printtoconsole=1
# JSON-RPC options (for controlling a running Bitcoin/bitcoind process)

[regtest]
rpcuser=rpcuser
rpcpassword=rpcpass
rpcport=8332
wallet=test
# server=1 tells Bitcoin-Qt and bitcoind to accept JSON-RPC commands
server=1
```
