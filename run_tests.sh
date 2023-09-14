#!/bin/bash

# Default values
NETWORK="regnet"
LOG_LEVEL="none"
BACKTRACE=0

# Parse command-line arguments
while getopts "n:l:b:t:" opt; do
  case $opt in
    n)
      if [ "$OPTARG" == "signet" ] || [ "$OPTARG" == "regnet" ]; then
        NETWORK=$OPTARG
      else
        echo "Invalid network option. Use 'regnet' or 'signet'."
        exit 1
      fi
      ;;
    l)
    if [ "$OPTARG" == "debug" ] || [ "$OPTARG" == "info" ] || [ "$OPTARG" == "none" ]; then
        LOG_LEVEL=$OPTARG
    else
        echo "Invalid log level option. Use 'info', 'debug', or 'none'."
        exit 1
    fi
    ;;
    b)
      BACKTRACE=$OPTARG
      ;;
    t)
      TEST_NAME="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Copy the bitcoin configuration from the current directory to ~/.bitcoin
cp ./bitcoin.conf ~/.bitcoin/

# Modify the ~/.bitcoin/bitcoin.conf based on the chosen network
if [ "$NETWORK" == "regnet" ]; then
    sed -i 's/^#\(regtest=1\)/\1/' ~/.bitcoin/bitcoin.conf
    sed -i 's/^\(signet=1\)/#\1/' ~/.bitcoin/bitcoin.conf
elif [ "$NETWORK" == "signet" ]; then
    sed -i 's/^#\(signet=1\)/\1/' ~/.bitcoin/bitcoin.conf
    sed -i 's/^\(regtest=1\)/#\1/' ~/.bitcoin/bitcoin.conf
else
    echo "Invalid network specified."
    exit 1
fi

# Start the Bitcoin daemon with the specific network
if [ "$NETWORK" == "regnet" ]; then
    bitcoind -regtest
elif [ "$NETWORK" == "signet" ]; then
    bitcoind -signet
else
    echo "Invalid network specified."
    exit 1
fi

# Sleep for a few seconds to allow the daemon to initialize
sleep 5

# Create a wallet if it doesn't exist
bitcoin-cli createwallet test 2>/dev/null

# Load the wallet
bitcoin-cli loadwallet test 2>/dev/null

# Function to get address by label
get_address_by_label() {
    local network=$1
    LABEL_ADDRESS=$(bitcoin-cli -$network getaddressesbylabel "test" | jq -r 'keys[0]')
    if [ -z "$LABEL_ADDRESS" ]; then
        # Create a new address and label it
        NEW_ADDRESS=$(bitcoin-cli -$network getnewaddress)
        bitcoin-cli -$network setlabel "$NEW_ADDRESS" "test"
        LABEL_ADDRESS=$NEW_ADDRESS
    fi
    echo $LABEL_ADDRESS
}


# Conditional block generation based on the network
if [ "$NETWORK" == "regnet" ]; then
    bitcoin-cli -regtest -generate 150
    WALLET_ADDRESS=$(get_address_by_label "regtest")
elif [ "$NETWORK" == "signet" ]; then
    echo "Transactions must be confirmed on signet (this might take some time)."
    WALLET_ADDRESS=$(get_address_by_label "signet")
    # You can't force block generation on signet,
    # Implementing a waiting mechanism here if required might be a good idea
else
    echo "Invalid network specified."
    exit 1
fi

# Create a temp file to capture the output
TEMP_FILE=$(mktemp)

# Call the Rust test and redirect output to the temp file and also display on the terminal
if [ "$LOG_LEVEL" == "none" ]; then
    if [ -z "$TEST_NAME" ]; then
        RUST_BACKTRACE=$BACKTRACE cargo test --features $NETWORK -- --nocapture 2>&1 | tee $TEMP_FILE
    else
        RUST_BACKTRACE=$BACKTRACE cargo test --features $NETWORK $TEST_NAME -- --nocapture 2>&1 | tee $TEMP_FILE
    fi
else
    if [ -z "$TEST_NAME" ]; then
        RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=$BACKTRACE cargo test --features $NETWORK -- --nocapture 2>&1 | tee $TEMP_FILE
    else
        RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=$BACKTRACE cargo test --features $NETWORK $TEST_NAME -- --nocapture 2>&1 | tee $TEMP_FILE
    fi
fi




# Check if the test failed
if grep -q "Insufficient funds" $TEMP_FILE; then
    echo "It appears you have insufficient funds in your wallet."
    echo "Please acquire coins for address: $WALLET_ADDRESS"
    if [ "$NETWORK" == "signet" ]; then
        echo "Visit the faucet at: https://alt.signetfaucet.com/ to get coins."
    fi
fi

# Delete the temporary file
rm $TEMP_FILE

# Stop the Bitcoin daemon after tests
bitcoin-cli stop