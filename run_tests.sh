#!/bin/bash

# Default values
NETWORK="regtest"
LOG_LEVEL="none"
LONG_TESTS=0
BACKTRACE=0

# Parse command-line arguments
while getopts "l:b:t:L" opt; do
  case $opt in
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
    L)
      LONG_TESTS=1
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

# Derive the NETWORK value from ~/.bitcoin/bitcoin.conf
if grep -q '^regtest=1' ~/.bitcoin/bitcoin.conf; then
    NETWORK="regtest"
elif grep -q '^signet=1' ~/.bitcoin/bitcoin.conf; then
    NETWORK="signet"
else
    echo "No valid network configuration found in bitcoin.conf."
    exit 1
fi

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
if [ "$NETWORK" == "regtest" ]; then
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

FEATURES="$NETWORK"

if [ $LONG_TESTS -eq 1 ]; then
    FEATURES="$FEATURES,long_tests"
fi

# Create a temp file to capture the output
TEMP_FILE=$(mktemp)

# Call the Rust test and redirect output to the temp file and also display on the terminal
if [ "$LOG_LEVEL" == "none" ]; then
    if [ -z "$TEST_NAME" ]; then
        script -q /dev/null -c "RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES -- --nocapture" 2>&1 | tee $TEMP_FILE
    else
        script -q /dev/null -c "RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES $TEST_NAME -- --nocapture" 2>&1 | tee $TEMP_FILE
    fi
else
    if [ -z "$TEST_NAME" ]; then
        script -q /dev/null -c "RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES -- --nocapture" 2>&1 | tee $TEMP_FILE
    else
        script -q /dev/null -c "RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES $TEST_NAME -- --nocapture" 2>&1 | tee $TEMP_FILE
    fi
fi



# Check if the test failed
if grep -q "Insufficient funds" $TEMP_FILE; then
    echo "It appears you have insufficient funds in your wallet."
    echo "Please acquire coins for address: $WALLET_ADDRESS"
    if [ "$NETWORK" == "signet" ]; then
        echo "Visit a faucet website to get coins."
    fi
fi

# Delete the temporary file
rm $TEMP_FILE
