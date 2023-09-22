#!/bin/bash

# Default values
NETWORK="regtest"
LOG_LEVEL="none"
LONG_TESTS=0
BACKTRACE=0

# Parse command-line arguments
VALID_ARGS=$(getopt -o l:b:t:L --long log-level:,backtrace:,test-name:,long-tests,signet,regtest,conf: -- "$@")
if [[ $? -ne 0 ]]; then
    echo "Invalid arguments."
    exit 1;
fi

eval set -- "$VALID_ARGS"
while [ : ]; do
  case "$1" in
    -l | --log-level)
        LOG_LEVEL="$2"
        shift 2
        ;;
    -b | --backtrace)
        BACKTRACE="$2"
        shift 2
        ;;
    -t | --test-name)
        TEST_NAME="$2"
        shift 2
        ;;
    -L | --long-tests)
        LONG_TESTS=1
        shift
        ;;
    --signet)
        NETWORK="signet"
        shift
        ;;
    --regtest)
        NETWORK="regtest"
        shift
        ;;
    --) shift; 
        break 
        ;;
  esac
done


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
