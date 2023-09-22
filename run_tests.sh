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

FEATURES="$NETWORK"

if [ $LONG_TESTS -eq 1 ]; then
    FEATURES="$FEATURES,long_tests"
fi

# Create a temp file to capture the output
TEMP_FILE=$(mktemp)

# Call the Rust test and redirect output to the temp file and also display on the terminal
if [ "$LOG_LEVEL" == "none" ]; then
    if [ -z "$TEST_NAME" ]; then
        RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES -- --nocapture 2>&1 | tee $TEMP_FILE
    else
        RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES $TEST_NAME -- --nocapture 2>&1 | tee $TEMP_FILE
    fi
else
    if [ -z "$TEST_NAME" ]; then
        RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES -- --nocapture 2>&1 | tee $TEMP_FILE
    else
        RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=$BACKTRACE cargo test --features $FEATURES $TEST_NAME -- --nocapture 2>&1 | tee $TEMP_FILE
    fi
fi

# Delete the temporary file
rm $TEMP_FILE
