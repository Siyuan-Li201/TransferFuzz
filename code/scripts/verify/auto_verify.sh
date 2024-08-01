#!/bin/bash

# Check arguments
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <binary_path> <command> <crash_dir> <crash_address>"
    exit 1
fi

BINARY_PATH=$1
COMMAND=$2
CRASH_DIR=$3
CRASH_ADDRESS=$4
REPORT_FILE="crash_report.txt"
RESULT_FILE="result.txt"

# Check if binary file exists
if [ ! -f "$BINARY_PATH" ]; then
    echo "Binary file '$BINARY_PATH' does not exist."
    exit 1
fi

# Check if crashes directory exists
if [ ! -d "$CRASH_DIR" ]; then
    echo "Directory '$CRASH_DIR' does not exist."
    exit 1
fi

# Clear the report and result files
> "$REPORT_FILE"
> "$RESULT_FILE"

# Iterate over all files in the crashes directory
for input in "$CRASH_DIR"/*; do
    if [ -f "$input" ]; then
        echo "Testing $input" | tee -a "$REPORT_FILE"

        # Replace "poc" in the command with the current input file path
        MODIFIED_COMMAND=${COMMAND//poc/$input}

        # Use gdb to run the program, run the command, and get the backtrace
        BT_OUTPUT=$(gdb --batch -ex "file $BINARY_PATH" -ex "run $MODIFIED_COMMAND" -ex "bt" | grep -v "(gdb)")

        # Save the backtrace to the report file
        echo "$BT_OUTPUT" >> "$REPORT_FILE"
        echo -e "\n" >> "$REPORT_FILE"

        # Check if the backtrace contains the crash address
        if echo "$BT_OUTPUT" | grep -q "$CRASH_ADDRESS"; then
            echo "$input" >> "$RESULT_FILE"
        fi
    fi
done

