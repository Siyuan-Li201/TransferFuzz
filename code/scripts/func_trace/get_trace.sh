#!/bin/bash


if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <PROGRAM> <ARGS> <INPUT_DIR> <OUTPUT_FILE>"
    exit 1
fi


PROGRAM=$1
ARGS=$2
INPUT_DIR=$3
OUTPUT_FILE=$4


> "$OUTPUT_FILE"


for FILE in "$INPUT_DIR"/*; do
    if [ -f "$FILE" ]; then
       
        MODIFIED_ARGS=${ARGS//poc/$FILE}

	echo $MODIFIED_ARGS;
        

        SEQUENCE=$(gdb --batch -ex "file $PROGRAM" -ex "run $MODIFIED_ARGS" -ex "bt" -ex "quit" 2>&1 | \
        awk '/^#[0-9]+/ {split($0, a, " "); print a[4]}' | tac | paste -sd "," -)
        

        echo "$SEQUENCE" >> "$OUTPUT_FILE"
    fi
done


sort -u "$OUTPUT_FILE" -o "$OUTPUT_FILE"

echo "Function call sequences saved to $OUTPUT_FILE"
