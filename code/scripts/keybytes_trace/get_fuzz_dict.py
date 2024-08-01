import os
import re
import argparse

def extract_byte_sequences(input_file, output_file):
    byte_sequences = set() 

    with open(input_file, 'r') as file:
        for line in file:
           
            match = re.search(r'in fileBytes: (.*)', line)
            if match:
                byte_sequence = match.group(1).strip()
               
                formatted_sequence = re.sub(r' ', r'\\x', byte_sequence)
               
                formatted_sequence = '"' + formatted_sequence + '"'
                formatted_sequence = formatted_sequence.replace('"', r'"\x', 1)
               
                formatted_sequence = re.sub(r'\\x([0-9a-fA-F])([^0-9a-fA-F]|$)', r'\\x0\1\2', formatted_sequence)
                byte_sequences.add(formatted_sequence)

   
    with open(output_file, 'w') as output:
        for sequence in byte_sequences:
            output.write(sequence + '\n')

def main():
    parser = argparse.ArgumentParser(description="Extract byte sequences from input file and write to output file.")
    parser.add_argument('input_file', type=str, help="Path to the input file.")
    parser.add_argument('output_file', type=str, help="Path to the output file.")
    args = parser.parse_args()


    output_dir = os.path.dirname(args.output_file)
    if not os.path.exists(output_dir) and output_dir != '':
        os.makedirs(output_dir)

    extract_byte_sequences(args.input_file, args.output_file)

if __name__ == '__main__':
    main()
