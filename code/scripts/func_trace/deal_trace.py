import argparse

def process_function_sequence(sequence):
    seen_calls = set()
    result_sequence = []
    functions = sequence.split(',')

    if len(functions) > 10:
        for i in range(len(functions) - 1):
            call = (functions[i], functions[i + 1])
            if call not in seen_calls:
                seen_calls.add(call)
                result_sequence.append(call[0])
        if functions:
            result_sequence.append(functions[-1])  # add the last function
        if len(result_sequence) <= 20:
            return (','.join(result_sequence[1:]))
        else:
            return (','.join(result_sequence[1:20]))
    else:
        return sequence[5:]
    
    

def main():
    parser = argparse.ArgumentParser(description="Process function call sequences to remove duplicates.")
    parser.add_argument('infile', type=str, help="Path to the input file.")
    parser.add_argument('outfile', type=str, help="Path to the output file.")
    args = parser.parse_args()

    with open(args.infile, 'r') as infile, open(args.outfile, 'w') as outfile:
        for line in infile:
            line = line.strip()
            if line:
                processed_sequence = process_function_sequence(line)
                outfile.write(processed_sequence + '\n')

if __name__ == '__main__':
    main()
