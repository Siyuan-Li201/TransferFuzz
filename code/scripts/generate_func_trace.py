import os
import sys

def read_func_trace_file(file_path):
    func_to_sources = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if ',' in line:  # Function call relationship
                funcs, source_info = line.split('|')
                caller, callee = funcs.split(',')
                if (caller, callee) not in func_to_sources:
                    func_to_sources[(caller, callee)] = []
                if source_info not in func_to_sources[(caller, callee)]:
                    func_to_sources[(caller, callee)].append(source_info)
            else:  # Single function
                func, source_info = line.split('|')
                if func not in func_to_sources:
                    func_to_sources[func] = []
                if source_info not in func_to_sources[func]:
                    func_to_sources[func].append(source_info)
    return func_to_sources

def process_infile(infile_path, func_to_sources):
    block_sources = set()
    edge_sources = []

    with open(infile_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            function_sequence = line.split(',')
            edge_list = []
            for i in range(len(function_sequence) - 1):
                func = function_sequence[i]
                next_func = function_sequence[i + 1]
                if func in func_to_sources:
                    block_sources.update(func_to_sources[func])  # Add all source lines for the function
                if (func, next_func) in func_to_sources:
                    for call_source_info in func_to_sources[(func, next_func)]:
                        block_sources.add(call_source_info)  # Add call source info to block sources
                        if next_func in func_to_sources:
                            for called_func_info in func_to_sources[next_func]:
                                edge_list.append("{},{}".format(call_source_info, called_func_info))

            edge_sources.append(edge_list)

    return block_sources, edge_sources

def write_transfer_blocks(block_sources, output_path):
    with open(output_path, 'w') as f:
        for source in sorted(block_sources):
            f.write(source + '\n')

def write_transfer_edges(edge_sources, output_path):
    with open(output_path, 'w') as f:
        for edge_list in edge_sources:
            for edge in edge_list:
                f.write(edge + '\n')
            f.write('\n')  # Add a new line between sequences

def main():
    if len(sys.argv) != 5:
        print("Usage: python script.py <infile_path> <func_trace_file_path> <transfer_blocks_output_path> <transfer_edges_output_path>")
        sys.exit(1)

    infile_path = sys.argv[1]
    func_trace_file_path = sys.argv[2]
    transfer_blocks_output_path = sys.argv[3]
    transfer_edges_output_path = sys.argv[4]

    func_to_sources = read_func_trace_file(func_trace_file_path)
    block_sources, edge_sources = process_infile(infile_path, func_to_sources)

    write_transfer_blocks(block_sources, transfer_blocks_output_path)
    write_transfer_edges(edge_sources, transfer_edges_output_path)

if __name__ == '__main__':
    main()