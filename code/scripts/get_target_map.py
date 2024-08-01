import os
import argparse

# 设置命令行参数解析
parser = argparse.ArgumentParser(description='Process target files.')
parser.add_argument('-e', '--target_edge_file', type=str, help='Path to the target edges file', default="/home/SVF-tools/example/objdump-CVE-2016-4487_transfer/obj-aflgo/temp/Transfer_edges.txt")
parser.add_argument('-b', '--target_blocks_file', type=str, help='Path to the target blocks file', default="/home/SVF-tools/example/objdump-CVE-2016-4487_transfer/obj-aflgo/temp/target_blocks.txt")
parser.add_argument('-m', '--save_file', type=str, help='Path to save the processed edges file', default="/home/SVF-tools/example/objdump-CVE-2016-4487_transfer/obj-aflgo/temp/target_map.txt")

# 解析命令行参数
args = parser.parse_args()

# 使用命令行提供的路径
target_edge_file = args.target_edge_file
target_blocks_file = args.target_blocks_file
save_file = args.save_file

block_id = {}
target_map = []

def find_last_block(b_id, b_dict):
    return_key = False
    sorted_dict = sorted(b_dict.keys())
    for key in sorted_dict:
        if b_id > key:
            return_key = key
        if b_id < key:
            break
    return return_key

with open(target_blocks_file, "r") as bbf:
    target_blocks = bbf.readlines()
    for block_item in target_blocks:
        block = block_item.strip().split(",")
        block_id[block[0]] = block[1]


target_map_list = []

with open(target_edge_file, "r") as eef:
    target_edges = eef.readlines()
    for edge_item in target_edges:
        if len(edge_item) < 2:
            target_map_list.append(target_map)
            target_map = []
            print("\t")
            continue
        edge = edge_item.strip().split(",")
        if edge[0] in block_id and edge[1] in block_id:
            edge_id = (int(block_id[edge[0]]) >> 1) ^ int(block_id[edge[1]])
            print("edge_id: %d" % edge_id)
            if edge_id not in target_map:
                target_map.append(edge_id)
        else:
            if edge[0] not in block_id:
                edge[0] = find_last_block(edge[0], block_id)
                # print("block_id not found: %s" % edge[0])
            if edge[1] not in block_id:
                edge[1] = find_last_block(edge[1], block_id)
                # print("block_id not found: %s" % edge[1])
            if edge[0] in block_id and edge[1] in block_id:
                edge_id = (int(block_id[edge[0]]) >> 1) ^ int(block_id[edge[1]])
                print("edge_id: %d" % edge_id)
                if edge_id not in target_map:
                    target_map.append(edge_id)

with open(save_file, "w") as sf:
    for target_map_item in target_map_list:
        target_map_str = ','.join(map(str, target_map_item))
        sf.write(target_map_str+"\n")
