## Installation:

# Manual installation
1. Run export AFLGO=transferfuzz_installation_dir
2. Under folder transferfuzz: make clean all
3. Under folder transferfuzz/llvm-mode: make clean all, error message "recipe for target 'test_build' failed" can be ignored.

# Docker

Alternatively, you can use docker: 
We have installed all required dependency the docker. You thus do NOT need to install it yourself.

## Run transferfuzz:

Under folder transferfuzz/scripts/fuzz: run \*.sh to fuzz the programs. 
You can also write shell scripts to fuzz other programs following the samples.

We also provide shell scripts to check the fuzzing results (with asan)
Copy run.sh to target_dir/obj-aflgo(or obj-dist)/ and run run.sh

## Artifacts: 

You can check the artifacts in folder transferfuzz/scripts/fuzz/exp.zip. 
The numbers in folder names are CVE numbers we tested.
If the folder contains obj-dist, then check the fuzzing results (e.g., the time used and the crash PoCs) in obj-dist/out;
Otherwise, check the results in obj-aflgo/out;

## QA:

1. When transferfuzz is effective?

transferfuzz is effective when the software is large and the number of target is small.

2. When transferfuzz is not effective?

transferfuzz is not effective when the path constraints to fuzzing targets are difficult to satisfy, as it currently uses random mutation and does not corporate with input mutation techniques like symbolic execution and taint tracking. 

3. How to improve transferfuzz's efficiency?

We leveraged [1] to perform inter-procedural data-flow analysis and find relevant code. More advanced data-flow analysis will definitely improve transferfuzz's performance.

[1] Temporal system call specialization for attack surface reduction

## Publication

You can find more details in our [Oakland 2023 paper](https://www.computer.org/csdl/proceedings-article/sp/2023/933600b050/1Js0DBwgpwY).

```tex
@inproceedings{luo2023transferfuzz,
    title       = {transferfuzz: Efficient Directed Fuzzing with Selective Path Exploration},
    author      = {Changhua Luo, Wei Meng, and Penghui Li},
    booktitle   = {2023 2023 IEEE Symposium on Security and Privacy (SP) (SP)},
    year = {2023}
}
```

## Contacts

- Changhua Luo (<chluo@cse.cuhk.edu.hk>)
- Wei Meng (<wei@cse.cuhk.edu.hk>)
- Penghui Li (<phli@cse.cuhk.edu.hk>)


