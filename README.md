# TransferFuzz
The code and dataset of the paper are at [https://github.com/Siyuan-Li201/TransferFuzz](https://github.com/Siyuan-Li201/TransferFuzz).

We introduce TransferFuzz, a novel vulnerability verification framework, to verify whether vulnerabilities propagated through code reuse can be triggered in new software. 

- Input: A fuzz driver script of the target binary. A basic binary with PoC.
- Output: The PoCs of the target binary.

We have enhanced the code and documentation to automate all steps:

- **Function-level Trace Extraction**. We wrote Python scripts to automate calls to GDB to extract function call stacks after crashes.
- **Key-bytes Trace Extraction**. We use PIN for taint analysis and judge whether tainted bytes come directly from POC bytes.
- **Trace Guided Fuzzing**: We wrap the modified code parts in macro definitions, enabling easy migration to new fuzzing technologies.
- **Crash Classification**. We wrote a shell script to automatically determine whether the fuzzing process is finished by viewing the crash address through GDB.

<br><br>

## 1. Introduction
- code: The sourcecode of TransferFuzzt
- bin: The 76 binaries used in the paper (along with two .so file). Since Git LFS is not easily accessible, you can download all binaries from [bin](https://drive.google.com/file/d/1TU1o0J5mpTFPEo-683DP01fV2IcrM_Hm/view?usp=sharing) here.
- poc: The 53 POCs of the 15 CVE vulnerabilities.

<br><br>

## 2. Reproduction of the veridied vulnerability code

#### 2.1 Reproduction of the 53 vulnerabilities (38 new and 15 origin vulnerabilities)

1. Download the binaries and POCs from `/bin` and `/poc`.
2. Execute the binaries with poc by the harness below. (To meet environment dependencies, it is recommended to run in the provided Docker container.)

#### 2.2 harness
1. tiffsplit-2016-10095: tiffsplit @@
2. tiffsplit-2016-5318: tiffsplit @@
3. thumbnail-2016-10095: thumbnail @@
4. thumbnail-2016-5318: thumbnail @@
5. tiffcmp-2016-10095:tiffcmp @@ @@
6. tiffcmp-2016-5318: tiffcmp @@ @@
7. cxxfilt-2016-4487: cxxfilt < @@
8. cxxfilt-2016-4489: cxxfilt < @@
9. cxxfilt-2016-4490: cxxfilt < @@
10. cxxfilt-2016-4491: cxxfilt < @@
11. cxxfilt-2016-4492: cxxfilt < @@
12. cxxfilt-2016-6131: cxxfilt < @@
13. objdump-2016-4487: objdump -t -C @@
14. objdump-2016-4489: objdump -t -C @@
15. objdump-2016-4490: objdump -t -C @@
16. objdump-2016-4491: objdump -t -C @@
17. objdump-2016-4492: objdump -t -C @@
18. objdump-2016-6131: objdump -t -C @@
19. nm-new-2016-4487: nm-new -C @@
20. nm-new-2016-4489: nm-new -C @@
21. nm-new-2016-4490: nm-new -C @@
22. nm-new-2016-4491: nm-new -C @@
23. nm-new-2016-4492: nm-new -C @@
24. nm-new-2016-6131: nm-new -C @@
25. addr2line-2016-4487: addr2line -e @@ -C -f 0x3dc8
26. addr2line-2016-4489: addr2line -e @@ -C -f 0x3dc8
27. addr2line-2016-4490: addr2line -e @@ -C -f 0x3dc8
28. addr2line-2016-4491: addr2line -e @@ -C -f 0x0000
29. addr2line-2016-4492: addr2line -e @@ -C -f 0x3dc8
30. addr2line-2016-6131: addr2line -e @@ -C -f 0x0000
31. strip-2017-7303: strip -o /dev/null @@
32. objcopy-2017-7303: objcopy @@
33. swftophp-2017-11733: swftophp @@
34. swftophp-2018-8807: swftophp @@
35. swftophp-2018-8962: swftophp @@
36. swftoperl-2017-11733: swftoperl @@
37. swftoperl-2018-8807: swftoperl @@
38. swftoperl-2018-8962: swftoperl @@
39. swftocxx-2017-11733: swftocxx @@
40. swftocxx-2018-8807: swftocxx @@
41. swftocxx-2018-8962: swftocxx @@
42. swftopython-2017-11733: swftopython @@
43. swftopython-2018-8807: swftopython @@
44. swftopython-2018-8962: swftopython @@
45. swftotcl-2017-11733: swftotcl @@
46. swftotcl-2018-8807: swftotcl @@
47. swftotcl-2018-8962: swftotcl @@
48. libav-2018-11102: avconv -y -i @@
49. ffmpeg-2018-11102: ffmpeg -y -i @@
50. libjpeg-turbo-2018-20330: tjbench @@ 90
51. mozjpeg-2018-20330: tjbench @@ 90
52. poppler-2017-18267: poppler @@
53. xpdf-2017-18267: xpdf @@

<br><br>

## 3. Reproduction of the Fuzzing process

### 3.1 Build 

#### 3.1.1 Build from docker

TransferFuzz is built on SelectFuzz. Since SelectFuzz's Docker image is relatively large, TransferFuzz is also large. For a more flexible build, you can also compile it yourself.

```bash
1 sudo docker pull anonymous4paper/transferfuzz
# You need to execute "echo core >/proc/sys/kernel/core_pattern" on the host to support AFL fuzzing.
```
#### 3.1.2 Build from source code （Not recommended）

Place the `/code` directory in the root (`/`) of the SelectFuzz environment and rename it to `/transferfuzz`.

You can ignore error messages when executing "make" commands in `/transferfuzz/llvm_mode`.

```bash
1 cd /transferfuzz
2 make clean all
3 cd llvm_mode
4 make clean all
```

<br>

### 3.2 Have a quick start

You can quickly verify the data in the paper with the following command.

#### 3.2.1 Start fuzzing

```bash
1 cd /transferfuzz/scripts/evaluation/
2 ./tiffcmp-2016-10095.sh
# When "Hamed: Finished PAG initialization..." is displayed, it may take some time (especially for a large project like binutils, which may take 10-20 minutes). This is the static analysis step of SelectFuzz, has nothing to do with the technology of this paper, and the time is acceptable.
```
#### 3.2.2 Check the crashes (Auto crash classification)
Many crashes will be generated during the fuzzing process. The *auto_verify.sh* script can be used to determine whether the expected POC is generated in the current crashes directory.

the string "poc" in  `<command>` will be replaced by POCs in `<crash_dir>`, which is similar to the "@@" used in AFL.

Usage:

```bash
1 cd /transferfuzz/scripts/verify
2 ./auto_verify.sh <binary_path> <command> <crash_dir> <crash_address>
3 cat ./result.txt
# Due to different project version, some vuls automatic verification may fail. You can read the crash_report.txt and check whether the verification is successful by function sequence.
```

Example:

```bash
1 cd /transferfuzz/scripts/verify
2 ./auto_verify.sh /transferfuzz/scripts/evaluation/tiffcmp-2016-10095/obj-dist/tools/tiffcmp "poc poc" /transferfuzz/scripts/evaluation/tiffcmp-2016-10095/obj-dist/out/crashes "tif_dir.c:1056"
3 cat ./result.txt
```

We use another binary *objdump* as an example too to demonstrate the usage:

```
1 ./auto_verify.sh /data/bin/binutils_2.26/objdump "-t -C poc" /result/objdump-2016-4487/crashes "cplus-dem.c:4319"
```

<br>

### 3.3 Full process

You can run the complete TransferFuzz with the following command. (e.g. Use tiffsplit as basic binary and tiffcmp as target binary)

#### 3.3.1 Function-level Trace Extraction

Automatically generate the `cve-2016-10095-functrace.txt` file.

Put the basic binary and poc into the directory `/data/bin/` and `/data/poc/` (The basic binary *tiffsplit* can be found at */bin* of github and the poc *tiffsplit-2016-10095-poc* can be found at */poc* or generated by Directed Fuzzing)

```bash
1 cd /transferfuzz/scripts/func_trace
2 ./get_trace.sh /data/bin/tiffsplit "poc" /data/poc ./result.txt
3 python3 ./deal_trace.py ./result.txt cve-2016-10095-functrace.txt
```

#### 3.3.2 Key-bytes Trace Extraction

Automatically generate the `cve-2016-10095-keybytes.txt` file.

Put the basic binary and poc into the directory `./bin/` and `./poc/` (The basic binary *tiffsplit* can be found at */bin* of github and the poc *tiffsplit-2016-10095-poc* can be found at */poc* or generated by Directed Fuzzing)

```bash
1 cd /transferfuzz/scripts/keybytes_trace
2 pin -t ./taint_test.so -i ./poc/tiffsplit-2016-10095-poc -v tiffcp -- ./bin/tiffsplit ./poc/tiffsplit-2016-10095-poc
3 python3 get_fuzz_dict.py ./taint_trace.out ./cve-2016-10095-keybytes.txt
```

#### 3.3.3 Trace Guided Fuzzing

put the `cve-2016-10095-functrace.txt` to `/transferfuzz/scripts/fuzz_functrace/` and  rename it to `cve-2016-10095.txt`.

put the `cve-2016-10095-keybytes.txt` to `/transferfuzz/scripts/fuzz_dict/` and  rename it to `cve-2016-10095.txt`.

```bash
1 cd /transferfuzz/scripts/evaluation
2 ./tiffcmp-2016-10095.sh
```

#### 3.3.4 Check the crashes (Auto crash classification)

```bash
1 cd /transferfuzz/scripts/verify
2 ./auto_verify.sh /transferfuzz/scripts/evaluation/tiffcmp-2016-10095/obj-dist/tools/tiffcmp "poc poc" /transferfuzz/scripts/evaluation/tiffcmp-2016-10095/obj-dist/out/crashes "tif_dir.c:1056"
3. cat ./result.txt
```

<br><br>

## 4. Verify a new vulnerability

- Prepare a basic binary and a target binary that reuses the code from the basic binary.
- Prepare a basic poc or generate poc by Directed Fuzzing.
- Run the **Function-level Trace Extraction** module and the **Key-bytes Trace Extraction** module to extract traces.
- Run **Trace Guided Fuzzing** for the target binary.
- Run the **Auto crash classification** to check vulnerability propagation.

<br><br>


## 5. Result Analysis

35 of the 38 new vuls in the paper were successful. In addition to the three unverified vulnerabilities presented in the paper, we also discovered two others (CVE-2022-34526 and CVE-2017-9147) that also could not be verified. 
We analyzed these bad cases to inform future research. The main reasons for the unverifiable vulnerabilities are as follows:

- Existing methods are prototypes and require additional engineering efforts, such as in-process instrumentation, to adapt to more software (For three unverified vulnerabilities presented in the paper).
- Some vulnerabilities are difficult to trigger by fuzzing, and there are no key bytes to bypass the conditional branch (For CVE-2022-34526 and CVE-2017-9147).


<br><br>

## 6. Migrate TransferFuzz to new fuzzing technology instead of SelectFuzz

We use macro definitions in `/code` to wrap all the code that needs to be modified.

We have successfully implemented TransferFuzz based on AFLGo, WindRanger and SelectFuzz. If you want to support more frameworks, please contact us.
