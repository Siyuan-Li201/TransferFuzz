/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#define USE_TRANSFERFUZZ

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <set>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

#ifdef USE_TRANSFERFUZZ
#include <thread>  // 包含用于sleep的头文件
#include <chrono>  // 包含时间相关的头文件
#endif

using namespace llvm;

#ifdef USE_TRANSFERFUZZ
cl::opt<std::string> TargetBlockFile(
    "target_block",
    cl::desc("target trace blocks."),
    cl::value_desc("filename")
);

cl::opt<std::string> FuncTraceFile(
    "func_trace",
    cl::desc("function call sequence."),
    cl::value_desc("functrace")
);
#endif

cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

static std::string LLVMInstructionAsString(Instruction * I) {
  std::string instString;
  raw_string_ostream N(instString);
  I -> print(N);
  return N.str();
}


namespace llvm {

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} // namespace llvm

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

char AFLCoverage::ID = 0;

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

#ifdef USE_TRANSFERFUZZ
bool parse_bb_name(const std::string& bb_name, std::string& file_name, int& line_number) {
    size_t pos = bb_name.find(':');
    if (pos == std::string::npos) {
        return false; // Invalid format
    }
    file_name = bb_name.substr(0, pos);
    line_number = std::stoi(bb_name.substr(pos + 1));
    return true;
}

// Function to find the closest matching basic block
std::string find_closest_bb(const std::vector<std::string>& basic_blocks, const std::string& bb_name) {
    std::string target_file;
    int target_line;
    if (!parse_bb_name(bb_name, target_file, target_line)) {
        std::cerr << "Invalid bb_name format: " << bb_name << std::endl;
        return "";
    }

    std::string closest_bb;
    int closest_line = -1;

    for (const auto& bb : basic_blocks) {
        std::string file_name;
        int line_number;
        if (!parse_bb_name(bb, file_name, line_number)) {
            continue; // Invalid format, skip this entry
        }

        if (bb == bb_name) {
            return bb; // Exact match found
        }

        if (file_name == target_file && line_number < target_line) {
            if (closest_line == -1 || line_number > closest_line) {
                closest_bb = bb;
                closest_line = line_number;
            }
        }
    }

    return closest_bb;
}
#endif


#ifdef USE_TRANSFERFUZZ
void findAndLogSourceInfo(Function *F, const std::string &functionName, std::string &sourceInfo, std::ofstream &blockOutfile) {
    if (!F->empty()) {
        for (auto &BB : *F) {
            for (auto &I : BB) {
                if (DILocation *loc = I.getDebugLoc()) {
                    std::string filename = loc->getFilename().str();
                    size_t pos = filename.find_last_of("/\\");
                    if (pos != std::string::npos) {
                        filename = filename.substr(pos + 1);
                    }
                    sourceInfo = filename + ":" + std::to_string(loc->getLine());
                    blockOutfile << functionName << "|" << sourceInfo << "\n";
                    return;
                }
            }
        }
    }
}
#endif


bool AFLCoverage::runOnModule(Module &M) {

  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;
  float min_distance = 99999;

  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return false;
  }


  std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::vector<std::string> basic_blocks;
  std::set<std::string> keep;
  std::ofstream debug( "/aflgo/debug.txt", std::ofstream::out | std::ofstream::app);
  // std::ofstream debugOutfile("/aflgo/debug_output.txt", std::ofstream::out | std::ofstream::app);  // 用于保存调试信息

#ifdef USE_TRANSFERFUZZ
  std::vector<std::string> basic_blocks_transfer;
  std::ofstream tbnames(OutDirectory + "/target_blocks.txt", std::ofstream::out | std::ofstream::app);
#endif

  if (!TargetsFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line))
      targets.push_back(line);
    targetsfile.close();

    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty()) {

    std::ifstream cf(DistanceFile);

    std::string DdgFile = DistanceFile;
    DdgFile = DdgFile.substr(0, DdgFile.length()-16);
    DdgFile.append("ctrl-data.dot");

    std::ifstream ddgf(DdgFile);

    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        int bb_dis = (int) (atof(line.substr(pos + 1, line.length()).c_str()));

        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);

      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }


    //debug << "keep: "<< DdgFile << "\n";
    if (ddgf.is_open()) {
      //debug << "keep1: "<< DdgFile << "\n";
      std::string line;
      while (getline(ddgf, line)) { 
        std::string bb_name = line.substr(0, line.length());
        //debug << "keep: "<< bb_name << "\n";
        keep.insert(bb_name);
        
      }
      ddgf.close();
      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DdgFile.c_str());
      return false;
    }

#ifdef USE_TRANSFERFUZZ
    if (!TargetBlockFile.empty()){
      printf("\n\nget target blocks!!\n\n");

      std::ifstream cf(TargetBlockFile);
      if (cf.is_open()) {

        std::string line;
        while (getline(cf, line)) {

          // std::string bb_name = line;//.find(",");
          std::string bb_name = find_closest_bb(basic_blocks, line); //not let bb_name = line, because bb_name maybe not the first line of sourcecode in the block.
          basic_blocks_transfer.push_back(bb_name);

        }
        cf.close();

        // is_aflgo = true;

      } else {
        FATAL("Unable to find %s.", TargetBlockFile.c_str());
        return false;
      }
    }
    
#endif

  }



  //for(auto i: keep) {
  //   debug << "keep: "<< i << "\n"; 
  //}

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Default: Not selective */
  char* is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

  }

  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {

    std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream iicalls(OutDirectory + "/IIcalls.txt", std::ofstream::out | std::ofstream::app);
#ifdef USE_TRANSFERFUZZ
    // std::ofstream blockOutfile(OutDirectory + "/Transfer_blocks.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream edgeOutfile(OutDirectory + "/edges_id.txt", std::ofstream::out | std::ofstream::app);
    // std::ofstream blockOutfile("target_block.txt", std::ofstream::out | std::ofstream::app);
    // std::ofstream edgeOutfile("target_edge.txt", std::ofstream::out | std::ofstream::app);
    std::string line;
#endif

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

#ifdef USE_TRANSFERFUZZ

    bool found_cplus = true;
    // for (DICompileUnit *CU : M.debug_compile_units()) {
    //   StringRef FileName = CU->getFilename();
    //   if (FileName.endswith("cplus-dem.c")) {
    //     found_cplus = true;
    //     // 当前编译的文件名是cplus-dem.c，执行特定操作
    //     // llvm::errs() << "Processing file: " << FileName << "\n";
    //     // debugOutfile << "Processing file: " << FileName.str() << "\n";
    //     // 在这里添加你的分析逻辑
    //     break;
    //   }
    // }

    if (found_cplus) {
      std::ifstream infile(FuncTraceFile);

      while (std::getline(infile, line)) {
        std::vector<std::string> functionSequence;
        std::stringstream ss(line);
        std::string funcName;
        std::vector<std::string> edgeInfo;

        // 读取函数调用序列
        while (std::getline(ss, funcName, ',')) {
          functionSequence.push_back(funcName);
        }

        // 打印并保存调试信息
        // std::string debugInfo = "Parsed function sequence: ";
        // for (const auto &fn : functionSequence) {
        //   debugInfo += fn + " ";
        // }
        // debugInfo += "\n";
        // errs() << debugInfo;
        // debugOutfile << debugInfo;

        for (size_t i = 0; i < functionSequence.size(); ++i) {
          const auto &functionName = functionSequence[i];
          Function *F = M.getFunction(functionName);
          if (!F) continue;
          // if (!F) {
          //   std::string notFoundInfo = "Function not found: " + functionName + "\n";
            // errs() << notFoundInfo;
            // debugOutfile << notFoundInfo;
            // continue;
          // }

          // 获取函数起始指令的调试信息
          std::string startSourceInfo;
          findAndLogSourceInfo(F, functionName, startSourceInfo, edgeOutfile);
          // if (!F->empty()) {
          //   bool found_source_id = false;
          //   // 遍历函数中的所有指令，直到找到带有调试信息的指令
          //   for (auto &BB : *F) {
          //       for (auto &I : BB) {
          //           if (DILocation *loc = I.getDebugLoc()) {
          //               std::string filename = loc->getFilename().str();
          //               size_t pos = filename.find_last_of("/\\");
          //               if (pos != std::string::npos) {
          //                   filename = filename.substr(pos + 1);
          //               }
          //               startSourceInfo = filename + ":" + std::to_string(loc->getLine());
          //               blockOutfile << startSourceInfo << "\n";
          //               std::string startInfo = "Start source info for function " + functionName + ": " + startSourceInfo + "\n";
          //               errs() << startInfo;
          //               debugOutfile << startInfo;
          //               found_source_id = true;
          //               // 找到调试信息后立即中断遍历
          //               break;
          //           }
          //       }
          //       if (found_source_id)
          //         break;
          //   }
          // }
          
          // 遍历函数的基本块和指令以查找调用指令
          if (i < functionSequence.size() - 1) { // 获取当前函数调用下一个函数的调用指令信息
              const auto &nextFunctionName = functionSequence[i + 1];
              for (BasicBlock &BB : *F) {
                  for (Instruction &I : BB) {
                      if (auto *callInst = dyn_cast<CallInst>(&I)) {
                          if (Function *calledFunc = callInst->getCalledFunction()) {
                              if (calledFunc->getName() == nextFunctionName) {
                                  if (DILocation *loc = callInst->getDebugLoc()) {
                                      std::string filename = loc->getFilename().str();
                                      size_t pos = filename.find_last_of("/\\");
                                      if (pos != std::string::npos) {
                                          filename = filename.substr(pos + 1);
                                      }
                                      std::string callSourceInfo = filename + ":" + std::to_string(loc->getLine());
                                      // std::string callInfo = "Call source info from " + functionName + " to " + nextFunctionName + ": " + callSourceInfo + "\n";
                                      // errs() << callInfo;
                                      // debugOutfile << callInfo;
                                      // 如果找到了调用指令信息和函数起始指令信息
                                      if (!callSourceInfo.empty() && !startSourceInfo.empty()) {
                                          edgeInfo.push_back(functionName + "," + nextFunctionName + "|" + callSourceInfo);
                                      }
                                  }
                              }
                          }
                      }
                  }
              }
          }


          // std::string callSourceInfo;
          // if (i > 0) { // 从第二个函数开始，获取前一个函数的调用指令信息
          //   const auto &prevFunctionName = functionSequence[i - 1];
          //   Function *prevF = M.getFunction(prevFunctionName);
          //   if (prevF) {
          //     for (BasicBlock &BB : *prevF) {
          //       for (Instruction &I : BB) {
          //         if (auto *callInst = dyn_cast<CallInst>(&I)) {
          //           if (Function *calledFunc = callInst->getCalledFunction()) {
          //             if (calledFunc->getName() == functionName) {
          //               if (DILocation *loc = callInst->getDebugLoc()) {
          //                 std::string filename = loc->getFilename().str();
          //                 size_t pos = filename.find_last_of("/\\");
          //                 if (pos != std::string::npos) {
          //                     filename = filename.substr(pos + 1);
          //                 }
          //                 callSourceInfo = filename + ":" + std::to_string(loc->getLine());
          //                 std::string callInfo = "Call source info from " + prevFunctionName + " to " + functionName + ": " + callSourceInfo + "\n";
          //                 errs() << callInfo;
          //                 debugOutfile << callInfo;
          //                 // 如果找到了调用指令信息和函数起始指令信息
          //                 if (!callSourceInfo.empty() && !startSourceInfo.empty()) {
          //                   edgeInfo.push_back(callSourceInfo + "," + startSourceInfo);
          //                 }
          //               }
          //             }
          //           }
          //         }
          //       }
          //     }
          //   }
          // }   
        }

        // 输出 edge 信息
        if (edgeInfo.size() > 0){
          for (size_t i = 0; i < edgeInfo.size(); ++i) {
            edgeOutfile << edgeInfo[i];
            if (i != edgeInfo.size() - 1) {
              edgeOutfile << "\n";
            }
          }
          edgeOutfile << "\n";
        }
        
      }
    }
#endif

    for (auto &F : M) {

      //debug << "module: " << &M << "\n";
      //debug << "module: " << M.getSourceFileName() << "\n";

      bool has_BBs = false;
      std::string funcName = F.getName();

      /* Black list of function names */
      if (isBlacklisted(&F)) {
        continue;
      }

      bool is_target = false;
      for (auto &BB : F) {

        std::string bb_name("");
        std::string filename;
        unsigned line;

        for (auto &I : BB) {
          getDebugLoc(&I, filename, line);
	  
          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;
	  
          
          if (bb_name.empty()) {

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
          }

          if (!is_target) {
              for (auto &target : targets) {
                std::size_t found = target.find_last_of("/\\");
                if (found != std::string::npos)
                  target = target.substr(found + 1);

                std::size_t pos = target.find_last_of(":");
                std::string target_file = target.substr(0, pos);
                unsigned int target_line = atoi(target.substr(pos + 1).c_str());

                if (!target_file.compare(filename) && target_line == line)
                  is_target = true;
		  
              }
            }

            if (auto *c = dyn_cast<CallInst>(&I)) {

              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos)
                filename = filename.substr(found + 1);

              if (auto *CalledF = c->getCalledFunction()) {
                if (!isBlacklisted(CalledF))
                  bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
                  if (CalledF->getName().str()!="llvm.dbg.declare" && CalledF->getName().str()!="llvm.dbg.value" )
		  iicalls << filename + "," + std::to_string(line) << " " << CalledF->getName().str() << "\n";
              }
            }
        }

        if (!bb_name.empty()) {

          BB.setName(bb_name + ":");
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            BB.setValueName(ValueName::Create(NameRef));
          }

          bbnames << BB.getName().str() << "\n";
          has_BBs = true;

#ifdef AFLGO_TRACING
          auto *TI = BB.getTerminator();
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
          Builder.CreateCall(instrumented, {bbnameVal});
#endif

        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true);
        }

        if (is_target)
          ftargets << F.getName().str() << "\n";
        fnames << F.getName().str() << "\n";
      }
    }

  } else {
    /* Distance instrumentation */

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
    
    for (auto &F : M) {

      int distance = -1;
      static const std::string Xlibs("/usr/");

      for (auto &BB : F) {

        distance = -1;
        bool flag = true;

#ifdef USE_TRANSFERFUZZ
        bool is_target_block = false;
        std::string tb_name("");
#endif
        if (true) {
          std::string bb_name("");
          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
            debug << "debug: " << bb_name << "\n";

#ifdef USE_TRANSFERFUZZ
            if (!bb_name.empty()) {
              if (!(find(basic_blocks_transfer.begin(), basic_blocks_transfer.end(), bb_name) == basic_blocks_transfer.end())) {

                is_target_block = true;
                tb_name = bb_name;
                break;
              }
            }
#endif

            break;
          }

          //find irrelevant bbs
          if(!bb_name.empty()) {
            //irrelevent
            if(keep.count(bb_name)==0) {
              flag=false;
            }
            else{
              //debug << "skip: " << bb_name << "\n";
            }
          }

          if (!bb_name.empty() && is_aflgo) {

            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) {

              if (is_selective)
                continue;

            } else {

              /* Find distance for BB */

              if (AFL_R(100) < dinst_ratio) {
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second;

              }
            }
          }

        }


        if(flag==false){
          continue;
        }

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

#ifdef USE_TRANSFERFUZZ
        if (is_target_block == true) {
          tbnames << tb_name << "," << cur_loc << "\n";
        }
#endif

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (distance >= 0) {


          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance);
          ConstantInt *Zero =
              ConstantInt::get(LargestType, (unsigned) 0);


          /* Add distance to shm[MAPSIZE] */

          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          //Value *PreDis = IRB.CreateAdd(MapDist, Zero);
          Value *Sub = IRB.CreateSub(Distance, MapDist);
          ConstantInt *Bits = ConstantInt::get(LargestType, 63);
          Value *Lshr = IRB.CreateLShr(Sub, Bits);
          Value *Mul1 = IRB.CreateMul(Lshr, Distance);
          Value *Sub1 = IRB.CreateSub(One, Lshr);
          Value *Mul2 = IRB.CreateMul(Sub1, MapDist);
          Value *Incr = IRB.CreateAdd(Mul1, Mul2);

          IRB.CreateStore(Incr, MapDistPtr)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8)] */

          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        inst_blocks++;

      }
    }
  }

  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN")
             ? "hardened"
             : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
               ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio, dinst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);

