//===-- Analyzer.cc - the kernel-analysis framework--------------===//
//
// This file implements the analysis framework. It calls the pass for
// building call-graph and the pass for finding security checks.
//
// ===-----------------------------------------------------------===//

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Path.h"

#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>

#include "Analyzer.h"
#include "CallGraph.h"
#include "Config.h"
#include "SecurityChecks.h"
#include "MissingChecks.h"
#include "PointerAnalysis.h"
#include "TypeInitializer.h"

using namespace llvm;

// Command line parameters.
cl::list<string> InputFilenames(             
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));    // cl::OneOrMore：控制在程序的命令行上允许（或要求）指定选项的次数,至少1次
                                                                          // cl::Positional: 这是一个没有与之关联的命令行选项的位置参数
cl::opt<unsigned> VerboseLevel(
    "verbose-level", cl::desc("Print information at which verbose level"),   // cl::desc参数，说明该命令行选项的作用是什么; 如果是单独写一个程序，在main函数的开头写如下代码：
	                                                                     // cl::ParseCommandLineOptions(argc, argv,);则可以在执行testCM -help时将cl::desc对应的描述输出出来。
    cl::init(0));

cl::opt<bool> SecurityChecks(       // 调用时：程序名 -sc
    "sc", 
    cl::desc("Identify sanity checks"), 
    cl::NotHidden, cl::init(false));

cl::opt<bool> MissingChecks(
		"mc",
		cl::desc("Identify missing-check bugs"),
		cl::NotHidden, cl::init(false));    // cl::init()：设定初始值。cl::Optional表明该选项是可选的。


GlobalContext GlobalCtx;   // NumSecurityChecks, NumCondStatements的个数，等定义


void IterativeModulePass::run(ModuleList &modules) {

  ModuleList::iterator i, e;
  OP << "[" << ID << "] Initializing " << modules.size() << " modules ";
  bool again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      again |= doInitialization(i->first);
      OP << ".";
    }
  }
  OP << "\n";

  unsigned iter = 0, changed = 1;
  while (changed) {
    ++iter;
    changed = 0;
    unsigned counter_modules = 0;
    unsigned total_modules = modules.size();
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      OP << "[" << ID << " / " << iter << "] ";
      OP << "[" << ++counter_modules << " / " << total_modules << "] ";
      OP << "[" << i->second << "]\n";

      bool ret = doModulePass(i->first);
      if (ret) {
        ++changed;
        OP << "\t [CHANGED]\n";
      } else
        OP << "\n";
    }
    OP << "[" << ID << "] Updated in " << changed << " modules.\n";
  }

  OP << "[" << ID << "] Postprocessing ...\n";
  again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      // TODO: Dump the results.
      again |= doFinalization(i->first);
    }
  }

  OP << "[" << ID << "] Done!\n\n";
}

void LoadStaticData(GlobalContext *GCtx) {

	// Load error-handling functions
	SetErrorHandleFuncs(GCtx->ErrorHandleFuncs);
	// load functions that copy/move values
	SetCopyFuncs(GCtx->CopyFuncs);
	// load data-fetch functions
	SetDataFetchFuncs(GCtx->DataFetchFuncs);
}

void ProcessResults(GlobalContext *GCtx) {
}

void PrintResults(GlobalContext *GCtx) {

	OP<<"############## Result Statistics ##############\n";
	OP<<"# Number of sanity checks: \t\t\t"<<GCtx->NumSecurityChecks<<"\n";
	OP<<"# Number of conditional statements: \t\t"<<GCtx->NumCondStatements<<"\n";
}

int main(int argc, char **argv) {

	// Print a stack trace if we signal out.
	sys::PrintStackTraceOnErrorSignal(argv[0]);     // 打印异常栈轨迹Stack Trace; argv[0]是当前执行的exe文件名
	PrettyStackTraceProgram X(argc, argv);          // 发生崩溃时，此对象将指定的程序参数作为堆栈跟踪打印到流中

	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.

	cl::ParseCommandLineOptions(argc, argv, "global analysis\n");  // 命令行接口
	SMDiagnostic Err;      // 此类的实例封装一个诊断报告，允许作为插入记号诊断程序打印到raw_ostream

	// Loading modules
	OP << "Total " << InputFilenames.size() << " file(s)\n";

	for (unsigned i = 0; i < InputFilenames.size(); ++i) {

		LLVMContext *LLVMCtx = new LLVMContext();    // 实例化一个LLVMContext对象，以存放一次LLVM编译的从属数据，使得LLVM线程安全。
		unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);   // unique_ptr：智能指针，在适当时机自动释放堆内存空间
                                                            // 如果给定文件包含位码图像，请为其返回一个模块。否则，请尝试将其解析为 LLVM 程序集并为其返回模块。

		if (M == NULL) {
			OP << argv[0] << ": error loading file '"
				<< InputFilenames[i] << "'\n";
			continue;
		}

		Module *Module = M.release();          // 释放
		StringRef MName = StringRef(strdup(InputFilenames[i].data()));  // strdup:返回一个指针,指向为复制字符串分配的空间; StringRef:表示一个固定不变的字符串的引用（包括一个字符数组的指针和长度）
		GlobalCtx.Modules.push_back(make_pair(Module, MName));  // make_pair:拼接，类似dict; push_back:函数将一个新的元素加到最后面
		GlobalCtx.ModuleMaps[Module] = InputFilenames[i];  
	}

	// Main workflow
	LoadStaticData(&GlobalCtx);    // Load error-handling functions/load functions that copy/move values/load data-fetch functions
	
	// Initilaize gloable type map
	TypeInitializerPass TIPass(&GlobalCtx);
	TIPass.run(GlobalCtx.Modules);
	TIPass.BuildTypeStructMap();

	// Build global callgraph.   1、两层类分析+类型逃逸、循环展开、指针/别名分析
	CallGraphPass CGPass(&GlobalCtx);
	CGPass.run(GlobalCtx.Modules);

	// Identify sanity checks    2
	if (SecurityChecks) {
		SecurityChecksPass SCPass(&GlobalCtx);
		SCPass.run(GlobalCtx.Modules);
	}

	// Identify missing-check bugs  3
	if (MissingChecks) {
		// Pointer analysis
		PointerAnalysisPass PAPass(&GlobalCtx);
		PAPass.run(GlobalCtx.Modules);

		SecurityChecksPass SCPass(&GlobalCtx);
		SCPass.run(GlobalCtx.Modules);

		MissingChecksPass MCPass(&GlobalCtx);
		MCPass.run(GlobalCtx.Modules);
		MCPass.processResults();
	}

	// Print final results
	//PrintResults(&GlobalCtx);

	return 0;
}

