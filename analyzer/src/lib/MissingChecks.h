#ifndef MISSING_CHECKS_H
#define MISSING_CHECKS_H

#include "Analyzer.h"
#include "DataFlowAnalysis.h"
#include "SecurityChecks.h"
#include "Common.h"


//
// Modeling security checks
//
// Operators in a security check
enum SCOperator {
	ICMP_OTHER,
	ICMP_EQ,
	ICMP_NE,
	ICMP_GT, // including ICMP_GE
	ICMP_LT, // including ICMP_LE
};

// Modeled conditions in a security check
enum SCCondition {
	SCC_OTHER,
	SCC_NULL,
	SCC_ZERO,
	SCC_POS,
	SCC_NEG,
	SCC_CONST,
	SCC_VAR,
};

// The security check model
struct ModelSC {
	SCOperator SCO;
	SCCondition SCC;
	Value *SrcUse;
	int8_t ArgNo;
	friend bool operator< (const ModelSC &MSC1, 
			const ModelSC &MSC2) {
		return (MSC1.SrcUse < MSC2.SrcUse);
	}
};

class MissingChecksPass : public IterativeModulePass {

	public:

		static int AnalysisStage;
		static map<src_t, unsigned>SrcCheckCount;
		static map<use_t, unsigned>UseCheckCount;
		static map<src_t, unsigned>SrcUncheckCount;
		static map<use_t, unsigned>UseUncheckCount;
		static map<use_t, unsigned>SrcTotalCount;
		static map<use_t, unsigned>UseTotalCount;
		// Sources with security checks
		static set<src_t>CheckedSrcSet;
		static set<use_t>CheckedUseSet;
		// Maps of checks to src/use 
		static map<src_t, set<ModelSC>>SrcChecksMap;
		static map<use_t, set<ModelSC>>UseChecksMap;
		// Maps of unchecks to src/use
		static map<src_t, set<Value *>>SrcUnchecksMap;
		static map<use_t, set<Value *>>UseUnchecksMap;
		// Analyzed sources
		static set<Value *>TrackedSrcSet;
		static set<Value *>TrackedUseSet;

		MissingChecksPass(GlobalContext *Ctx_)
			: IterativeModulePass(Ctx_, "MissingChecks"), 
			DFA(Ctx_) {
				MIdx = 0;
			}
		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

		// Process final results
		void processResults();

	private:

		DataFlowAnalysis DFA;   //找到所有的源，但这里源的常量+errcode好像没对应，param也没有，SrcSet；UseSet差不多和论文内容写的相符。由SourceSet，找到CVset，跟踪 
		int MIdx;
		set<Instruction *>CheckSet;
                // 别名
		void collectAliasPointers(Function *, LoadInst*, set <Value *> &);

		void evaluateCheckInstruction(Value *, set<Value *> &);
                // // 跟踪给定关键变量的来源和来源相同的关键变量。CVset
		void findSourceCV(Value *, set <Value *>&, set <Value *>&);
		void findInFuncSourceCV(Value *V, set <Value *>&SourceSet, set <Value *>&);
		void identifyCheckedTargets(Function *, Value *,
				set<Value *> &);
		void identifyIndirectTargets(Function *, Value *,
				set<Value *> &);

	        // 
		void findClosestBranch (Value *Src, Value *SC, set<Value *> &BrSet);  // 找到相近的分支，return instruction、branch instruction
		void findParallelPaths(set<Value *> &BrSet, set<Path> &PPathSet);   //没有被定义

		void isCheckedForward(Function *F, src_t Src,
				Value *V, set<BasicBlock *> &Scope, set<Value *> &VSet, 
				bool &isChecked, unsigned &Depth, bool enableAlias=true);

		void isCheckedBackward(Function *F, use_t Use,
				Value *V, set<BasicBlock *> &Scope, set<Value *> &VSet, 
				bool &isChecked, unsigned &Depth);

		void countSrcUseChecks(Function *F, Instruction *SCI);  // 确定每次安全检查中使用的关键变量/函数。
		void countSrcUseUnchecks(Function *F);

		ModelSC modelCheck(CmpInst *CmpI, Value *SrcUse, int8_t ArgNo);
		void addSrcCheck(src_t Src, ModelSC MSC);
		void addUseCheck(use_t Use, ModelSC MSC);
		void addSrcUncheck(src_t Src, Value *V);
		void addUseUncheck(use_t Use, Value *V);
		bool inModeledCheckSet(CmpInst *CmpI, Value *SrcUse, 
				int8_t ArgNo, bool IsSrc);
};

#endif
