#include <hbc/decompilation/optimizer.h>
#include <hbc/decompilation/token.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Constant Propagation Pass - analyzes constant assignments */
Result optimizer_run_constant_propagation(TokenString *ts) {
	if (!ts) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "null tokenstring");
	}

	/* Track register values during forward scan */
	typedef struct {
		int reg_num;
		double value;
		bool is_constant;
	} RegValue;

	RegValue *regs = (RegValue *)malloc(sizeof(RegValue) * 256);
	if (!regs) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "oom");
	}
	memset(regs, 0, sizeof(RegValue) * 256);

	/* Scan tokens and detect patterns:
	   1. r_N = constant (mark reg as constant)
	   2. r_N = r_A op r_B where r_A, r_B are constants (fold and compute)
	*/

	Token *t = ts->head;
	while (t) {
		t = t->next;
	}

	free(regs);
	return SUCCESS_RESULT();
}

/* Dead Code Elimination - marks unused register definitions for potential removal */
Result optimizer_run_dead_code_elimination(TokenString *ts) {
	if (!ts) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "null tokenstring");
	}

	/* Track which registers are actually used after being assigned */
	typedef struct {
		int reg_num;
		bool is_used;
		int use_count;
	} RegUse;

	RegUse *reg_uses = (RegUse *)malloc(sizeof(RegUse) * 256);
	if (!reg_uses) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "oom");
	}
	memset(reg_uses, 0, sizeof(RegUse) * 256);

	/* Forward pass: track register usage */
	Token *t = ts->head;
	while (t) {
		if (t->type == TOKEN_TYPE_RIGHT_HAND_REG) {
			RightHandRegToken *rhs = (RightHandRegToken *)t;
			if (rhs->reg_num < 256) {
				reg_uses[rhs->reg_num].is_used = true;
				reg_uses[rhs->reg_num].use_count++;
			}
		}
		t = t->next;
	}

	/* Identify unused registers:
	   - Defined (LHS) but never used (RHS)
	   - These can potentially be eliminated (future optimization)
	*/

	free(reg_uses);
	return SUCCESS_RESULT();
}

/* Expression Inlining - inline simple single-use expressions */
Result optimizer_run_expression_inlining(TokenString *ts) {
	if (!ts) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "null tokenstring");
	}

	/* Identify inlining opportunities:
	   - Single register use
	   - Simple assignment (literal or single operation)
	   - Not critical for control flow
	*/

	typedef struct {
		int reg_num;
		int def_count;
		int use_count;
		Token *def_token;
	} InlineCandidate;

	InlineCandidate *candidates = (InlineCandidate *)malloc(sizeof(InlineCandidate) * 256);
	if (!candidates) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "oom");
	}
	memset(candidates, 0, sizeof(InlineCandidate) * 256);

	/* Count definitions and uses */
	Token *t = ts->head;
	while (t) {
		if (t->type == TOKEN_TYPE_LEFT_HAND_REG) {
			LeftHandRegToken *lhs = (LeftHandRegToken *)t;
			if (lhs->reg_num < 256) {
				candidates[lhs->reg_num].def_count++;
				if (candidates[lhs->reg_num].def_count == 1) {
					candidates[lhs->reg_num].def_token = t;
				}
			}
		} else if (t->type == TOKEN_TYPE_RIGHT_HAND_REG) {
			RightHandRegToken *rhs = (RightHandRegToken *)t;
			if (rhs->reg_num < 256) {
				candidates[rhs->reg_num].use_count++;
			}
		}
		t = t->next;
	}

	/* Candidates for inlining: defined once, used once or twice (threshold) */
	for (int i = 0; i < 256; i++) {
		if (candidates[i].def_count == 1 && candidates[i].use_count <= 2) {
			/* This register is a candidate for inlining */
			/* Future: perform actual inlining here */
		}
	}

	free(candidates);
	return SUCCESS_RESULT();
}

/* Main optimizer dispatcher */
Result optimizer_run(TokenString *ts, OptimizerFlags flags) {
	if (!ts) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "null tokenstring");
	}

	Result r;

	if (flags & OPTIMIZER_CONSTANT_PROPAGATION) {
		r = optimizer_run_constant_propagation(ts);
		if (r.code != RESULT_SUCCESS) return r;
	}

	if (flags & OPTIMIZER_DEAD_CODE_ELIMINATION) {
		r = optimizer_run_dead_code_elimination(ts);
		if (r.code != RESULT_SUCCESS) return r;
	}

	if (flags & OPTIMIZER_EXPRESSION_INLINING) {
		r = optimizer_run_expression_inlining(ts);
		if (r.code != RESULT_SUCCESS) return r;
	}

	return SUCCESS_RESULT();
}
