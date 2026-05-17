#ifndef HERMES_DEC_OPTIMIZER_H
#define HERMES_DEC_OPTIMIZER_H

#include <hbc/common.h>
#include <hbc/decompilation/token.h>

typedef enum {
	OPTIMIZER_NONE = 0,
	OPTIMIZER_CONSTANT_PROPAGATION = 1,
	OPTIMIZER_DEAD_CODE_ELIMINATION = 2,
	OPTIMIZER_EXPRESSION_INLINING = 4,
	OPTIMIZER_ALL = 7
} OptimizerFlags;

/* Constant value type */
typedef enum {
	CONST_TYPE_NONE,
	CONST_TYPE_NUMBER,
	CONST_TYPE_BOOL,
	CONST_TYPE_NULL,
	CONST_TYPE_UNDEFINED,
	CONST_TYPE_STRING
} ConstType;

typedef struct {
	ConstType type;
	union {
		double num_val;
		bool bool_val;
		const char *str_val;
	} val;
} ConstValue;

/* Token optimization pass - processes and transforms token sequences */
Result optimizer_run_constant_propagation(TokenString *ts);
Result optimizer_run_dead_code_elimination(TokenString *ts);
Result optimizer_run_expression_inlining(TokenString *ts);

/* Main optimizer entry point */
Result optimizer_run(TokenString *ts, OptimizerFlags flags);

#endif /* HERMES_DEC_OPTIMIZER_H */
