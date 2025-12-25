#ifndef HERMES_DEC_DECOMPILER_H
#define HERMES_DEC_DECOMPILER_H

#include <hbc/common.h>
#include <hbc/parser.h>
#include <hbc/bytecode.h>
#include <hbc/hbc.h>
#include <hbc/decompilation/token.h>

/* Forward declaration */
struct Environment;
typedef struct Environment Environment;

/* Forward declaration */
struct DecompiledFunctionBody;
typedef struct DecompiledFunctionBody DecompiledFunctionBody;

/* Basic block for control flow */
typedef struct BasicBlock {
	u32 start_address;
	u32 end_address;
	bool may_be_cycling_anchor;
	bool may_be_cycling_target;
	bool is_unconditional_throw_anchor;
	bool is_unconditional_return_end;
	bool is_unconditional_jump_anchor;
	bool is_yield_action_anchor;
	bool is_conditional_jump_anchor;
	bool is_switch_action_anchor;
	ParsedInstruction *anchor_instruction;
	u32 *jump_targets_for_anchor;
	u32 jump_targets_count;
	bool stay_visible;

	/* Control flow graph */
	struct BasicBlock **child_nodes;
	u32 child_nodes_count;
	u32 child_nodes_capacity;
	struct BasicBlock **parent_nodes;
	u32 parent_nodes_count;
	u32 parent_nodes_capacity;
	struct BasicBlock **error_handling_child_nodes;
	u32 error_handling_child_nodes_count;
	u32 error_handling_child_nodes_capacity;
	struct BasicBlock **error_handling_parent_nodes;
	u32 error_handling_parent_nodes_count;
	u32 error_handling_parent_nodes_capacity;
} BasicBlock;

/* Environment for closure variable handling */
struct Environment {
	Environment *parent_environment;
	int nesting_quantity;
	char **slot_index_to_varname;
	int var_count;
	int slot_capacity;
};

/* Address to strings mapping */
typedef struct {
	u32 address;
	char **labels;
	u32 label_count;
} AddressLabels;

/* Decompiled code nesting frame (e.g. for..in loop body scope) */
typedef struct {
	u32 start_address;
	u32 end_address;
} NestedFrame;

/* Function body decompilation state */
struct DecompiledFunctionBody {
	bool is_global;
	char *function_name;
	u32 function_id;
	FunctionHeader *function_object;
	ExceptionHandlerInfo *exc_handlers;
	u32 exc_handlers_count;

	/* Control flow data */
	AddressLabels *try_starts; /* Map from address to list of strings */
	u32 try_starts_count;
	AddressLabels *try_ends; /* Map from address to list of strings */
	u32 try_ends_count;
	AddressLabels *catch_targets; /* Map from address to list of strings */
	u32 catch_targets_count;

	ParsedInstruction **jump_anchors; /* Map from address to instruction */
	u32 jump_anchors_count;
	ParsedInstruction **ret_anchors; /* Map from address to instruction */
	u32 ret_anchors_count;
	ParsedInstruction **throw_anchors; /* Map from address to instruction */
	u32 throw_anchors_count;

	u32 *jump_targets; /* Set of addresses */
	u32 jump_targets_count;
	u32 jump_targets_capacity;

	/* Function flags */
	bool is_closure;
	bool is_async;
	bool is_generator;

	/* Closure variable naming */
	Environment *parent_environment;
	int environment_id;
	Environment **local_items; /* Map from env_register to Environment */
	u32 local_items_count;
	u32 local_items_capacity;
	Environment **owned_environments; /* Environments allocated for this function */
	u32 owned_environments_count;
	u32 owned_environments_capacity;

	/* Control flow structures */
	BasicBlock *basic_blocks;
	u32 basic_blocks_count;
	u32 basic_blocks_capacity;

	/* Decompiled-code nesting frames */
	NestedFrame *nested_frames;
	u32 nested_frames_count;
	u32 nested_frames_capacity;

	/* Generated code */
	TokenString *statements;
	u32 statements_count;
	u32 statements_capacity;

	/* Parsed instructions */
	ParsedInstructionList instructions;
};

/* Main decompiler state */
typedef struct HermesDecompiler {
	char *input_file;
	char *output_file;
	HBCReader *hbc_reader;
	HBC *hbc; /* Use HBC provider instead of direct file I/O */
	u32 *calldirect_function_ids;
	u32 calldirect_function_ids_count;
	u32 calldirect_function_ids_capacity;
	bool *decompiled_functions; /* Track which functions have been decompiled */
	int indent_level;
	bool inlining_function; /* True when outputting a nested function inline */
	HBCDecompOptions options;
	StringBuffer output;
} HermesDecompiler;

/* Function declarations */
Result _hbc_decompiler_init(HermesDecompiler *decompiler);
Result _hbc_decompiler_init_with_provider(HermesDecompiler *decompiler, HBC *hbc);
Result _hbc_decompiler_cleanup(HermesDecompiler *decompiler);
/* High-level entry points */
Result _hbc_decompile_file(const char *input_file, const char *output_file);
/* Buffer-based APIs used by hermesdec library */
Result _hbc_decompile_all_to_buffer(HBCReader *reader, HBCDecompOptions options, StringBuffer *out);
Result _hbc_decompile_all_with_provider(HBC *hbc, HBCDecompOptions options, StringBuffer *out);
Result _hbc_decompile_function_to_buffer(HBCReader *reader, u32 function_id, HBCDecompOptions options, StringBuffer *out);
Result _hbc_decompile_function_with_provider(HBC *hbc, u32 function_id, HBCDecompOptions options, StringBuffer *out);
Result _hbc_decompile_function(HermesDecompiler *state, u32 function_id, Environment *parent_environment, int environment_id, bool is_closure, bool is_generator, bool is_async);

/* Transformation passes */
Result _hbc_pass1_set_metadata(HermesDecompiler *state, DecompiledFunctionBody *function_body);
Result _hbc_pass2_transform_code(HermesDecompiler *state, DecompiledFunctionBody *function_body);
Result _hbc_pass3_parse_forin_loops(HermesDecompiler *state, DecompiledFunctionBody *function_body);
Result _hbc_pass4_name_closure_vars(HermesDecompiler *state, DecompiledFunctionBody *function_body);
Result _hbc_output_code(HermesDecompiler *state, DecompiledFunctionBody *function_body);

/* Helper functions */
Result _hbc_function_body_init(DecompiledFunctionBody *body, u32 function_id, FunctionHeader *function_object, bool is_global);
void _hbc_function_body_cleanup(DecompiledFunctionBody *body);
Result _hbc_add_jump_target(DecompiledFunctionBody *body, u32 address);
Result _hbc_create_basic_block(DecompiledFunctionBody *body, u32 start_address, u32 end_address);

/* Internal: build CFG and anchors for a function */
Result _hbc_build_control_flow_graph(HBCReader *reader, u32 function_id, ParsedInstructionList *list, DecompiledFunctionBody *out_body);

#endif /* HERMES_DEC_DECOMPILER_H */
