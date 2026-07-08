/* radare2 - BSD - Copyright 2025-2026 - pancake */

#ifndef LIBHBC_TOKEN_H
#define LIBHBC_TOKEN_H

#include <hbc/common.h>
#include <hbc/bytecode.h>

/* Forward declarations */
struct HermesDecompiler;
struct Environment;

/* HbcToken types */
typedef enum {
	HBC_TOKEN_TYPE_RAW,
	HBC_TOKEN_TYPE_LEFT_HAND_REG,
	HBC_TOKEN_TYPE_RIGHT_HAND_REG,
	HBC_TOKEN_TYPE_ASSIGNMENT,
	HBC_TOKEN_TYPE_LEFT_PARENTHESIS,
	HBC_TOKEN_TYPE_RIGHT_PARENTHESIS,
	HBC_TOKEN_TYPE_DOT_ACCESSOR,
	HBC_TOKEN_TYPE_BIND,
	HBC_TOKEN_TYPE_RETURN_DIRECTIVE,
	HBC_TOKEN_TYPE_THROW_DIRECTIVE,
	HBC_TOKEN_TYPE_FUNCTION_TABLE_INDEX,
	HBC_TOKEN_TYPE_JUMP_CONDITION,
	HBC_TOKEN_TYPE_JUMP_NOT_CONDITION,
	HBC_TOKEN_TYPE_GET_ENVIRONMENT,
	HBC_TOKEN_TYPE_LOAD_FROM_ENVIRONMENT,
	HBC_TOKEN_TYPE_NEW_ENVIRONMENT,
	HBC_TOKEN_TYPE_NEW_INNER_ENVIRONMENT,
	HBC_TOKEN_TYPE_SWITCH_IMM,
	HBC_TOKEN_TYPE_STORE_TO_ENVIRONMENT,
	HBC_TOKEN_TYPE_FOR_IN_LOOP_INIT,
	HBC_TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER,
	HBC_TOKEN_TYPE_RESUME_GENERATOR,
	HBC_TOKEN_TYPE_SAVE_GENERATOR,
	HBC_TOKEN_TYPE_START_GENERATOR,
	HBC_TOKEN_TYPE_CATCH_BLOCK_START
} HbcTokenType;

/* Base token structure */
typedef struct HbcToken {
	HbcTokenType type;
	struct HbcToken *next;
} HbcToken;

/* Raw token with string content */
typedef struct {
	HbcToken base;
	char *text;
} HbcRawToken;

/* Register token (left-hand side) */
typedef struct {
	HbcToken base;
	int reg_num;
} HbcLeftHandRegToken;

/* Register token (right-hand side) */
typedef struct {
	HbcToken base;
	int reg_num;
} HbcRightHandRegToken;

/* Assignment token (=) */
typedef struct {
	HbcToken base;
} HbcAssignmentToken;

/* Parenthesis tokens */
typedef struct {
	HbcToken base;
} HbcLeftParenthesisToken;

typedef struct {
	HbcToken base;
} HbcRightParenthesisToken;

/* Dot accessor token (.) */
typedef struct {
	HbcToken base;
} HbcDotAccessorToken;

/* Bind token (.bind ()) */
typedef struct {
	HbcToken base;
	int reg_num;
} HbcBindToken;

/* Return directive token */
typedef struct {
	HbcToken base;
} HbcReturnDirectiveToken;

/* Throw directive token */
typedef struct {
	HbcToken base;
} HbcThrowDirectiveToken;

/* Function table index token */
typedef struct {
	HbcToken base;
	u32 function_id;
	struct HermesDecompiler *state;
	int environment_id;
	bool is_closure;
	bool is_builtin;
	bool is_generator;
	bool is_async;
	struct Environment *parent_environment;
} HbcFunctionTableIndexToken;

/* Jump condition tokens */
typedef struct {
	HbcToken base;
	u32 target_address;
} HbcJumpConditionToken;

typedef struct {
	HbcToken base;
	u32 target_address;
} HbcJumpNotConditionToken;

/* Environment tokens */
typedef struct {
	HbcToken base;
	int reg_num;
	int nesting_level;
} HbcGetEnvironmentToken;

typedef struct {
	HbcToken base;
	int reg_num;
	int slot_index;
} HbcLoadFromEnvironmentToken;

typedef struct {
	HbcToken base;
	int reg_num;
} HbcNewEnvironmentToken;

typedef struct {
	HbcToken base;
	int dest_register;
	int parent_register;
	int number_of_slots;
} HbcNewInnerEnvironmentToken;

/* Switch statement token */
typedef struct {
	HbcToken base;
	int value_reg;
	u32 jump_table_address;
	u32 default_jump_address;
	u32 unsigned_min_value;
	u32 unsigned_max_value;
} HbcSwitchImmToken;

/* Environment store token */
typedef struct {
	HbcToken base;
	int env_register;
	int slot_index;
	int value_register;
} HbcStoreToEnvironmentToken;

/* For-in loop tokens */
typedef struct {
	HbcToken base;
	int obj_props_register;
	int obj_register;
	int iter_index_register;
	int iter_size_register;
} HbcForInLoopInitToken;

typedef struct {
	HbcToken base;
	int next_value_register;
	int obj_props_register;
	int obj_register;
	int iter_index_register;
	int iter_size_register;
} HbcForInLoopNextIterToken;

/* Generator tokens */
typedef struct {
	HbcToken base;
	int result_out_reg;
	int return_bool_out_reg;
} HbcResumeGeneratorToken;

typedef struct {
	HbcToken base;
	u32 address;
} HbcSaveGeneratorToken;

typedef struct {
	HbcToken base;
} HbcStartGeneratorToken;

/* Try-catch token */
typedef struct {
	HbcToken base;
	int arg_register;
} HbcCatchBlockStartToken;

/* HbcToken string (list of tokens) */
typedef struct {
	HbcToken *head;
	HbcToken *tail;
	ParsedInstruction *assembly;
} HbcTokenString;

/* Function declarations */
Result _hbc_token_string_init(HbcTokenString *token_string, ParsedInstruction *instruction);
void _hbc_token_string_cleanup(HbcTokenString *token_string);

/* HbcToken creation functions */
HbcToken *hbc_token_new_raw(const char *text);
HbcToken *hbc_token_new_left_hand_reg(int reg_num);
HbcToken *hbc_token_new_right_hand_reg(int reg_num);
HbcToken *hbc_token_new_assignment(void);
HbcToken *hbc_token_new_left_parenthesis(void);
HbcToken *hbc_token_new_right_parenthesis(void);
HbcToken *hbc_token_new_dot_accessor(void);
HbcToken *hbc_token_new_bind(int reg_num);
HbcToken *hbc_token_new_return_directive(void);
HbcToken *hbc_token_new_throw_directive(void);
HbcToken *hbc_token_new_function_table_index(u32 function_id, struct HermesDecompiler *state);
HbcToken *hbc_token_new_jump_condition(u32 target_address);
HbcToken *hbc_token_new_jump_not_condition(u32 target_address);

/* Advanced token creation */
HbcToken *hbc_token_new_get_environment(int reg_num, int nesting_level);
HbcToken *hbc_token_new_load_from_environment(int reg_num, int slot_index);
HbcToken *hbc_token_new_new_environment(int reg_num);
HbcToken *hbc_token_new_new_inner_environment(int dest_register, int parent_register, int number_of_slots);
HbcToken *hbc_token_new_switch_imm(int value_reg, u32 jump_table_address, u32 default_jump_address, u32 unsigned_min_value, u32 unsigned_max_value);
HbcToken *hbc_token_new_store_to_environment(int env_register, int slot_index, int value_register);
HbcToken *hbc_token_new_for_in_loop_init(int obj_props_register, int obj_register, int iter_index_register, int iter_size_register);
HbcToken *hbc_token_new_for_in_loop_next_iter(int next_value_register, int obj_props_register, int obj_register, int iter_index_register, int iter_size_register);
HbcToken *hbc_token_new_resume_generator(int result_out_reg, int return_bool_out_reg);
HbcToken *hbc_token_new_save_generator(u32 address);
HbcToken *hbc_token_new_start_generator(void);
HbcToken *hbc_token_new_catch_block_start(int arg_register);

/* HbcToken manipulation */
Result _hbc_token_string_add_token(HbcTokenString *token_string, HbcToken *token);
void _hbc_token_free(HbcToken *token);
Result _hbc_token_to_string(HbcToken *token, StringBuffer *buffer);
Result _hbc_token_string_to_string(HbcTokenString *token_string, StringBuffer *buffer);

#endif /* LIBHBC_TOKEN_H */
