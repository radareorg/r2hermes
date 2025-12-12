#ifndef HERMES_DEC_TOKEN_H
#define HERMES_DEC_TOKEN_H

#include <hbc/common.h>
#include <hbc/parsers/hbc_bytecode_parser.h>

/* Forward declarations */
struct HermesDecompiler;
struct Environment;

/* Token types */
typedef enum {
	TOKEN_TYPE_RAW,
	TOKEN_TYPE_LEFT_HAND_REG,
	TOKEN_TYPE_RIGHT_HAND_REG,
	TOKEN_TYPE_ASSIGNMENT,
	TOKEN_TYPE_LEFT_PARENTHESIS,
	TOKEN_TYPE_RIGHT_PARENTHESIS,
	TOKEN_TYPE_DOT_ACCESSOR,
	TOKEN_TYPE_BIND,
	TOKEN_TYPE_RETURN_DIRECTIVE,
	TOKEN_TYPE_THROW_DIRECTIVE,
	TOKEN_TYPE_FUNCTION_TABLE_INDEX,
	TOKEN_TYPE_JUMP_CONDITION,
	TOKEN_TYPE_JUMP_NOT_CONDITION,
	TOKEN_TYPE_GET_ENVIRONMENT,
	TOKEN_TYPE_LOAD_FROM_ENVIRONMENT,
	TOKEN_TYPE_NEW_ENVIRONMENT,
	TOKEN_TYPE_NEW_INNER_ENVIRONMENT,
	TOKEN_TYPE_SWITCH_IMM,
	TOKEN_TYPE_STORE_TO_ENVIRONMENT,
	TOKEN_TYPE_FOR_IN_LOOP_INIT,
	TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER,
	TOKEN_TYPE_RESUME_GENERATOR,
	TOKEN_TYPE_SAVE_GENERATOR,
	TOKEN_TYPE_START_GENERATOR,
	TOKEN_TYPE_CATCH_BLOCK_START
} TokenType;

/* Base token structure */
typedef struct Token {
	TokenType type;
	struct Token *next;
} Token;

/* Raw token with string content */
typedef struct {
	Token base;
	char *text;
} RawToken;

/* Register token (left-hand side) */
typedef struct {
	Token base;
	int reg_num;
} LeftHandRegToken;

/* Register token (right-hand side) */
typedef struct {
	Token base;
	int reg_num;
} RightHandRegToken;

/* Assignment token (=) */
typedef struct {
	Token base;
} AssignmentToken;

/* Parenthesis tokens */
typedef struct {
	Token base;
} LeftParenthesisToken;

typedef struct {
	Token base;
} RightParenthesisToken;

/* Dot accessor token (.) */
typedef struct {
	Token base;
} DotAccessorToken;

/* Bind token (.bind ()) */
typedef struct {
	Token base;
	int reg_num;
} BindToken;

/* Return directive token */
typedef struct {
	Token base;
} ReturnDirectiveToken;

/* Throw directive token */
typedef struct {
	Token base;
} ThrowDirectiveToken;

/* Function table index token */
typedef struct {
	Token base;
	u32 function_id;
	struct HermesDecompiler *state;
	int environment_id;
	bool is_closure;
	bool is_builtin;
	bool is_generator;
	bool is_async;
	struct Environment *parent_environment;
} FunctionTableIndexToken;

/* Jump condition tokens */
typedef struct {
	Token base;
	u32 target_address;
} JumpConditionToken;

typedef struct {
	Token base;
	u32 target_address;
} JumpNotConditionToken;

/* Environment tokens */
typedef struct {
	Token base;
	int reg_num;
	int nesting_level;
} GetEnvironmentToken;

typedef struct {
	Token base;
	int reg_num;
	int slot_index;
} LoadFromEnvironmentToken;

typedef struct {
	Token base;
	int reg_num;
} NewEnvironmentToken;

typedef struct {
	Token base;
	int dest_register;
	int parent_register;
	int number_of_slots;
} NewInnerEnvironmentToken;

/* Switch statement token */
typedef struct {
	Token base;
	int value_reg;
	u32 jump_table_address;
	u32 default_jump_address;
	u32 unsigned_min_value;
	u32 unsigned_max_value;
} SwitchImmToken;

/* Environment store token */
typedef struct {
	Token base;
	int env_register;
	int slot_index;
	int value_register;
} StoreToEnvironmentToken;

/* For-in loop tokens */
typedef struct {
	Token base;
	int obj_props_register;
	int obj_register;
	int iter_index_register;
	int iter_size_register;
} ForInLoopInitToken;

typedef struct {
	Token base;
	int next_value_register;
	int obj_props_register;
	int obj_register;
	int iter_index_register;
	int iter_size_register;
} ForInLoopNextIterToken;

/* Generator tokens */
typedef struct {
	Token base;
	int result_out_reg;
	int return_bool_out_reg;
} ResumeGeneratorToken;

typedef struct {
	Token base;
	u32 address;
} SaveGeneratorToken;

typedef struct {
	Token base;
} StartGeneratorToken;

/* Try-catch token */
typedef struct {
	Token base;
	int arg_register;
} CatchBlockStartToken;

/* Token string (list of tokens) */
typedef struct {
	Token *head;
	Token *tail;
	ParsedInstruction *assembly;
} TokenString;

/* Function declarations */
Result token_string_init(TokenString *token_string, ParsedInstruction *instruction);
void token_string_cleanup(TokenString *token_string);

/* Token creation functions */
Token *create_raw_token(const char *text);
Token *create_left_hand_reg_token(int reg_num);
Token *create_right_hand_reg_token(int reg_num);
Token *create_assignment_token(void);
Token *create_left_parenthesis_token(void);
Token *create_right_parenthesis_token(void);
Token *create_dot_accessor_token(void);
Token *create_bind_token(int reg_num);
Token *create_return_directive_token(void);
Token *create_throw_directive_token(void);
Token *create_function_table_index_token(u32 function_id, struct HermesDecompiler *state);
Token *create_jump_condition_token(u32 target_address);
Token *create_jump_not_condition_token(u32 target_address);

/* Advanced token creation */
Token *create_get_environment_token(int reg_num, int nesting_level);
Token *create_load_from_environment_token(int reg_num, int slot_index);
Token *create_new_environment_token(int reg_num);
Token *create_new_inner_environment_token(int dest_register, int parent_register, int number_of_slots);
Token *create_switch_imm_token(int value_reg, u32 jump_table_address, u32 default_jump_address,
	u32 unsigned_min_value, u32 unsigned_max_value);
Token *create_store_to_environment_token(int env_register, int slot_index, int value_register);
Token *create_for_in_loop_init_token(int obj_props_register, int obj_register,
	int iter_index_register, int iter_size_register);
Token *create_for_in_loop_next_iter_token(int next_value_register, int obj_props_register,
	int obj_register, int iter_index_register, int iter_size_register);
Token *create_resume_generator_token(int result_out_reg, int return_bool_out_reg);
Token *create_save_generator_token(u32 address);
Token *create_start_generator_token(void);
Token *create_catch_block_start_token(int arg_register);

/* Token manipulation */
Result token_string_add_token(TokenString *token_string, Token *token);
void token_free(Token *token);
Result token_to_string(Token *token, StringBuffer *buffer);
Result token_string_to_string(TokenString *token_string, StringBuffer *buffer);

#endif /* HERMES_DEC_TOKEN_H */
