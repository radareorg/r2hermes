#include <hbc/decompilation/token.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/common.h>

#include <ctype.h>

static Token *alloc_token(TokenType type, size_t extra) {
	Token *t = (Token *)malloc ((sizeof (Token)) + extra);
	if (!t) {
		return NULL;
	}
	t->type = type;
	t->next = NULL;
	return t;
}

Result token_string_init(TokenString *ts, ParsedInstruction *insn) {
	if (!ts) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "token_string_init: ts NULL");
	}
	ts->head = ts->tail = NULL;
	ts->assembly = insn;
	return SUCCESS_RESULT ();
}

void token_string_cleanup(TokenString *ts) {
	if (!ts) {
		return;
	}
	Token *cur = ts->head;
	while (cur) {
		Token *nxt = cur->next;
		token_free (cur);
		cur = nxt;
	}
	ts->head = ts->tail = NULL;
	ts->assembly = NULL;
}

Result token_string_add_token(TokenString *ts, Token *t) {
	if (!ts || !t) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "token_string_add_token: NULL");
	}
	if (!ts->head) {
		ts->head = ts->tail = t;
	} else {
		ts->tail->next = t;
		ts->tail = t;
	}
	return SUCCESS_RESULT ();
}

Token *create_raw_token(const char *text) {
	if (!text) {
		return NULL;
	}
	RawToken *rt = (RawToken *)alloc_token (TOKEN_TYPE_RAW, sizeof (RawToken) - sizeof (Token));
	if (!rt) {
		return NULL;
	}
	size_t len = strlen (text);
	rt->text = (char *)malloc (len + 1);
	if (!rt->text) {
		free (rt);
		return NULL;
	}
	memcpy (rt->text, text, len + 1);
	return (Token *)rt;
}

Token *create_left_hand_reg_token(int reg_num) {
	LeftHandRegToken *t = (LeftHandRegToken *)alloc_token (TOKEN_TYPE_LEFT_HAND_REG, sizeof (LeftHandRegToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (Token *)t;
}

Token *create_right_hand_reg_token(int reg_num) {
	RightHandRegToken *t = (RightHandRegToken *)alloc_token (TOKEN_TYPE_RIGHT_HAND_REG, sizeof (RightHandRegToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (Token *)t;
}

Token *create_assignment_token(void) {
	return alloc_token (TOKEN_TYPE_ASSIGNMENT, 0);
}

Token *create_left_parenthesis_token(void) {
	return alloc_token (TOKEN_TYPE_LEFT_PARENTHESIS, 0);
}
Token *create_right_parenthesis_token(void) {
	return alloc_token (TOKEN_TYPE_RIGHT_PARENTHESIS, 0);
}
Token *create_dot_accessor_token(void) {
	return alloc_token (TOKEN_TYPE_DOT_ACCESSOR, 0);
}

Token *create_bind_token(int reg_num) {
	BindToken *t = (BindToken *)alloc_token (TOKEN_TYPE_BIND, sizeof (BindToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (Token *)t;
}

Token *create_return_directive_token(void) {
	return alloc_token (TOKEN_TYPE_RETURN_DIRECTIVE, 0);
}
Token *create_throw_directive_token(void) {
	return alloc_token (TOKEN_TYPE_THROW_DIRECTIVE, 0);
}

Token *create_function_table_index_token(u32 function_id, struct HermesDecompiler *state) {
	FunctionTableIndexToken *t = (FunctionTableIndexToken *)alloc_token (TOKEN_TYPE_FUNCTION_TABLE_INDEX, sizeof (FunctionTableIndexToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->function_id = function_id;
	t->state = state;
	t->environment_id = -1;
	t->is_closure = false;
	t->is_builtin = false;
	t->is_generator = false;
	t->is_async = false;
	t->parent_environment = NULL;
	return (Token *)t;
}

Token *create_jump_condition_token(u32 target_address) {
	JumpConditionToken *t = (JumpConditionToken *)alloc_token (TOKEN_TYPE_JUMP_CONDITION, sizeof (JumpConditionToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->target_address = target_address;
	return (Token *)t;
}

Token *create_jump_not_condition_token(u32 target_address) {
	JumpNotConditionToken *t = (JumpNotConditionToken *)alloc_token (TOKEN_TYPE_JUMP_NOT_CONDITION, sizeof (JumpNotConditionToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->target_address = target_address;
	return (Token *)t;
}

Token *create_get_environment_token(int reg_num, int nesting_level) {
	GetEnvironmentToken *t = (GetEnvironmentToken *)alloc_token (TOKEN_TYPE_GET_ENVIRONMENT, sizeof (GetEnvironmentToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	t->nesting_level = nesting_level;
	return (Token *)t;
}

Token *create_load_from_environment_token(int reg_num, int slot_index) {
	LoadFromEnvironmentToken *t = (LoadFromEnvironmentToken *)alloc_token (TOKEN_TYPE_LOAD_FROM_ENVIRONMENT, sizeof (LoadFromEnvironmentToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	t->slot_index = slot_index;
	return (Token *)t;
}

Token *create_new_environment_token(int reg_num) {
	NewEnvironmentToken *t = (NewEnvironmentToken *)alloc_token (TOKEN_TYPE_NEW_ENVIRONMENT, sizeof (NewEnvironmentToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (Token *)t;
}

Token *create_new_inner_environment_token(int dest_register, int parent_register, int number_of_slots) {
	NewInnerEnvironmentToken *t = (NewInnerEnvironmentToken *)alloc_token (TOKEN_TYPE_NEW_INNER_ENVIRONMENT, sizeof (NewInnerEnvironmentToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->dest_register = dest_register;
	t->parent_register = parent_register;
	t->number_of_slots = number_of_slots;
	return (Token *)t;
}

Token *create_switch_imm_token(int value_reg, u32 jump_table_address, u32 default_jump_address, u32 unsigned_min_value, u32 unsigned_max_value) {
	SwitchImmToken *t = (SwitchImmToken *)alloc_token (TOKEN_TYPE_SWITCH_IMM, sizeof (SwitchImmToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->value_reg = value_reg;
	t->jump_table_address = jump_table_address;
	t->default_jump_address = default_jump_address;
	t->unsigned_min_value = unsigned_min_value;
	t->unsigned_max_value = unsigned_max_value;
	return (Token *)t;
}

Token *create_store_to_environment_token(int env_register, int slot_index, int value_register) {
	StoreToEnvironmentToken *t = (StoreToEnvironmentToken *)alloc_token (TOKEN_TYPE_STORE_TO_ENVIRONMENT, sizeof (StoreToEnvironmentToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->env_register = env_register;
	t->slot_index = slot_index;
	t->value_register = value_register;
	return (Token *)t;
}

Token *create_for_in_loop_init_token(int obj_props_register, int obj_register, int iter_index_register, int iter_size_register) {
	ForInLoopInitToken *t = (ForInLoopInitToken *)alloc_token (TOKEN_TYPE_FOR_IN_LOOP_INIT, sizeof (ForInLoopInitToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->obj_props_register = obj_props_register;
	t->obj_register = obj_register;
	t->iter_index_register = iter_index_register;
	t->iter_size_register = iter_size_register;
	return (Token *)t;
}

Token *create_for_in_loop_next_iter_token(int next_value_register, int obj_props_register, int obj_register, int iter_index_register, int iter_size_register) {
	ForInLoopNextIterToken *t = (ForInLoopNextIterToken *)alloc_token (TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER, sizeof (ForInLoopNextIterToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->next_value_register = next_value_register;
	t->obj_props_register = obj_props_register;
	t->obj_register = obj_register;
	t->iter_index_register = iter_index_register;
	t->iter_size_register = iter_size_register;
	return (Token *)t;
}

Token *create_resume_generator_token(int result_out_reg, int return_bool_out_reg) {
	ResumeGeneratorToken *t = (ResumeGeneratorToken *)alloc_token (TOKEN_TYPE_RESUME_GENERATOR, sizeof (ResumeGeneratorToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->result_out_reg = result_out_reg;
	t->return_bool_out_reg = return_bool_out_reg;
	return (Token *)t;
}

Token *create_save_generator_token(u32 address) {
	SaveGeneratorToken *t = (SaveGeneratorToken *)alloc_token (TOKEN_TYPE_SAVE_GENERATOR, sizeof (SaveGeneratorToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->address = address;
	return (Token *)t;
}

Token *create_start_generator_token(void) {
	return alloc_token (TOKEN_TYPE_START_GENERATOR, 0);
}

Token *create_catch_block_start_token(int arg_register) {
	CatchBlockStartToken *t = (CatchBlockStartToken *)alloc_token (TOKEN_TYPE_CATCH_BLOCK_START, sizeof (CatchBlockStartToken) - sizeof (Token));
	if (!t) {
		return NULL;
	}
	t->arg_register = arg_register;
	return (Token *)t;
}

void token_free(Token *tok) {
	if (!tok) {
		return;
	}
	if (tok->type == TOKEN_TYPE_RAW) {
		RawToken *rt = (RawToken *)tok;
		free (rt->text);
	}
	free (tok);
}

static Result append_reg(StringBuffer *b, int r) {
	char buf[32];
	snprintf (buf, sizeof (buf), "r%d", r);
	return string_buffer_append (b, buf);
}

/* Very simple token to string printer, good enough for M1 */
Result token_to_string(Token *token, StringBuffer *buffer) {
	if (!token || !buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "token_to_string: NULL");
	}
	switch (token->type) {
	case TOKEN_TYPE_RAW:
		{
			RawToken *t = (RawToken *)token;
			return string_buffer_append (buffer, t->text? t->text: "");
		}
	case TOKEN_TYPE_LEFT_HAND_REG:
		{
			LeftHandRegToken *t = (LeftHandRegToken *)token;
			return append_reg (buffer, t->reg_num);
		}
	case TOKEN_TYPE_RIGHT_HAND_REG:
		{
			RightHandRegToken *t = (RightHandRegToken *)token;
			return append_reg (buffer, t->reg_num);
		}
	case TOKEN_TYPE_ASSIGNMENT: return string_buffer_append (buffer, "=");
	case TOKEN_TYPE_LEFT_PARENTHESIS: return string_buffer_append (buffer, "(");
	case TOKEN_TYPE_RIGHT_PARENTHESIS: return string_buffer_append (buffer, ")");
	case TOKEN_TYPE_DOT_ACCESSOR: return string_buffer_append (buffer, ".");
	case TOKEN_TYPE_BIND:
		{
			BindToken *t = (BindToken *)token;
			RETURN_IF_ERROR (string_buffer_append (buffer, ".bind("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			return string_buffer_append (buffer, ")");
		}
	case TOKEN_TYPE_RETURN_DIRECTIVE: return string_buffer_append (buffer, "return");
	case TOKEN_TYPE_THROW_DIRECTIVE: return string_buffer_append (buffer, "throw");
	case TOKEN_TYPE_FUNCTION_TABLE_INDEX:
		{
			FunctionTableIndexToken *t = (FunctionTableIndexToken *)token;
			/* Try to resolve name if possible */
		if (t->state && t->state->hbc_reader && t->function_id < t->state->hbc_reader->header.functionCount) {
				u32 name_id = t->state->hbc_reader->function_headers[t->function_id].functionName;
			const char *name = (name_id < t->state->hbc_reader->header.stringCount && t->state->hbc_reader->strings)? t->state->hbc_reader->strings[name_id]: NULL;
			if (name && *name) {
					RETURN_IF_ERROR (string_buffer_append (buffer, name));
					return SUCCESS_RESULT ();
				}
			}
			char buf[32];
			snprintf (buf, sizeof (buf), "fn_%u", t->function_id);
			return string_buffer_append (buffer, buf);
		}
	case TOKEN_TYPE_JUMP_CONDITION:
		{
			JumpConditionToken *t = (JumpConditionToken *)token;
			char buf[64];
			snprintf (buf, sizeof (buf), "/* jump -> 0x%08x */", t->target_address);
			return string_buffer_append (buffer, buf);
		}
	case TOKEN_TYPE_JUMP_NOT_CONDITION:
		{
			JumpNotConditionToken *t = (JumpNotConditionToken *)token;
			char buf[64];
			snprintf (buf, sizeof (buf), "/* jump_if_not -> 0x%08x */", t->target_address);
			return string_buffer_append (buffer, buf);
		}
	case TOKEN_TYPE_GET_ENVIRONMENT:
		{
			GetEnvironmentToken *t = (GetEnvironmentToken *)token;
			RETURN_IF_ERROR (string_buffer_append (buffer, "get_env("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			RETURN_IF_ERROR (string_buffer_append (buffer, ", "));
			char nb[16];
			snprintf (nb, sizeof (nb), "%d", t->nesting_level);
			RETURN_IF_ERROR (string_buffer_append (buffer, nb));
			return string_buffer_append (buffer, ")");
		}
	case TOKEN_TYPE_LOAD_FROM_ENVIRONMENT:
		{
			LoadFromEnvironmentToken *t = (LoadFromEnvironmentToken *)token;
			RETURN_IF_ERROR (string_buffer_append (buffer, "env_load("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			RETURN_IF_ERROR (string_buffer_append (buffer, ", "));
			char nb[16];
			snprintf (nb, sizeof (nb), "%d", t->slot_index);
			RETURN_IF_ERROR (string_buffer_append (buffer, nb));
			return string_buffer_append (buffer, ")");
		}
	case TOKEN_TYPE_NEW_ENVIRONMENT:
		{
			NewEnvironmentToken *t = (NewEnvironmentToken *)token;
			RETURN_IF_ERROR (string_buffer_append (buffer, "new_env("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			return string_buffer_append (buffer, ")");
		}
	case TOKEN_TYPE_NEW_INNER_ENVIRONMENT:
		{
			NewInnerEnvironmentToken *t = (NewInnerEnvironmentToken *)token;
			char nb[64];
			snprintf (nb, sizeof (nb), "new_inner_env(r%d, r%d, %d)", t->dest_register, t->parent_register, t->number_of_slots);
			return string_buffer_append (buffer, nb);
		}
	case TOKEN_TYPE_SWITCH_IMM:
		{
			SwitchImmToken *t = (SwitchImmToken *)token;
			char nb[128];
			snprintf (nb, sizeof (nb), "switch(r%d /*%u..%u*/)", t->value_reg, t->unsigned_min_value, t->unsigned_max_value);
			return string_buffer_append (buffer, nb);
		}
	case TOKEN_TYPE_STORE_TO_ENVIRONMENT:
		{
			StoreToEnvironmentToken *t = (StoreToEnvironmentToken *)token;
			char nb[64];
			snprintf (nb, sizeof (nb), "env_store(r%d, %d, r%d)", t->env_register, t->slot_index, t->value_register);
			return string_buffer_append (buffer, nb);
		}
	case TOKEN_TYPE_FOR_IN_LOOP_INIT:
		{
			ForInLoopInitToken *t = (ForInLoopInitToken *)token;
			char nb[128];
			snprintf (nb, sizeof (nb), "forin_init(r%d, r%d, r%d, r%d)", t->obj_props_register, t->obj_register, t->iter_index_register, t->iter_size_register);
			return string_buffer_append (buffer, nb);
		}
	case TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER:
		{
			ForInLoopNextIterToken *t = (ForInLoopNextIterToken *)token;
			char nb[160];
			snprintf (nb, sizeof (nb), "forin_next(r%d, r%d, r%d, r%d, r%d)", t->next_value_register, t->obj_props_register, t->obj_register, t->iter_index_register, t->iter_size_register);
			return string_buffer_append (buffer, nb);
		}
	case TOKEN_TYPE_RESUME_GENERATOR:
		{
			ResumeGeneratorToken *t = (ResumeGeneratorToken *)token;
			char nb[64];
			snprintf (nb, sizeof (nb), "resume_gen(r%d, r%d)", t->result_out_reg, t->return_bool_out_reg);
			return string_buffer_append (buffer, nb);
		}
	case TOKEN_TYPE_SAVE_GENERATOR:
		{
			SaveGeneratorToken *t = (SaveGeneratorToken *)token;
			char nb[64];
			snprintf (nb, sizeof (nb), "save_gen(0x%08x)", t->address);
			return string_buffer_append (buffer, nb);
		}
	case TOKEN_TYPE_START_GENERATOR: return string_buffer_append (buffer, "start_generator()");
	case TOKEN_TYPE_CATCH_BLOCK_START:
		{
			CatchBlockStartToken *t = (CatchBlockStartToken *)token;
			char nb[32];
			snprintf (nb, sizeof (nb), "catch(r%d)", t->arg_register);
			return string_buffer_append (buffer, nb);
		}
	default:
		return string_buffer_append (buffer, "/*token*/");
	}
}

static bool is_punct(TokenType t) {
	return t == TOKEN_TYPE_LEFT_PARENTHESIS || t == TOKEN_TYPE_RIGHT_PARENTHESIS || t == TOKEN_TYPE_DOT_ACCESSOR;
}

Result token_string_to_string(TokenString *ts, StringBuffer *out) {
	if (!ts || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "token_string_to_string: NULL");
	}
	Token *cur = ts->head;
	TokenType prev = (TokenType) (-1);
	while (cur) {
		/* spacing rules: no space before punctuation, no space after '(' or before ')', add spaces around '=' */
		if (cur != ts->head) {
			bool need_space = true;
			if (is_punct (cur->type) || prev == TOKEN_TYPE_LEFT_PARENTHESIS || cur->type == TOKEN_TYPE_RIGHT_PARENTHESIS || cur->type == TOKEN_TYPE_DOT_ACCESSOR) {
				need_space = false;
			}
			if (prev == TOKEN_TYPE_DOT_ACCESSOR) {
				need_space = false;
			}
			if (prev == TOKEN_TYPE_ASSIGNMENT || cur->type == TOKEN_TYPE_ASSIGNMENT) {
				need_space = true;
			}
			if (need_space) {
				RETURN_IF_ERROR (string_buffer_append_char (out, ' '));
			}
		}
		RETURN_IF_ERROR (token_to_string (cur, out));
		prev = cur->type;
		cur = cur->next;
	}
	return SUCCESS_RESULT ();
}
