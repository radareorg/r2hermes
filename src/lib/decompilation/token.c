/* radare2 - BSD - Copyright 2025-2026 - pancake */

#include <hbc/decompilation/token.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/common.h>

#include <ctype.h>

static HbcToken *alloc_token(HbcTokenType type, size_t extra) {
	HbcToken *t = (HbcToken *)malloc ((sizeof (HbcToken)) + extra);
	if (!t) {
		return NULL;
	}
	t->type = type;
	t->next = NULL;
	return t;
}

Result _hbc_token_string_init(HbcTokenString *ts, ParsedInstruction *insn) {
	if (!ts) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_token_string_init: ts NULL");
	}
	ts->head = ts->tail = NULL;
	ts->assembly = insn;
	return SUCCESS_RESULT ();
}

void _hbc_token_string_cleanup(HbcTokenString *ts) {
	if (!ts) {
		return;
	}
	HbcToken *cur = ts->head;
	while (cur) {
		HbcToken *nxt = cur->next;
		_hbc_token_free (cur);
		cur = nxt;
	}
	ts->head = ts->tail = NULL;
	ts->assembly = NULL;
}

Result _hbc_token_string_add_token(HbcTokenString *ts, HbcToken *t) {
	if (!ts || !t) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_token_string_add_token: NULL");
	}
	if (!ts->head) {
		ts->head = ts->tail = t;
	} else {
		ts->tail->next = t;
		ts->tail = t;
	}
	return SUCCESS_RESULT ();
}

HbcToken *hbc_token_new_raw(const char *text) {
	if (!text) {
		return NULL;
	}
	HbcRawToken *rt = (HbcRawToken *)alloc_token (HBC_TOKEN_TYPE_RAW, sizeof (HbcRawToken) - sizeof (HbcToken));
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
	return (HbcToken *)rt;
}

HbcToken *hbc_token_new_left_hand_reg(int reg_num) {
	HbcLeftHandRegToken *t = (HbcLeftHandRegToken *)alloc_token (HBC_TOKEN_TYPE_LEFT_HAND_REG, sizeof (HbcLeftHandRegToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_right_hand_reg(int reg_num) {
	HbcRightHandRegToken *t = (HbcRightHandRegToken *)alloc_token (HBC_TOKEN_TYPE_RIGHT_HAND_REG, sizeof (HbcRightHandRegToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_assignment(void) {
	return alloc_token (HBC_TOKEN_TYPE_ASSIGNMENT, 0);
}

HbcToken *hbc_token_new_left_parenthesis(void) {
	return alloc_token (HBC_TOKEN_TYPE_LEFT_PARENTHESIS, 0);
}
HbcToken *hbc_token_new_right_parenthesis(void) {
	return alloc_token (HBC_TOKEN_TYPE_RIGHT_PARENTHESIS, 0);
}
HbcToken *hbc_token_new_dot_accessor(void) {
	return alloc_token (HBC_TOKEN_TYPE_DOT_ACCESSOR, 0);
}

HbcToken *hbc_token_new_bind(int reg_num) {
	HbcBindToken *t = (HbcBindToken *)alloc_token (HBC_TOKEN_TYPE_BIND, sizeof (HbcBindToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_return_directive(void) {
	return alloc_token (HBC_TOKEN_TYPE_RETURN_DIRECTIVE, 0);
}
HbcToken *hbc_token_new_throw_directive(void) {
	return alloc_token (HBC_TOKEN_TYPE_THROW_DIRECTIVE, 0);
}

HbcToken *hbc_token_new_function_table_index(u32 function_id, struct HermesDecompiler *state) {
	HbcFunctionTableIndexToken *t = (HbcFunctionTableIndexToken *)alloc_token (HBC_TOKEN_TYPE_FUNCTION_TABLE_INDEX, sizeof (HbcFunctionTableIndexToken) - sizeof (HbcToken));
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
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_jump_condition(u32 target_address) {
	HbcJumpConditionToken *t = (HbcJumpConditionToken *)alloc_token (HBC_TOKEN_TYPE_JUMP_CONDITION, sizeof (HbcJumpConditionToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->target_address = target_address;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_jump_not_condition(u32 target_address) {
	HbcJumpNotConditionToken *t = (HbcJumpNotConditionToken *)alloc_token (HBC_TOKEN_TYPE_JUMP_NOT_CONDITION, sizeof (HbcJumpNotConditionToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->target_address = target_address;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_get_environment(int reg_num, int nesting_level) {
	HbcGetEnvironmentToken *t = (HbcGetEnvironmentToken *)alloc_token (HBC_TOKEN_TYPE_GET_ENVIRONMENT, sizeof (HbcGetEnvironmentToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	t->nesting_level = nesting_level;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_load_from_environment(int reg_num, int slot_index) {
	HbcLoadFromEnvironmentToken *t = (HbcLoadFromEnvironmentToken *)alloc_token (HBC_TOKEN_TYPE_LOAD_FROM_ENVIRONMENT, sizeof (HbcLoadFromEnvironmentToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	t->slot_index = slot_index;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_new_environment(int reg_num) {
	HbcNewEnvironmentToken *t = (HbcNewEnvironmentToken *)alloc_token (HBC_TOKEN_TYPE_NEW_ENVIRONMENT, sizeof (HbcNewEnvironmentToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->reg_num = reg_num;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_new_inner_environment(int dest_register, int parent_register, int number_of_slots) {
	HbcNewInnerEnvironmentToken *t = (HbcNewInnerEnvironmentToken *)alloc_token (HBC_TOKEN_TYPE_NEW_INNER_ENVIRONMENT, sizeof (HbcNewInnerEnvironmentToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->dest_register = dest_register;
	t->parent_register = parent_register;
	t->number_of_slots = number_of_slots;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_switch_imm(int value_reg, u32 jump_table_address, u32 default_jump_address, u32 unsigned_min_value, u32 unsigned_max_value) {
	HbcSwitchImmToken *t = (HbcSwitchImmToken *)alloc_token (HBC_TOKEN_TYPE_SWITCH_IMM, sizeof (HbcSwitchImmToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->value_reg = value_reg;
	t->jump_table_address = jump_table_address;
	t->default_jump_address = default_jump_address;
	t->unsigned_min_value = unsigned_min_value;
	t->unsigned_max_value = unsigned_max_value;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_store_to_environment(int env_register, int slot_index, int value_register) {
	HbcStoreToEnvironmentToken *t = (HbcStoreToEnvironmentToken *)alloc_token (HBC_TOKEN_TYPE_STORE_TO_ENVIRONMENT, sizeof (HbcStoreToEnvironmentToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->env_register = env_register;
	t->slot_index = slot_index;
	t->value_register = value_register;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_for_in_loop_init(int obj_props_register, int obj_register, int iter_index_register, int iter_size_register) {
	HbcForInLoopInitToken *t = (HbcForInLoopInitToken *)alloc_token (HBC_TOKEN_TYPE_FOR_IN_LOOP_INIT, sizeof (HbcForInLoopInitToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->obj_props_register = obj_props_register;
	t->obj_register = obj_register;
	t->iter_index_register = iter_index_register;
	t->iter_size_register = iter_size_register;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_for_in_loop_next_iter(int next_value_register, int obj_props_register, int obj_register, int iter_index_register, int iter_size_register) {
	HbcForInLoopNextIterToken *t = (HbcForInLoopNextIterToken *)alloc_token (HBC_TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER, sizeof (HbcForInLoopNextIterToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->next_value_register = next_value_register;
	t->obj_props_register = obj_props_register;
	t->obj_register = obj_register;
	t->iter_index_register = iter_index_register;
	t->iter_size_register = iter_size_register;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_resume_generator(int result_out_reg, int return_bool_out_reg) {
	HbcResumeGeneratorToken *t = (HbcResumeGeneratorToken *)alloc_token (HBC_TOKEN_TYPE_RESUME_GENERATOR, sizeof (HbcResumeGeneratorToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->result_out_reg = result_out_reg;
	t->return_bool_out_reg = return_bool_out_reg;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_save_generator(u32 address) {
	HbcSaveGeneratorToken *t = (HbcSaveGeneratorToken *)alloc_token (HBC_TOKEN_TYPE_SAVE_GENERATOR, sizeof (HbcSaveGeneratorToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->address = address;
	return (HbcToken *)t;
}

HbcToken *hbc_token_new_start_generator(void) {
	return alloc_token (HBC_TOKEN_TYPE_START_GENERATOR, 0);
}

HbcToken *hbc_token_new_catch_block_start(int arg_register) {
	HbcCatchBlockStartToken *t = (HbcCatchBlockStartToken *)alloc_token (HBC_TOKEN_TYPE_CATCH_BLOCK_START, sizeof (HbcCatchBlockStartToken) - sizeof (HbcToken));
	if (!t) {
		return NULL;
	}
	t->arg_register = arg_register;
	return (HbcToken *)t;
}

void _hbc_token_free(HbcToken *tok) {
	if (!tok) {
		return;
	}
	if (tok->type == HBC_TOKEN_TYPE_RAW) {
		HbcRawToken *rt = (HbcRawToken *)tok;
		free (rt->text);
	}
	free (tok);
}

static Result append_reg(RStrBuf *b, int r) {
	return HBC_TO_RESULT (r_strbuf_appendf (b, "r%d", r));
}

/* Very simple token to string printer, good enough for M1 */
Result _hbc_token_to_string(HbcToken *token, RStrBuf *buffer) {
	if (!token || !buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_token_to_string: NULL");
	}
	switch (token->type) {
	case HBC_TOKEN_TYPE_RAW:
		{
			HbcRawToken *t = (HbcRawToken *)token;
			return HBC_TO_RESULT (r_strbuf_append (buffer, t->text? t->text: ""));
		}
	case HBC_TOKEN_TYPE_LEFT_HAND_REG:
		{
			HbcLeftHandRegToken *t = (HbcLeftHandRegToken *)token;
			return append_reg (buffer, t->reg_num);
		}
	case HBC_TOKEN_TYPE_RIGHT_HAND_REG:
		{
			HbcRightHandRegToken *t = (HbcRightHandRegToken *)token;
			return append_reg (buffer, t->reg_num);
		}
	case HBC_TOKEN_TYPE_ASSIGNMENT: return HBC_TO_RESULT (r_strbuf_append (buffer, "="));
	case HBC_TOKEN_TYPE_LEFT_PARENTHESIS: return HBC_TO_RESULT (r_strbuf_append (buffer, "("));
	case HBC_TOKEN_TYPE_RIGHT_PARENTHESIS: return HBC_TO_RESULT (r_strbuf_append (buffer, ")"));
	case HBC_TOKEN_TYPE_DOT_ACCESSOR: return HBC_TO_RESULT (r_strbuf_append (buffer, "."));
	case HBC_TOKEN_TYPE_BIND:
		{
			HbcBindToken *t = (HbcBindToken *)token;
			RETURN_IF_ERROR (r_strbuf_append (buffer, ".bind("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			return HBC_TO_RESULT (r_strbuf_append (buffer, ")"));
		}
	case HBC_TOKEN_TYPE_RETURN_DIRECTIVE: return HBC_TO_RESULT (r_strbuf_append (buffer, "return"));
	case HBC_TOKEN_TYPE_THROW_DIRECTIVE: return HBC_TO_RESULT (r_strbuf_append (buffer, "throw"));
	case HBC_TOKEN_TYPE_FUNCTION_TABLE_INDEX:
		{
			HbcFunctionTableIndexToken *t = (HbcFunctionTableIndexToken *)token;
			/* Try to resolve name if possible */
			if (t->state && t->state->hbc_reader && t->function_id < t->state->hbc_reader->header.functionCount) {
				u32 name_id = t->state->hbc_reader->function_headers[t->function_id].functionName;
				const char *name = (name_id < t->state->hbc_reader->header.stringCount && t->state->hbc_reader->strings)? t->state->hbc_reader->strings[name_id]: NULL;
				if (name && *name) {
					RETURN_IF_ERROR (r_strbuf_append (buffer, name));
					return SUCCESS_RESULT ();
				}
			}
			return HBC_TO_RESULT (r_strbuf_appendf (buffer, "fn_%u", t->function_id));
		}
	case HBC_TOKEN_TYPE_JUMP_CONDITION:
		{
			HbcJumpConditionToken *t = (HbcJumpConditionToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer, "/* jump -> 0x%08x */", t->target_address));
		}
	case HBC_TOKEN_TYPE_JUMP_NOT_CONDITION:
		{
			HbcJumpNotConditionToken *t = (HbcJumpNotConditionToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer, "/* jump_if_not -> 0x%08x */", t->target_address));
		}
	case HBC_TOKEN_TYPE_GET_ENVIRONMENT:
		{
			HbcGetEnvironmentToken *t = (HbcGetEnvironmentToken *)token;
			RETURN_IF_ERROR (r_strbuf_append (buffer, "get_env("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			RETURN_IF_ERROR (r_strbuf_append (buffer, ", "));
			RETURN_IF_ERROR (r_strbuf_appendf (buffer, "%d", t->nesting_level));
			return HBC_TO_RESULT (r_strbuf_append (buffer, ")"));
		}
	case HBC_TOKEN_TYPE_LOAD_FROM_ENVIRONMENT:
		{
			HbcLoadFromEnvironmentToken *t = (HbcLoadFromEnvironmentToken *)token;
			RETURN_IF_ERROR (r_strbuf_append (buffer, "env_load("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			RETURN_IF_ERROR (r_strbuf_append (buffer, ", "));
			RETURN_IF_ERROR (r_strbuf_appendf (buffer, "%d", t->slot_index));
			return HBC_TO_RESULT (r_strbuf_append (buffer, ")"));
		}
	case HBC_TOKEN_TYPE_NEW_ENVIRONMENT:
		{
			HbcNewEnvironmentToken *t = (HbcNewEnvironmentToken *)token;
			RETURN_IF_ERROR (r_strbuf_append (buffer, "new_env("));
			RETURN_IF_ERROR (append_reg (buffer, t->reg_num));
			return HBC_TO_RESULT (r_strbuf_append (buffer, ")"));
		}
	case HBC_TOKEN_TYPE_NEW_INNER_ENVIRONMENT:
		{
			HbcNewInnerEnvironmentToken *t = (HbcNewInnerEnvironmentToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer,
				"new_inner_env(r%d, r%d, %d)",
				t->dest_register,
				t->parent_register,
				t->number_of_slots));
		}
	case HBC_TOKEN_TYPE_SWITCH_IMM:
		{
			HbcSwitchImmToken *t = (HbcSwitchImmToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer,
				"switch(r%d /*%u..%u*/)",
				t->value_reg,
				t->unsigned_min_value,
				t->unsigned_max_value));
		}
	case HBC_TOKEN_TYPE_STORE_TO_ENVIRONMENT:
		{
			HbcStoreToEnvironmentToken *t = (HbcStoreToEnvironmentToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer,
				"env_store(r%d, %d, r%d)",
				t->env_register,
				t->slot_index,
				t->value_register));
		}
	case HBC_TOKEN_TYPE_FOR_IN_LOOP_INIT:
		{
			HbcForInLoopInitToken *t = (HbcForInLoopInitToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer,
				"forin_init(r%d, r%d, r%d, r%d)",
				t->obj_props_register,
				t->obj_register,
				t->iter_index_register,
				t->iter_size_register));
		}
	case HBC_TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER:
		{
			HbcForInLoopNextIterToken *t = (HbcForInLoopNextIterToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer,
				"forin_next(r%d, r%d, r%d, r%d, r%d)",
				t->next_value_register,
				t->obj_props_register,
				t->obj_register,
				t->iter_index_register,
				t->iter_size_register));
		}
	case HBC_TOKEN_TYPE_RESUME_GENERATOR:
		{
			HbcResumeGeneratorToken *t = (HbcResumeGeneratorToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer, "resume_gen(r%d, r%d)", t->result_out_reg, t->return_bool_out_reg));
		}
	case HBC_TOKEN_TYPE_SAVE_GENERATOR:
		{
			HbcSaveGeneratorToken *t = (HbcSaveGeneratorToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer, "save_gen(0x%08x)", t->address));
		}
	case HBC_TOKEN_TYPE_START_GENERATOR: return HBC_TO_RESULT (r_strbuf_append (buffer, "start_generator()"));
	case HBC_TOKEN_TYPE_CATCH_BLOCK_START:
		{
			HbcCatchBlockStartToken *t = (HbcCatchBlockStartToken *)token;
			return HBC_TO_RESULT (r_strbuf_appendf (buffer, "catch(r%d)", t->arg_register));
		}
	default:
		return HBC_TO_RESULT (r_strbuf_append (buffer, "/*token*/"));
	}
}

Result _hbc_token_string_to_string(HbcTokenString *ts, RStrBuf *out) {
	if (!ts || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_token_string_to_string: NULL");
	}
	HbcToken *cur = ts->head;
	HbcTokenType prev = (HbcTokenType) (-1);
	while (cur) {
		/* spacing rules: space before '(', none after '(' or '.' nor before ')' or '.' */
		if (cur != ts->head) {
			bool need_space;
			if (cur->type == HBC_TOKEN_TYPE_LEFT_PARENTHESIS) {
				need_space = true;
			} else if (cur->type == HBC_TOKEN_TYPE_RIGHT_PARENTHESIS || cur->type == HBC_TOKEN_TYPE_DOT_ACCESSOR) {
				need_space = false;
			} else {
				need_space = prev != HBC_TOKEN_TYPE_LEFT_PARENTHESIS && prev != HBC_TOKEN_TYPE_DOT_ACCESSOR;
			}
			if (need_space) {
				RETURN_IF_ERROR (r_strbuf_appendf (out, "%c", ' '));
			}
		}
		RETURN_IF_ERROR (_hbc_token_to_string (cur, out));
		prev = cur->type;
		cur = cur->next;
	}
	return SUCCESS_RESULT ();
}
