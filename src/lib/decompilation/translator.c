#include <hbc/decompilation/translator.h>
#include <hbc/opcodes.h>
#include <hbc/parser.h>
#include <ctype.h>
#include <string.h>
#include <hbc/decompilation/literals.h>

static Result add(TokenString *ts, Token *t) {
	if (!t) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "alloc token");
	}
	return _hbc_token_string_add_token (ts, t);
}

/* Validate register bounds against function register count */
static bool is_valid_register(u32 reg_num, const ParsedInstruction *insn) {
	if (!insn || !insn->inst) {
		return false;
	}
	if (!insn->hbc_reader) {
		return true;
	}
	if (insn->function_offset >= insn->hbc_reader->header.functionCount) {
		return false;
	}
	FunctionHeader *fh = &insn->hbc_reader->function_headers[insn->function_offset];
	return reg_num < fh->frameSize;
}

/* Get operand value with type validation */
static bool is_operand_register(const Instruction *inst, int idx) {
	if (!inst || idx < 0 || idx >= 6) {
		return false;
	}
	OperandType t = inst->operands[idx].operand_type;
	return t == OPERAND_TYPE_REG8 || t == OPERAND_TYPE_REG32;
}

static bool is_operand_addr(const Instruction *inst, int idx) {
	if (!inst || idx < 0 || idx >= 6) {
		return false;
	}
	OperandType t = inst->operands[idx].operand_type;
	return t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32;
}

static u32 get_operand_value(const ParsedInstruction *insn, int idx) {
	switch (idx) {
	case 0: return insn->arg1;
	case 1: return insn->arg2;
	case 2: return insn->arg3;
	case 3: return insn->arg4;
	case 4: return insn->arg5;
	default: return insn->arg6;
	}
}

static u32 compute_target_address(const ParsedInstruction *insn, int op_index) {
	u32 v = get_operand_value (insn, op_index);
	u32 base = insn->original_pos;
	if (_hbc_is_jump_instruction (insn->opcode)) {
		base += insn->inst->binary_size;
	}
	return base + v;
}

static const char *jump_cmp_operator(u8 op) {
	switch (op) {
	case OP_JEqual:
	case OP_JEqualLong: return "==";
	case OP_JNotEqual:
	case OP_JNotEqualLong: return "!=";
	case OP_JStrictEqual:
	case OP_JStrictEqualLong: return "===";
	case OP_JStrictNotEqual:
	case OP_JStrictNotEqualLong: return "!==";
	case OP_JLess:
	case OP_JLessLong:
	case OP_JLessN:
	case OP_JLessNLong: return "<";
	case OP_JNotLess:
	case OP_JNotLessLong:
	case OP_JNotLessN:
	case OP_JNotLessNLong: return ">=";
	case OP_JLessEqual:
	case OP_JLessEqualLong:
	case OP_JLessEqualN:
	case OP_JLessEqualNLong: return "<=";
	case OP_JNotLessEqual:
	case OP_JNotLessEqualLong:
	case OP_JNotLessEqualN:
	case OP_JNotLessEqualNLong: return ">";
	case OP_JGreater:
	case OP_JGreaterLong:
	case OP_JGreaterN:
	case OP_JGreaterNLong: return ">";
	case OP_JNotGreater:
	case OP_JNotGreaterLong:
	case OP_JNotGreaterN:
	case OP_JNotGreaterNLong: return "<=";
	case OP_JGreaterEqual:
	case OP_JGreaterEqualLong:
	case OP_JGreaterEqualN:
	case OP_JGreaterEqualNLong: return ">=";
	case OP_JNotGreaterEqual:
	case OP_JNotGreaterEqualLong:
	case OP_JNotGreaterEqualN:
	case OP_JNotGreaterEqualNLong: return "<";
	default: return NULL;
	}
}

/* Safe register token creation with validation */
static Token *reg_l_safe(const ParsedInstruction *insn, int idx) {
	if (!insn || !insn->inst) {
		return create_raw_token ("r?");
	}
	if (!is_operand_register (insn->inst, idx)) {
		return create_raw_token ("/*not_reg*/");
	}
	u32 r = get_operand_value (insn, idx);
	if (!is_valid_register (r, insn)) {
		hbc_debug_printf ("WARNING: Out-of-bounds register r%u (bytecode may be corrupted)\n", r);
	}
	return create_left_hand_reg_token ((int)r);
}

static Token *reg_r_safe(const ParsedInstruction *insn, int idx) {
	if (!insn || !insn->inst) {
		return create_raw_token ("r?");
	}
	if (!is_operand_register (insn->inst, idx)) {
		return create_raw_token ("/*not_reg*/");
	}
	u32 r = get_operand_value (insn, idx);
	if (!is_valid_register (r, insn)) {
		hbc_debug_printf ("WARNING: Out-of-bounds register r%u (bytecode may be corrupted)\n", r);
	}
	return create_right_hand_reg_token ((int)r);
}

static Token *num_token_u32(u32 v) {
	char buf[32];
	snprintf (buf, sizeof (buf), "%u", v);
	return create_raw_token (buf);
}

static Token *num_token_i32(i32 v) {
	char buf[32];
	snprintf (buf, sizeof (buf), "%d", v);
	return create_raw_token (buf);
}

static Token *double_token(u32 lo, u32 hi) {
	union {
		u64 u;
		double d;
	} u;
	u.u = ((u64)hi << 32) | (u64)lo;
	char buf[64];
	snprintf (buf, sizeof (buf), "%.*g", 15, u.d);
	return create_raw_token (buf);
}

static Token *quoted_string(HBCReader *r, u32 sid) {
	if (r && r->strings && sid < r->header.stringCount) {
		const char *s = r->strings[sid];
		size_t n = s? strlen (s): 0;
		StringBuffer sb;
		if (_hbc_string_buffer_init (&sb, n + 8).code != RESULT_SUCCESS) {
			return NULL;
		}
		_hbc_string_buffer_append (&sb, "\"");
		for (size_t i = 0; i < n; i++) {
			char c = s[i];
			if (c == '\\' || c == '"') {
				_hbc_string_buffer_append_char (&sb, '\\');
			}
			if ((unsigned char)c < 0x20) {
				char tmp[8];
				snprintf (tmp, sizeof (tmp), "\\x%02x", (unsigned char)c);
				_hbc_string_buffer_append (&sb, tmp);
			} else {
				_hbc_string_buffer_append_char (&sb, c);
			}
		}
		_hbc_string_buffer_append (&sb, "\"");
		Token *t = create_raw_token (sb.data? sb.data: "\"\"");
		_hbc_string_buffer_free (&sb);
		return t;
	}
	return create_raw_token ("\"\"");
}

static Token *unquoted_string(HBCReader *r, u32 sid) {
	if (r && r->strings && sid < r->header.stringCount) {
		const char *s = r->strings[sid];
		if (s) {
			return create_raw_token (s);
		}
	}
	return create_raw_token ("unknown");
}

/* Helper: reg = const-like value */
static Result emit_reg_assign(TokenString *out, const ParsedInstruction *insn, Token *val) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	return add (out, val);
}

/* Helper: reg1 op reg2 */
static Result emit_binary_op(TokenString *out, const ParsedInstruction *insn, const char *op) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
	RETURN_IF_ERROR (add (out, create_raw_token (op)));
	return add (out, reg_r_safe (insn, 2));
}

/* Helper: reg op value */
static Result emit_unary_op(TokenString *out, const ParsedInstruction *insn, const char *op) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, create_raw_token (op)));
	return add (out, reg_r_safe (insn, 1));
}

/* Load/Store patterns */
#define EMIT_LOAD_OP(name, bits) \
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0))); \
	RETURN_IF_ERROR (add (out, create_assignment_token ())); \
	RETURN_IF_ERROR (add (out, create_raw_token ("load_" #bits "("))); \
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1))); \
	RETURN_IF_ERROR (add (out, create_raw_token (", "))); \
	RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2))); \
	return add (out, create_raw_token (")"));

#define EMIT_STORE_OP(bits) \
	RETURN_IF_ERROR (add (out, create_raw_token ("store_" #bits "("))); \
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 0))); \
	RETURN_IF_ERROR (add (out, create_raw_token (", "))); \
	RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2))); \
	RETURN_IF_ERROR (add (out, create_raw_token (", "))); \
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1))); \
	return add (out, create_raw_token (")"));

/* ============ HANDLER FUNCTIONS ============ */

static Result h_mov(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	return add (out, reg_r_safe (insn, 1));
}

static Result h_const_undefined(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, create_raw_token ("undefined"));
}

static Result h_const_null(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, create_raw_token ("null"));
}

static Result h_const_true(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, create_raw_token ("true"));
}

static Result h_const_false(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, create_raw_token ("false"));
}

static Result h_const_zero(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, create_raw_token ("0"));
}

static Result h_const_uint8(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, num_token_u32 (insn->arg2));
}

static Result h_const_int(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, num_token_i32 ((i32)insn->arg2));
}

static Result h_const_double(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, double_token (insn->arg2, insn->arg3));
}

static Result h_const_string(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, quoted_string (insn->hbc_reader, insn->arg2));
}

static Result h_load_param(const ParsedInstruction *insn, TokenString *out) {
	char buf[32];
	snprintf (buf, sizeof (buf), "a%u", insn->arg2);
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	return add (out, create_raw_token (buf));
}

static Result h_arithmetic(const ParsedInstruction *insn, TokenString *out) {
	u8 op = insn->opcode;
	const char *opstr = (op == OP_Add || op == OP_AddN)? "+"
		: (op == OP_Sub || op == OP_SubN)? "-"
		: (op == OP_Mul || op == OP_MulN)? "*"
		: (op == OP_Div || op == OP_DivN)? "/"
		: "%";
	return emit_binary_op (out, insn, opstr);
}

static Result h_unary(const ParsedInstruction *insn, TokenString *out) {
	u8 op = insn->opcode;
	const char *opstr = (op == OP_Negate)? "-" : (op == OP_Not)? "!" : "~";
	return emit_unary_op (out, insn, opstr);
}

static Result h_strict_eq(const ParsedInstruction *insn, TokenString *out) {
	return emit_binary_op (out, insn, " === ");
}

static Result h_strict_neq(const ParsedInstruction *insn, TokenString *out) {
	return emit_binary_op (out, insn, " !== ");
}

static Result h_select_object(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, create_raw_token ("select_object(")));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
	RETURN_IF_ERROR (add (out, create_raw_token (", ")));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 2)));
	return add (out, create_raw_token (")"));
}

static Result h_reify_arguments(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, create_raw_token ("arguments"));
}

static Result h_catch(const ParsedInstruction *insn, TokenString *out) {
	if (is_operand_register (insn->inst, 0)) {
		return add (out, create_catch_block_start_token ((int)get_operand_value (insn, 0)));
	}
	return add (out, create_raw_token ("/*catch non-reg*/"));
}

static Result h_create_environment(const ParsedInstruction *insn, TokenString *out) {
	if (is_operand_register (insn->inst, 0)) {
		return add (out, create_new_environment_token ((int)get_operand_value (insn, 0)));
	}
	return add (out, create_raw_token ("/*new_env_invalid*/"));
}

static Result h_create_inner_environment(const ParsedInstruction *insn, TokenString *out) {
	if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 1)) {
		return add (out, create_new_inner_environment_token (
			(int)get_operand_value (insn, 0),
			(int)get_operand_value (insn, 1),
			(int)get_operand_value (insn, 2)));
	}
	return add (out, create_raw_token ("/*new_inner_env_invalid*/"));
}

static Result h_create_closure(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (
		get_operand_value (insn, 2), NULL);
	if (!t) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
	}
	t->environment_id = (int)get_operand_value (insn, 1);
	t->is_closure = true;
	return add (out, (Token *)t);
}

static Result h_create_generator_closure(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (
		get_operand_value (insn, 2), NULL);
	if (!t) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
	}
	t->environment_id = (int)get_operand_value (insn, 1);
	t->is_closure = true;
	t->is_generator = true;
	return add (out, (Token *)t);
}

static Result h_create_generator(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (
		get_operand_value (insn, 2), NULL);
	if (!t) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
	}
	t->environment_id = (int)get_operand_value (insn, 1);
	t->is_generator = true;
	return add (out, (Token *)t);
}

static Result h_new_object(const ParsedInstruction *insn, TokenString *out) {
	return emit_reg_assign (out, insn, create_raw_token ("{}"));
}

static Result h_new_array(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, create_raw_token ("new Array(")));
	RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
	return add (out, create_raw_token (")"));
}

static Result h_get_by_id(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
	u32 sid = insn->arg4;
	const char *s = NULL;
	if (insn->hbc_reader && insn->hbc_reader->strings && sid < insn->hbc_reader->header.stringCount) {
		s = insn->hbc_reader->strings[sid];
	}
	bool ident = true;
	if (!s || !*s) {
		ident = false;
	} else {
		if (!(isalpha ((unsigned char)*s) || *s == '_' || *s == '$')) {
			ident = false;
		}
		for (const char *p = s + 1; ident && *p; p++) {
			ident = (isalnum ((unsigned char)*p) || *p == '_' || *p == '$');
		}
	}
	if (ident) {
		RETURN_IF_ERROR (add (out, create_dot_accessor_token ()));
		return add (out, create_raw_token (s));
	} else {
		RETURN_IF_ERROR (add (out, create_raw_token ("[")));
		RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, sid)));
		return add (out, create_raw_token ("]"));
	}
}

static Result h_get_by_val(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
	RETURN_IF_ERROR (add (out, create_raw_token ("[")));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 2)));
	return add (out, create_raw_token ("]"));
}

static Result h_put_by_id(const ParsedInstruction *insn, TokenString *out, u32 sid_arg_idx) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	u32 sid = (sid_arg_idx == 3)? insn->arg3 : insn->arg4;
	const char *s = NULL;
	if (insn->hbc_reader && insn->hbc_reader->strings && sid < insn->hbc_reader->header.stringCount) {
		s = insn->hbc_reader->strings[sid];
	}
	if (s && _hbc_is_js_identifier (s)) {
		RETURN_IF_ERROR (add (out, create_dot_accessor_token ()));
		RETURN_IF_ERROR (add (out, create_raw_token (s)));
	} else {
		RETURN_IF_ERROR (add (out, create_raw_token ("[")));
		RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, sid)));
		RETURN_IF_ERROR (add (out, create_raw_token ("]")));
	}
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	return add (out, reg_r_safe (insn, 1));
}

static Result h_put_by_val(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_raw_token ("[")));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
	RETURN_IF_ERROR (add (out, create_raw_token ("]")));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	return add (out, reg_r_safe (insn, 2));
}

static Result h_put_own_getter_setter_by_val(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_raw_token ("[")));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
	RETURN_IF_ERROR (add (out, create_raw_token ("] = {getter: ")));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 2)));
	RETURN_IF_ERROR (add (out, create_raw_token (", setter: ")));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 3)));
	return add (out, create_raw_token ("}"));
}

static Result h_call_builtin(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, create_raw_token ("builtin_")));
	RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
	RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
	if (insn->arg3 > 0) {
		RETURN_IF_ERROR (add (out, create_raw_token ("/*")));
		RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg3)));
		RETURN_IF_ERROR (add (out, create_raw_token ("args*/")));
	}
	return add (out, create_right_parenthesis_token ());
}

static Result h_call_direct(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	RETURN_IF_ERROR (add (out, create_raw_token ("fn_")));
	RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg4)));
	RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
	RETURN_IF_ERROR (add (out, create_raw_token ("/*argc:")));
	RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg3)));
	RETURN_IF_ERROR (add (out, create_raw_token ("*/")));
	return add (out, create_right_parenthesis_token ());
}

static Result h_jump_condition(const ParsedInstruction *insn, TokenString *out, bool negate) {
	(void)negate; /* unused */
	const char *cmp = jump_cmp_operator (insn->opcode);
	if (!cmp) {
		return add (out, create_raw_token ("/*jump_cmp*/"));
	}
	i32 rel = (i32)get_operand_value (insn, 0);
	u32 target = compute_target_address (insn, 0);
	if (rel > 0) {
		RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
		RETURN_IF_ERROR (add (out, create_raw_token ("!")));
		RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
	} else {
		RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
	}
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
	RETURN_IF_ERROR (add (out, create_raw_token (cmp)));
	RETURN_IF_ERROR (add (out, reg_r_safe (insn, 2)));
	if (rel > 0) {
		RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
	}
	return SUCCESS_RESULT ();
}

static Result h_get_pname_list(const ParsedInstruction *insn, TokenString *out) {
	if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 1) &&
		is_operand_register (insn->inst, 2) && is_operand_register (insn->inst, 3)) {
		return add (out, create_for_in_loop_init_token (
			(int)get_operand_value (insn, 0), (int)get_operand_value (insn, 1),
			(int)get_operand_value (insn, 2), (int)get_operand_value (insn, 3)));
	}
	return add (out, create_raw_token ("/*forin_init_invalid*/"));
}

static Result h_get_next_pname(const ParsedInstruction *insn, TokenString *out) {
	if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 1) &&
		is_operand_register (insn->inst, 2) && is_operand_register (insn->inst, 3) &&
		is_operand_register (insn->inst, 4)) {
		return add (out, create_for_in_loop_next_iter_token (
			(int)get_operand_value (insn, 0), (int)get_operand_value (insn, 1),
			(int)get_operand_value (insn, 2), (int)get_operand_value (insn, 3),
			(int)get_operand_value (insn, 4)));
	}
	return add (out, create_raw_token ("/*forin_next_invalid*/"));
}

static Result h_create_async_closure(const ParsedInstruction *insn, TokenString *out) {
	RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
	RETURN_IF_ERROR (add (out, create_assignment_token ()));
	FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (
		get_operand_value (insn, 2), NULL);
	if (!t) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
	}
	t->environment_id = (int)get_operand_value (insn, 1);
	t->is_async = true;
	t->is_closure = true;
	return add (out, (Token *)t);
}

static Result h_load_i8(const ParsedInstruction *insn, TokenString *out) {
	EMIT_LOAD_OP(load, i8);
}

static Result h_load_u8(const ParsedInstruction *insn, TokenString *out) {
	EMIT_LOAD_OP(load, u8);
}

static Result h_load_i16(const ParsedInstruction *insn, TokenString *out) {
	EMIT_LOAD_OP(load, i16);
}

static Result h_load_u16(const ParsedInstruction *insn, TokenString *out) {
	EMIT_LOAD_OP(load, u16);
}

static Result h_load_i32(const ParsedInstruction *insn, TokenString *out) {
	EMIT_LOAD_OP(load, i32);
}

static Result h_load_u32(const ParsedInstruction *insn, TokenString *out) {
	EMIT_LOAD_OP(load, u32);
}

static Result h_store_8(const ParsedInstruction *insn, TokenString *out) {
	EMIT_STORE_OP(8);
}

static Result h_store_16(const ParsedInstruction *insn, TokenString *out) {
	EMIT_STORE_OP(16);
}

static Result h_store_32(const ParsedInstruction *insn, TokenString *out) {
	EMIT_STORE_OP(32);
}

/* ============ MAIN DISPATCHER ============ */

Result _hbc_translate_instruction_to_tokens(const ParsedInstruction *insn_c, TokenString *out) {
	if (!insn_c || !out || !insn_c->inst) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "translate: bad args");
	}
	ParsedInstruction *insn = (ParsedInstruction *)insn_c;
	RETURN_IF_ERROR (_hbc_token_string_init (out, insn));

	const u8 op = insn->opcode;
	
	/* Dispatch by opcode */
	switch (op) {
	case OP_Mov:
	case OP_MovLong:
		return h_mov (insn, out);
	case OP_LoadConstUndefined:
		return h_const_undefined (insn, out);
	case OP_LoadConstNull:
		return h_const_null (insn, out);
	case OP_LoadConstTrue:
		return h_const_true (insn, out);
	case OP_LoadConstFalse:
		return h_const_false (insn, out);
	case OP_LoadConstZero:
		return h_const_zero (insn, out);
	case OP_LoadConstUInt8:
		return h_const_uint8 (insn, out);
	case OP_LoadConstInt:
		return h_const_int (insn, out);
	case OP_LoadConstDouble:
		return h_const_double (insn, out);
	case OP_LoadConstString:
	case OP_LoadConstStringLongIndex:
		return h_const_string (insn, out);
	case OP_LoadParam:
	case OP_LoadParamLong:
		return h_load_param (insn, out);
	case OP_Add:
	case OP_AddN:
	case OP_Sub:
	case OP_SubN:
	case OP_Mul:
	case OP_MulN:
	case OP_Div:
	case OP_DivN:
	case OP_Mod:
		return h_arithmetic (insn, out);
	case OP_Negate:
	case OP_Not:
	case OP_BitNot:
		return h_unary (insn, out);
	case OP_StrictEq:
		return h_strict_eq (insn, out);
	case OP_StrictNeq:
		return h_strict_neq (insn, out);
	case OP_SelectObject:
		return h_select_object (insn, out);
	case OP_ReifyArguments:
		return h_reify_arguments (insn, out);
	case OP_Catch:
		return h_catch (insn, out);
	case OP_CreateEnvironment:
		return h_create_environment (insn, out);
	case OP_CreateInnerEnvironment:
		return h_create_inner_environment (insn, out);
	case OP_CreateClosure:
	case OP_CreateClosureLongIndex:
		return h_create_closure (insn, out);
	case OP_CreateGeneratorClosure:
	case OP_CreateGeneratorClosureLongIndex:
		return h_create_generator_closure (insn, out);
	case OP_CreateGenerator:
	case OP_CreateGeneratorLongIndex:
		return h_create_generator (insn, out);
	case OP_NewObject:
		return h_new_object (insn, out);
	case OP_NewArray:
		return h_new_array (insn, out);
	case OP_GetById:
	case OP_GetByIdShort:
	case OP_GetByIdLong:
		return h_get_by_id (insn, out);
	case OP_GetByVal:
		return h_get_by_val (insn, out);
	case OP_PutById:
	case OP_PutByIdLong:
		return h_put_by_id (insn, out, 2);
	case OP_PutOwnByVal:
		return h_put_by_val (insn, out);
	case OP_PutNewOwnById:
	case OP_PutNewOwnByIdShort:
	case OP_PutNewOwnByIdLong:
		return h_put_by_id (insn, out, 2);
	case OP_TryPutById:
	case OP_TryPutByIdLong:
		return h_put_by_id (insn, out, 3);
	case OP_PutNewOwnNEById:
	case OP_PutNewOwnNEByIdLong:
		return h_put_by_id (insn, out, 3);
	case OP_PutOwnGetterSetterByVal:
		return h_put_own_getter_setter_by_val (insn, out);
	case OP_GetPNameList:
		return h_get_pname_list (insn, out);
	case OP_GetNextPName:
		return h_get_next_pname (insn, out);
	case OP_CallBuiltin:
	case OP_CallBuiltinLong:
		return h_call_builtin (insn, out);
	case OP_GetBuiltinClosure:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			FunctionTableIndexToken *t = (FunctionTableIndexToken *)
				create_function_table_index_token (get_operand_value (insn, 1), NULL);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
			}
			t->is_builtin = true;
			t->is_closure = true;
			return add (out, (Token *)t);
		}
	case OP_CallDirect:
	case OP_CallDirectLongIndex:
		return h_call_direct (insn, out);
	case OP_GetArgumentsPropByVal:
		RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
		RETURN_IF_ERROR (add (out, create_assignment_token ()));
		RETURN_IF_ERROR (add (out, create_raw_token ("arguments[")));
		RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
		return add (out, create_raw_token ("]"));
	case OP_GetArgumentsLength:
		return emit_reg_assign (out, insn, create_raw_token ("arguments.length"));
	case OP_GetNewTarget:
		return emit_reg_assign (out, insn, create_raw_token ("new.target"));
	case OP_LoadThisNS:
		return emit_reg_assign (out, insn, create_raw_token ("this"));
	case OP_CoerceThisNS:
		RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
		RETURN_IF_ERROR (add (out, create_assignment_token ()));
		RETURN_IF_ERROR (add (out, create_raw_token ("coerce_this(")));
		RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
		return add (out, create_raw_token (")"));
	case OP_CreateThis:
		RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
		RETURN_IF_ERROR (add (out, create_assignment_token ()));
		RETURN_IF_ERROR (add (out, create_raw_token ("new_this(")));
		RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
		return add (out, create_raw_token (")"));
	case OP_NewObjectWithParent:
		RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
		RETURN_IF_ERROR (add (out, create_assignment_token ()));
		RETURN_IF_ERROR (add (out, create_raw_token ("new_obj_with_parent(")));
		RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
		return add (out, create_raw_token (")"));
	case OP_Unreachable:
		return add (out, create_raw_token ("unreachable()"));
	case OP_Debugger:
		return add (out, create_raw_token ("debugger"));
	case OP_AsyncBreakCheck:
		return add (out, create_raw_token ("async_break_check()"));
	case OP_ProfilePoint:
		RETURN_IF_ERROR (add (out, create_raw_token ("profile_point(")));
		RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg1)));
		return add (out, create_raw_token (")"));
	case OP_ThrowIfEmpty:
		RETURN_IF_ERROR (add (out, create_raw_token ("throw_if_empty(")));
		return add (out, reg_r_safe (insn, 0));
	case OP_ThrowIfUndefinedInst:
		return add (out, create_raw_token ("throw_if_undefined_inst()"));
	case OP_DirectEval:
		RETURN_IF_ERROR (add (out, reg_l_safe (insn, 0)));
		RETURN_IF_ERROR (add (out, create_assignment_token ()));
		RETURN_IF_ERROR (add (out, create_raw_token ("eval(")));
		RETURN_IF_ERROR (add (out, reg_r_safe (insn, 1)));
		return add (out, create_raw_token (")"));
	case OP_DeclareGlobalVar:
		RETURN_IF_ERROR (add (out, create_raw_token ("declare extern var ")));
		return add (out, unquoted_string (insn->hbc_reader, insn->arg1));
	case OP_ThrowIfHasRestrictedGlobalProperty:
		RETURN_IF_ERROR (add (out, create_raw_token ("throw_if_restricted_prop(")));
		RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, insn->arg1)));
		return add (out, create_raw_token (")"));
	case OP_SwitchImm:
		RETURN_IF_ERROR (add (out, create_raw_token ("switch(")));
		RETURN_IF_ERROR (add (out, reg_r_safe (insn, 0)));
		RETURN_IF_ERROR (add (out, create_raw_token (") /*tableSize:")));
		RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
		return add (out, create_raw_token (")"));
	case OP_JLessN:
	case OP_JLessNLong:
	case OP_JNotLessN:
	case OP_JNotLessNLong:
	case OP_JGreaterN:
	case OP_JGreaterNLong:
	case OP_JNotGreaterN:
	case OP_JNotGreaterNLong:
	case OP_JLessEqualN:
	case OP_JLessEqualNLong:
	case OP_JNotLessEqualN:
	case OP_JNotLessEqualNLong:
	case OP_JGreaterEqualN:
	case OP_JGreaterEqualNLong:
	case OP_JNotGreaterEqualN:
	case OP_JNotGreaterEqualNLong:
		return h_jump_condition (insn, out, false);
	case OP_Loadi8:
		return h_load_i8 (insn, out);
	case OP_Loadu8:
		return h_load_u8 (insn, out);
	case OP_Loadi16:
		return h_load_i16 (insn, out);
	case OP_Loadu16:
		return h_load_u16 (insn, out);
	case OP_Loadi32:
		return h_load_i32 (insn, out);
	case OP_Loadu32:
		return h_load_u32 (insn, out);
	case OP_Store8:
		return h_store_8 (insn, out);
	case OP_Store16:
		return h_store_16 (insn, out);
	case OP_Store32:
		return h_store_32 (insn, out);
	case OP_DebuggerCheck:
		return add (out, create_raw_token ("debugger_check()"));
	case OP_CreateAsyncClosure:
	case OP_CreateAsyncClosureLongIndex:
		return h_create_async_closure (insn, out);
	case OP_Add32:
	case OP_Sub32:
	case OP_Mul32:
	case OP_Divi32:
	case OP_Divu32:
		{
			const char *opstr = (op == OP_Add32)? " +i32 "
				: (op == OP_Sub32)? " -i32 "
				: (op == OP_Mul32)? " *i32 "
				: (op == OP_Divi32)? " /i32 "
				: " /u32 ";
			return emit_binary_op (out, insn, opstr);
		}
	default:
		{
			if (!insn->inst->name || strcmp (insn->inst->name, "Unknown") == 0) {
				char buf[96];
				u32 skipped = insn->arg1;
				if (skipped) {
					snprintf (buf, sizeof (buf), "/* unknown opcode 0x%02x (%u bytes skipped) */", op, skipped);
				} else {
					snprintf (buf, sizeof (buf), "/* unknown opcode 0x%02x */", op);
				}
				Token *t = create_raw_token (buf);
				if (!t) {
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
				}
				RETURN_IF_ERROR (add (out, t));
				break;
			}

			/* Generic compare-jump fallback (covers variants not explicitly handled above). */
			const char *cmp = jump_cmp_operator (op);
			if (cmp && is_operand_addr (insn->inst, 0) && 
				is_operand_register (insn->inst, 1) && is_operand_register (insn->inst, 2)) {
				return h_jump_condition (insn, out, false);
			}

			/* Fallback: emit mnemonic as comment */
			StringBuffer sb;
			_hbc_string_buffer_init (&sb, 64);
			_hbc_string_buffer_append (&sb, "/* ");
			_hbc_string_buffer_append (&sb, insn->inst->name);
			_hbc_string_buffer_append (&sb, " */");
			Token *t = create_raw_token (sb.data? sb.data: "/* insn */");
			_hbc_string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			return add (out, t);
		}
	}
}
