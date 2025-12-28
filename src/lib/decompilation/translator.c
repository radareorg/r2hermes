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
	/* frameSize holds register count; max registers = frameSize */
	if (!insn->hbc_reader) {
		return true; /* can't validate without reader */
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
		/* Out-of-bounds register: show normally but warn in debug mode.
		 * This is a rare error condition indicating bytecode corruption
		 * or a parser bug, not a normal feature. */
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
		/* Out-of-bounds register: show normally but warn in debug mode.
		 * This is a rare error condition indicating bytecode corruption
		 * or a parser bug, not a normal feature. */
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
	/* Print with minimal precision; avoid locale issues */
	snprintf (buf, sizeof (buf), "%.*g", 15, u.d);
	return create_raw_token (buf);
}

static Token *quoted_string(HBCReader *r, u32 sid) {
	if (r && r->strings && sid < r->header.stringCount) {
		const char *s = r->strings[sid];
		size_t n = s? strlen (s): 0;
		/* naive escape for quotes and backslashes */
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

Result _hbc_translate_instruction_to_tokens(const ParsedInstruction *insn_c, TokenString *out) {
	if (!insn_c || !out || !insn_c->inst) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "translate: bad args");
	}
	ParsedInstruction *insn = (ParsedInstruction *)insn_c; /* for storing pointer in token_string */
	RETURN_IF_ERROR (_hbc_token_string_init (out, insn));

	const u8 op = insn->opcode;
	switch (op) {
	case OP_Mov:
	case OP_MovLong:
		{
			/* dest <- src */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			break;
		}
	case OP_LoadConstUndefined:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("undefined")));
			break;
		}
	case OP_LoadConstNull:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("null")));
			break;
		}
	case OP_LoadConstTrue:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("true")));
			break;
		}
	case OP_LoadConstFalse:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("false")));
			break;
		}
	case OP_LoadConstZero:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("0")));
			break;
		}
	case OP_LoadConstUInt8:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			break;
		}
	case OP_LoadConstInt:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, num_token_i32 ((i32)insn->arg2)));
			break;
		}
	case OP_LoadConstDouble:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, double_token (insn->arg2, insn->arg3)));
			break;
		}
	case OP_LoadConstString:
	case OP_LoadConstStringLongIndex:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, insn->arg2)));
			break;
		}
	case OP_LoadParam:
	case OP_LoadParamLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			/* a<idx> */
			char buf[32];
			snprintf (buf, sizeof (buf), "a%u", insn->arg2);
			RETURN_IF_ERROR (add (out, create_raw_token (buf)));
			break;
		}
	case OP_Add:
	case OP_AddN:
	case OP_Sub:
	case OP_SubN:
	case OP_Mul:
	case OP_MulN:
	case OP_Div:
	case OP_DivN:
	case OP_Mod:
		{
		const char *opstr = (op == OP_Add || op == OP_AddN)? "+": (op == OP_Sub || op == OP_SubN)? "-"
			: (op == OP_Mul || op == OP_MulN)? "*"
			: (op == OP_Div || op == OP_DivN)? "/"
													: "%";
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (opstr)));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Negate:
	case OP_Not:
	case OP_BitNot:
		{
			const char *opstr = (op == OP_Negate)? "-": (op == OP_Not)? "!"
									: "~";
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token (opstr)));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			break;
		}
	case OP_StrictEq:
		{
			/* rD = rB === rC */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" === ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_StrictNeq:
		{
			/* rD = rB !== rC */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" !== ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_SelectObject:
		{
			/* rD = select_object (obj1, obj2) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("select_object(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_ReifyArguments:
		{
			/* rD = arguments */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("arguments")));
			break;
		}
	case OP_Catch:
		{
			/* catch (rN) marker */
			if (is_operand_register (insn->inst, 0)) {
				RETURN_IF_ERROR (add (out, create_catch_block_start_token ((int)get_operand_value (insn, 0))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*catch non-reg*/")));
			}
			break;
		}
	case OP_CreateEnvironment:
		{
			/* Create a new environment object in rD */
			if (is_operand_register (insn->inst, 0)) {
				RETURN_IF_ERROR (add (out, create_new_environment_token ((int)get_operand_value (insn_c, 0))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*new_env_invalid*/")));
			}
			break;
		}
	case OP_CreateInnerEnvironment:
		{
		if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 1)) {
				RETURN_IF_ERROR (add (out, create_new_inner_environment_token ((int)get_operand_value (insn_c, 0), (int)get_operand_value (insn_c, 1), (int)get_operand_value (insn_c, 2))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*new_inner_env_invalid*/")));
			}
			break;
		}
	case OP_CreateClosure:
	case OP_CreateClosureLongIndex:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (get_operand_value (insn_c, 2), NULL);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
			}
			t->environment_id = (int)get_operand_value (insn_c, 1);
			t->is_closure = true;
			RETURN_IF_ERROR (add (out, (Token *)t));
			break;
		}
	case OP_CreateGeneratorClosure:
	case OP_CreateGeneratorClosureLongIndex:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (get_operand_value (insn_c, 2), NULL);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
			}
			t->environment_id = (int)get_operand_value (insn_c, 1);
			t->is_closure = true;
			t->is_generator = true;
			RETURN_IF_ERROR (add (out, (Token *)t));
			break;
		}
	case OP_CreateGenerator:
	case OP_CreateGeneratorLongIndex:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (get_operand_value (insn_c, 2), NULL);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
			}
			t->environment_id = (int)get_operand_value (insn_c, 1);
			t->is_generator = true;
			RETURN_IF_ERROR (add (out, (Token *)t));
			break;
		}
	case OP_NewObject:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("{}")));
			break;
		}
	case OP_NewArray:
		{
			/* rD = new Array (count) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("new Array(")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_GetById:
	case OP_GetByIdShort:
	case OP_GetByIdLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			u32 sid = insn->arg4;
			const char *s = NULL;
		if (insn->hbc_reader && insn->hbc_reader->strings && sid < insn->hbc_reader->header.stringCount) {
				s = insn->hbc_reader->strings[sid];
			}
			bool ident = true;
		if (!s || !*s) {
				ident = false;
			} else {
			if (! (isalpha ((unsigned char)*s) || *s == '_' || *s == '$')) {
					ident = false;
				}
			for (const char *p = s + 1; ident && *p; p++) {
				ident = (isalnum ((unsigned char)*p) || *p == '_' || *p == '$');
				}
			}
			if (ident) {
				RETURN_IF_ERROR (add (out, create_dot_accessor_token ()));
				RETURN_IF_ERROR (add (out, create_raw_token (s)));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("[")));
				RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, sid)));
				RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			}
			break;
		}
	case OP_GetByVal:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			break;
		}
	case OP_TryGetById:
	case OP_TryGetByIdLong:
		{
			/* rD = try_get (obj.prop) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			_hbc_string_buffer_init (&sb, 48);
			_hbc_string_buffer_append (&sb, "try_get(");
			char nb[16];
			snprintf (nb, sizeof (nb), "r%u", (unsigned)insn->arg2);
			_hbc_string_buffer_append (&sb, nb);
			_hbc_format_property_from_string_id (insn->hbc_reader, (op == OP_TryGetById)? insn->arg4: insn->arg4, &sb);
			_hbc_string_buffer_append (&sb, ")");
			Token *t = create_raw_token (sb.data? sb.data: "try_get(r0)");
			_hbc_string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	case OP_PutNewOwnByIdShort:
	case OP_PutNewOwnById:
	case OP_PutNewOwnByIdLong:
		{
			/* obj.name = value (prefer dot accessor) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			u32 sid = (op == OP_PutNewOwnByIdShort)? insn->arg3: (op == OP_PutNewOwnById)? insn->arg3
												: insn->arg4;
		const char *s = (insn->hbc_reader && insn->hbc_reader->strings && sid < insn->hbc_reader->header.stringCount)? insn->hbc_reader->strings[sid]: NULL;
		if (s && _hbc_is_js_identifier (s)) {
				RETURN_IF_ERROR (add (out, create_dot_accessor_token ()));
				RETURN_IF_ERROR (add (out, create_raw_token (s)));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("[")));
				RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, sid)));
				RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			}
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			break;
		}
	case OP_PutOwnByIndex:
	case OP_PutOwnByIndexL:
		{
			/* obj[idx] = value */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_PutByVal:
		{
			/* rObj[rKey] = rVal */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0))); /* use LHS token for consistency */
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_PutById:
	case OP_PutByIdLong:
		{
			/* rObj["name"] = rVal */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			u32 sid = (op == OP_PutById)? insn->arg4: insn->arg4;
			RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, sid)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			break;
		}
	case OP_Ret:
		{
			RETURN_IF_ERROR (add (out, create_return_directive_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			break;
		}
	case OP_Throw:
		{
			RETURN_IF_ERROR (add (out, create_throw_directive_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			break;
		}
	case OP_IteratorBegin:
		{
			/* rD = iterator_begin (obj) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("iterator_begin(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_IteratorNext:
		{
			/* rD = iterator_next (iter, state) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("iterator_next(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_IteratorClose:
		{
			/* iterator_close (iter, hint) */
			RETURN_IF_ERROR (add (out, create_raw_token ("iterator_close(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	/* Generators */
	case OP_StartGenerator:
		{
			RETURN_IF_ERROR (add (out, create_start_generator_token ()));
			break;
		}
	case OP_ResumeGenerator:
		{
			/* args: result_out, return_bool_out */
		if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 1)) {
				RETURN_IF_ERROR (add (out, create_resume_generator_token ((int)insn->arg1, (int)insn->arg2)));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*resume_gen_invalid*/")));
			}
			break;
		}
	case OP_CompleteGenerator:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("complete_generator()")));
			break;
		}
	case OP_SaveGenerator:
	case OP_SaveGeneratorLong:
		{
			u32 target = compute_target_address (insn, 0);
			RETURN_IF_ERROR (add (out, create_save_generator_token (target)));
			break;
		}
	case OP_GetEnvironment:
		{
			if (is_operand_register (insn->inst, 0)) {
				RETURN_IF_ERROR (add (out, create_get_environment_token ((int)get_operand_value (insn_c, 0), (int)get_operand_value (insn_c, 1))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*get_env_invalid*/")));
			}
			break;
		}
	case OP_StoreToEnvironment:
	case OP_StoreToEnvironmentL:
		{
		if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 2)) {
				RETURN_IF_ERROR (add (out, create_store_to_environment_token ((int)get_operand_value (insn_c, 0), (int)get_operand_value (insn_c, 1), (int)get_operand_value (insn_c, 2))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*env_store_invalid*/")));
			}
			break;
		}
	case OP_StoreNPToEnvironment:
	case OP_StoreNPToEnvironmentL:
		{
			/* env[slot] = value (NP variant) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_GetGlobalObject:
		{
			/* rD = globalThis */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("globalThis")));
			break;
		}
	case OP_LoadFromEnvironment:
	case OP_LoadFromEnvironmentL:
		{
			/* rD = load_from_env (envReg, slot) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			if (is_operand_register (insn->inst, 1)) {
				RETURN_IF_ERROR (add (out, create_load_from_environment_token ((int)get_operand_value (insn_c, 1), (int)get_operand_value (insn_c, 2))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*env_load_invalid*/")));
			}
			break;
		}
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			Result r = _hbc_string_buffer_init (&sb, 128);
			if (r.code != RESULT_SUCCESS) {
				return r;
			}
			r = _hbc_format_object_literal (insn->hbc_reader, insn->arg2, insn->arg3, insn->arg4, insn->arg5, &sb, LITERALS_PRETTY_AUTO, false);
		Token *t = create_raw_token ((r.code == RESULT_SUCCESS && sb.data)? sb.data: "{ /*object*/ }");
			_hbc_string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	case OP_NewArrayWithBuffer:
	case OP_NewArrayWithBufferLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			Result r = _hbc_string_buffer_init (&sb, 128);
			if (r.code != RESULT_SUCCESS) {
				return r;
			}
			r = _hbc_format_array_literal (insn->hbc_reader, insn->arg3, insn->arg4, &sb, LITERALS_PRETTY_AUTO, false);
		Token *t = create_raw_token ((r.code == RESULT_SUCCESS && sb.data)? sb.data: "[ /*array*/ ]");
			_hbc_string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	case OP_Call1:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			break;
		}
	case OP_Call2:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 3)));
			RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			break;
		}
	case OP_Call3:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 3)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 4)));
			RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			break;
		}
	case OP_Call4:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 3)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 4)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 5)));
			RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			break;
		}
	case OP_Call:
	case OP_CallLong:
	case OP_Construct:
	case OP_ConstructLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			if (true) {
				char buf2[32];
				snprintf (buf2, sizeof (buf2), ", /*argc:%u*/", (unsigned)insn->arg3);
				RETURN_IF_ERROR (add (out, create_raw_token (buf2)));
			}
			RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			break;
		}
	/* Comparison operators */
	case OP_Eq:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" == ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Neq:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" != ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Less:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" < ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_LessEq:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" <= ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Greater:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" > ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_GreaterEq:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" >= ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	/* Bitwise operators */
	case OP_LShift:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" << ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_RShift:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" >> ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_URshift:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" >>> ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_BitAnd:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" & ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_BitXor:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" ^ ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_BitOr:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" | ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	/* Increment/Decrement */
	case OP_Inc:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" + 1")));
			break;
		}
	case OP_Dec:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" - 1")));
			break;
		}
	/* Type operations */
	case OP_TypeOf:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("typeof ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			break;
		}
	case OP_InstanceOf:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" instanceof ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_IsIn:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" in ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	/* Type conversion */
	case OP_ToNumber:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("Number(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_ToNumeric:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("to_numeric(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_ToInt32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("to_int32(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_AddEmptyString:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("String(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	/* Delete operations */
	case OP_DelById:
	case OP_DelByIdLong:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("delete ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			u32 sid = insn->arg2;
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
			break;
		}
	case OP_DelByVal:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("delete ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			break;
		}
	/* Regex and special operations */
	case OP_CreateRegExp:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("new RegExp(")));
			RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, insn->arg3)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_LoadConstEmpty:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("empty")));
			break;
		}
	case OP_LoadConstBigInt:
	case OP_LoadConstBigIntLongIndex:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token ("n")));
			break;
		}
	/* Jump instructions */
	case OP_Jmp:
	case OP_JmpLong:
		{
			i32 rel = (i32)get_operand_value (insn_c, 0);
			u32 target = compute_target_address (insn, 0);
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
				RETURN_IF_ERROR (add (out, create_raw_token ("false")));
			} else {
				RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
				RETURN_IF_ERROR (add (out, create_raw_token ("true")));
			}
			break;
		}
	case OP_JmpTrue:
	case OP_JmpTrueLong:
		{
			i32 rel = (i32)get_operand_value (insn_c, 0);
			u32 target = compute_target_address (insn, 0);
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
				RETURN_IF_ERROR (add (out, create_raw_token ("!")));
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			} else {
				RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			}
			break;
		}
	case OP_JmpFalse:
	case OP_JmpFalseLong:
		{
			i32 rel = (i32)get_operand_value (insn_c, 0);
			u32 target = compute_target_address (insn, 0);
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			} else {
				RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
				RETURN_IF_ERROR (add (out, create_raw_token ("!")));
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			}
			break;
		}
	case OP_JmpUndefined:
	case OP_JmpUndefinedLong:
		{
			i32 rel = (i32)get_operand_value (insn_c, 0);
			u32 target = compute_target_address (insn, 0);
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
				RETURN_IF_ERROR (add (out, create_raw_token ("!==")));
				RETURN_IF_ERROR (add (out, create_raw_token ("undefined")));
			} else {
				RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
				RETURN_IF_ERROR (add (out, create_raw_token ("===")));
				RETURN_IF_ERROR (add (out, create_raw_token ("undefined")));
			}
			break;
		}
	/* Conditional jump instructions */
	case OP_JLess:
	case OP_JLessLong:
	case OP_JNotLess:
	case OP_JNotLessLong:
	case OP_JGreater:
	case OP_JGreaterLong:
	case OP_JNotGreater:
	case OP_JNotGreaterLong:
	case OP_JEqual:
	case OP_JEqualLong:
	case OP_JNotEqual:
	case OP_JNotEqualLong:
	case OP_JStrictEqual:
	case OP_JStrictEqualLong:
	case OP_JStrictNotEqual:
	case OP_JStrictNotEqualLong:
		{
			const char *cmp = jump_cmp_operator (op);
			if (!cmp) {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*jump_cmp*/")));
				break;
			}
			i32 rel = (i32)get_operand_value (insn_c, 0);
			u32 target = compute_target_address (insn, 0);
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
				RETURN_IF_ERROR (add (out, create_raw_token ("!")));
				RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			} else {
				RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
			}
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (cmp)));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			}
			break;
		}
	/* 32-bit ops */
	case OP_Add32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" +i32 ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Sub32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" -i32 ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Mul32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" *i32 ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Divi32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" /i32 ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_Divu32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (" /u32 ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	/* Built-in calls */
	case OP_CallBuiltin:
	case OP_CallBuiltinLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("builtin_")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			if (insn->arg3 > 0) {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*")));
				RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg3)));
				RETURN_IF_ERROR (add (out, create_raw_token ("args*/")));
			}
			RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			break;
		}
	case OP_GetBuiltinClosure:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (get_operand_value (insn_c, 1), NULL);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
			}
			t->is_builtin = true;
			t->is_closure = true;
			RETURN_IF_ERROR (add (out, (Token *)t));
			break;
		}
	case OP_CallDirect:
	case OP_CallDirectLongIndex:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("fn_")));
			RETURN_IF_ERROR (add (out, num_token_u32 ((op == OP_CallDirect)? insn->arg4: insn->arg4)));
			RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("/*argc:")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg3)));
			RETURN_IF_ERROR (add (out, create_raw_token ("*/")));
			RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			break;
		}
	/* Arguments operations */
	case OP_GetArgumentsPropByVal:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("arguments[")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			break;
		}
	case OP_GetArgumentsLength:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("arguments.length")));
			break;
		}
	/* New target and this */
	case OP_GetNewTarget:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("new.target")));
			break;
		}
	case OP_LoadThisNS:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("this")));
			break;
		}
	case OP_CoerceThisNS:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("coerce_this(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_CreateThis:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("new_this(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_NewObjectWithParent:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("new_obj_with_parent(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	/* Special operations */
	case OP_Unreachable:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("unreachable()")));
			break;
		}
	case OP_Debugger:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("debugger")));
			break;
		}
	case OP_AsyncBreakCheck:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("async_break_check()")));
			break;
		}
	case OP_ProfilePoint:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("profile_point(")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_ThrowIfEmpty:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("throw_if_empty(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_ThrowIfUndefinedInst:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("throw_if_undefined_inst()")));
			break;
		}
	case OP_DirectEval:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("eval(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_DeclareGlobalVar:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("declare extern var ")));
			u32 sid = insn->arg1;
			RETURN_IF_ERROR (add (out, unquoted_string (insn->hbc_reader, sid)));
			break;
		}
	case OP_ThrowIfHasRestrictedGlobalProperty:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("throw_if_restricted_prop(")));
			u32 sid = insn->arg1;
			RETURN_IF_ERROR (add (out, quoted_string (insn->hbc_reader, sid)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_SwitchImm:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("switch(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token (") /*tableSize:")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token ("*/")));
			break;
		}
	/* Property operations (variants) */
	case OP_TryPutById:
	case OP_TryPutByIdLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			u32 sid = insn->arg3;
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
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			break;
		}
	case OP_PutNewOwnNEById:
	case OP_PutNewOwnNEByIdLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			u32 sid = (op == OP_PutNewOwnNEById)? insn->arg3: insn->arg4;
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
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			break;
		}
	case OP_PutOwnByVal:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			break;
		}
	case OP_PutOwnGetterSetterByVal:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			RETURN_IF_ERROR (add (out, create_raw_token (" = {getter: ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", setter: ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 3)));
			RETURN_IF_ERROR (add (out, create_raw_token ("}")));
			break;
		}
	/* Property list operations */
	case OP_GetPNameList:
		{
		if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 1) &&
			is_operand_register (insn->inst, 2) && is_operand_register (insn->inst, 3)) {
				RETURN_IF_ERROR (add (out, create_for_in_loop_init_token ((int)get_operand_value (insn_c, 0), (int)get_operand_value (insn_c, 1), (int)get_operand_value (insn_c, 2), (int)get_operand_value (insn_c, 3))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*forin_init_invalid*/")));
			}
			break;
		}
	case OP_GetNextPName:
		{
		if (is_operand_register (insn->inst, 0) && is_operand_register (insn->inst, 1) &&
			is_operand_register (insn->inst, 2) && is_operand_register (insn->inst, 3) &&
				is_operand_register (insn->inst, 4)) {
				RETURN_IF_ERROR (add (out, create_for_in_loop_next_iter_token ((int)get_operand_value (insn_c, 0), (int)get_operand_value (insn_c, 1), (int)get_operand_value (insn_c, 2), (int)get_operand_value (insn_c, 3), (int)get_operand_value (insn_c, 4))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*forin_next_invalid*/")));
			}
			break;
		}
	/* Async closures */
	case OP_CreateAsyncClosure:
	case OP_CreateAsyncClosureLongIndex:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			FunctionTableIndexToken *t = (FunctionTableIndexToken *)create_function_table_index_token (get_operand_value (insn_c, 2), NULL);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom fti");
			}
			t->environment_id = (int)get_operand_value (insn_c, 1);
			t->is_async = true;
			t->is_closure = true;
			RETURN_IF_ERROR (add (out, (Token *)t));
			break;
		}
	/* Conditional jump instructions (N variants) */
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
		{
			const char *cmp = jump_cmp_operator (op);
			if (!cmp) {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*jump_cmp*/")));
				break;
			}
			i32 rel = (i32)get_operand_value (insn_c, 0);
			u32 target = compute_target_address (insn, 0);
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
				RETURN_IF_ERROR (add (out, create_raw_token ("!")));
				RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
			} else {
				RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
			}
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (cmp)));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
			if (rel > 0) {
				RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
			}
			break;
		}
	/* Load operations */
	case OP_Loadi8:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("load_i8(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_Loadu8:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("load_u8(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_Loadi16:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("load_i16(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_Loadu16:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("load_u16(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_Loadi32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("load_i32(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_Loadu32:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("load_u32(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	/* Store operations */
	case OP_Store8:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("store_8(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_Store16:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("store_16(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_Store32:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("store_32(")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token (", ")));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token (")")));
			break;
		}
	case OP_DebuggerCheck:
		{
			RETURN_IF_ERROR (add (out, create_raw_token ("debugger_check()")));
			break;
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
		if (cmp && is_operand_addr (insn->inst, 0) && is_operand_register (insn->inst, 1) && is_operand_register (insn->inst, 2)) {
				i32 rel = (i32)get_operand_value (insn_c, 0);
				u32 target = compute_target_address (insn, 0);
				if (rel > 0) {
					RETURN_IF_ERROR (add (out, create_jump_not_condition_token (target)));
					RETURN_IF_ERROR (add (out, create_raw_token ("!")));
					RETURN_IF_ERROR (add (out, create_left_parenthesis_token ()));
				} else {
					RETURN_IF_ERROR (add (out, create_jump_condition_token (target)));
				}
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
				RETURN_IF_ERROR (add (out, create_raw_token (cmp)));
				RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
				if (rel > 0) {
					RETURN_IF_ERROR (add (out, create_right_parenthesis_token ()));
				}
				break;
			}

			/* Fallback: emit a comment-like raw token with mnemonic */
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
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	}
	return SUCCESS_RESULT ();
}
