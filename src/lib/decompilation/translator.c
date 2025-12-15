#include <hbc/decompilation/translator.h>
#include <hbc/opcodes.h>
#include <hbc/parser.h>
#include <ctype.h>
#include <hbc/decompilation/literals.h>

static Result add(TokenString *ts, Token *t) {
	if (!t) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "alloc token");
	}
	return token_string_add_token (ts, t);
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

/* Safe register token creation with validation */
static Token *reg_l_safe(const ParsedInstruction *insn, int idx) {
	if (!insn || !insn->inst) {
		return create_raw_token("r?");
	}
	if (!is_operand_register(insn->inst, idx)) {
		return create_raw_token("/*not_reg*/");
	}
	u32 r = get_operand_value(insn, idx);
	if (!is_valid_register(r, insn)) {
		char buf[32];
		snprintf(buf, sizeof(buf), "r%u_OOB", r);
		return create_raw_token(buf);
	}
	return create_left_hand_reg_token((int)r);
}

static Token *reg_r_safe(const ParsedInstruction *insn, int idx) {
	if (!insn || !insn->inst) {
		return create_raw_token("r?");
	}
	if (!is_operand_register(insn->inst, idx)) {
		return create_raw_token("/*not_reg*/");
	}
	u32 r = get_operand_value(insn, idx);
	if (!is_valid_register(r, insn)) {
		char buf[32];
		snprintf(buf, sizeof(buf), "r%u_OOB", r);
		return create_raw_token(buf);
	}
	return create_right_hand_reg_token((int)r);
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
		if (string_buffer_init (&sb, n + 8).code != RESULT_SUCCESS) {
			return NULL;
		}
		string_buffer_append (&sb, "\"");
		for (size_t i = 0; i < n; i++) {
			char c = s[i];
			if (c == '\\' || c == '"') {
				string_buffer_append_char (&sb, '\\');
			}
			if ((unsigned char)c < 0x20) {
				char tmp[8];
				snprintf (tmp, sizeof (tmp), "\\x%02x", (unsigned char)c);
				string_buffer_append (&sb, tmp);
			} else {
				string_buffer_append_char (&sb, c);
			}
		}
		string_buffer_append (&sb, "\"");
		Token *t = create_raw_token (sb.data? sb.data: "\"\"");
		string_buffer_free (&sb);
		return t;
	}
	return create_raw_token ("\"\"");
}

Result translate_instruction_to_tokens(const ParsedInstruction *insn_c, TokenString *out) {
	if (!insn_c || !out || !insn_c->inst) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "translate: bad args");
	}
	ParsedInstruction *insn = (ParsedInstruction *)insn_c; /* for storing pointer in token_string */
	RETURN_IF_ERROR (token_string_init (out, insn));

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
			if (is_operand_register(insn->inst, 0)) {
				RETURN_IF_ERROR (add (out, create_catch_block_start_token ((int)get_operand_value(insn, 0))));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*catch non-reg*/")));
			}
			break;
		}
	case OP_CreateEnvironment:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, create_raw_token ("new_env()")));
			break;
		}
	case OP_CreateInnerEnvironment:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			string_buffer_init (&sb, 48);
			string_buffer_append (&sb, "new_inner_env(");
			char nb[16];
			/* arg2 should be register; validate operand type */
			if (is_operand_register(insn->inst, 1)) {
				snprintf (nb, sizeof (nb), "r%u", (unsigned)insn->arg2);
			} else {
				snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg2);
			}
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ", ");
			snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg3);
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ")");
			Token *t = create_raw_token (sb.data? sb.data: "new_inner_env(r0,0)");
			string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	case OP_CreateClosure:
	case OP_CreateClosureLongIndex:
		{
			/* rD = closure (fn_id, envReg) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			string_buffer_init (&sb, 48);
			string_buffer_append (&sb, "closure(fn_");
			char nb[16];
			snprintf (nb, sizeof (nb), "%u", (unsigned) ((op == OP_CreateClosure)? insn->arg3: insn->arg3));
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ", r");
			snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg2);
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ")");
			Token *t = create_raw_token (sb.data? sb.data: "closure(fn_0,r0)");
			string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	case OP_CreateGeneratorClosure:
	case OP_CreateGeneratorClosureLongIndex:
		{
			/* rD = gen_closure (fn_id, envReg) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			string_buffer_init (&sb, 48);
			string_buffer_append (&sb, "gen_closure(fn_");
			char nb[16];
			snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg3);
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ", r");
			snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg2);
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ")");
			Token *t = create_raw_token (sb.data? sb.data: "gen_closure(fn_0,r0)");
			string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	case OP_CreateGenerator:
	case OP_CreateGeneratorLongIndex:
		{
			/* rD = generator (fn_id, envReg) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			string_buffer_init (&sb, 48);
			string_buffer_append (&sb, "generator(fn_");
			char nb[16];
			snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg3);
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ", r");
			snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg2);
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ")");
			Token *t = create_raw_token (sb.data? sb.data: "generator(fn_0,r0)");
			string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
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
			string_buffer_init (&sb, 48);
			string_buffer_append (&sb, "try_get(");
			char nb[16];
			snprintf (nb, sizeof (nb), "r%u", (unsigned)insn->arg2);
			string_buffer_append (&sb, nb);
			format_property_from_string_id (insn->hbc_reader, (op == OP_TryGetById)? insn->arg4: insn->arg4, &sb);
			string_buffer_append (&sb, ")");
			Token *t = create_raw_token (sb.data? sb.data: "try_get(r0)");
			string_buffer_free (&sb);
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
		if (s && is_js_identifier (s)) {
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
			if (is_operand_register(insn->inst, 0) && is_operand_register(insn->inst, 1)) {
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
			if (is_operand_register(insn->inst, 0)) {
				RETURN_IF_ERROR (add (out, create_save_generator_token (insn->arg1)));
			} else {
				RETURN_IF_ERROR (add (out, create_raw_token ("/*save_gen_invalid*/")));
			}
			break;
		}
	case OP_GetEnvironment:
		{
			/* rD = env (depth) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			string_buffer_init (&sb, 32);
			string_buffer_append (&sb, "env(");
			char nb[16];
			snprintf (nb, sizeof (nb), "%u", (unsigned)insn->arg2);
			string_buffer_append (&sb, nb);
			string_buffer_append (&sb, ")");
			Token *t = create_raw_token (sb.data? sb.data: "env(0)");
			string_buffer_free (&sb);
			if (!t) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
			}
			RETURN_IF_ERROR (add (out, t));
			break;
		}
	case OP_StoreToEnvironment:
	case OP_StoreToEnvironmentL:
		{
			/* env[slot] = value (env reg in arg1, slot in arg2/arg2L, value in arg3) */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg2)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 2)));
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
			/* rD = envReg[slot] */
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			RETURN_IF_ERROR (add (out, reg_r_safe (insn_c, 1)));
			RETURN_IF_ERROR (add (out, create_raw_token ("[")));
			RETURN_IF_ERROR (add (out, num_token_u32 (insn->arg3)));
			RETURN_IF_ERROR (add (out, create_raw_token ("]")));
			break;
		}
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
		{
			RETURN_IF_ERROR (add (out, reg_l_safe (insn_c, 0)));
			RETURN_IF_ERROR (add (out, create_assignment_token ()));
			StringBuffer sb;
			Result r = string_buffer_init (&sb, 128);
			if (r.code != RESULT_SUCCESS) {
				return r;
			}
			r = format_object_literal (insn->hbc_reader, insn->arg2, insn->arg3, insn->arg4, insn->arg5, &sb, LITERALS_PRETTY_AUTO, false);
		Token *t = create_raw_token ((r.code == RESULT_SUCCESS && sb.data)? sb.data: "{ /*object*/ }");
			string_buffer_free (&sb);
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
			Result r = string_buffer_init (&sb, 128);
			if (r.code != RESULT_SUCCESS) {
				return r;
			}
			r = format_array_literal (insn->hbc_reader, insn->arg3, insn->arg4, &sb, LITERALS_PRETTY_AUTO, false);
		Token *t = create_raw_token ((r.code == RESULT_SUCCESS && sb.data)? sb.data: "[ /*array*/ ]");
			string_buffer_free (&sb);
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
	default:
		{
			if (true) {
				/* Fallback: emit a comment-like raw token with mnemonic */
				StringBuffer sb;
				string_buffer_init (&sb, 64);
				string_buffer_append (&sb, "/* ");
				string_buffer_append (&sb, insn->inst->name);
				string_buffer_append (&sb, " */");
				Token *t = create_raw_token (sb.data? sb.data: "/* insn */");
				string_buffer_free (&sb);
				if (!t) {
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
				}
				RETURN_IF_ERROR (add (out, t));
			}
			break;
		}
	}
	return SUCCESS_RESULT ();
}
