/* radare2 - BSD - Copyright 2025-2026 - pancake */

static void set_esil(RAnalOp *op, const u8 *bytes, ut64 addr) {
	if (!bytes || !op) {
		return;
	}
	const int opcode = bytes[0];

	/* Compact ESIL emitters: mid/pre/cmp are string literals spliced into the
	 * format; register operands are read from fixed byte positions. */
#define E3(mid) { r_strbuf_setf (&op->esil, "r%u,r%u," mid ",r%u,=", bytes[3], bytes[2], bytes[1]); break; }
#define E2(mid) { r_strbuf_setf (&op->esil, "r%u," mid ",r%u,=", bytes[2], bytes[1]); break; }
#define EDST(pre) { r_strbuf_setf (&op->esil, pre ",r%u,=", bytes[1]); break; }
#define JMP_S { r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", addr + (i8)bytes[1]); break; }
#define JMP_L { r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", addr + (i32)r_read_le32 (bytes + 1)); break; }
#define JC1_S(pre) { r_strbuf_setf (&op->esil, "r%u," pre "?{,0x%" PFMT64x ",pc,=,}", bytes[2], addr + (i8)bytes[1]); break; }
#define JC1_L(pre) { r_strbuf_setf (&op->esil, "r%u," pre "?{,0x%" PFMT64x ",pc,=,}", bytes[5], addr + (i32)r_read_le32 (bytes + 1)); break; }
#define JCC_S(cmp) { r_strbuf_setf (&op->esil, "r%u,r%u," cmp ",?{,0x%" PFMT64x ",pc,=,}", bytes[3], bytes[2], addr + (i8)bytes[1]); break; }
#define JCC_L(cmp) { r_strbuf_setf (&op->esil, "r%u,r%u," cmp ",?{,0x%" PFMT64x ",pc,=,}", bytes[6], bytes[5], addr + (i32)r_read_le32 (bytes + 1)); break; }

	switch (opcode) {
	case OP_Mov:
		r_strbuf_setf (&op->esil, "r%u,r%u,=", bytes[2], bytes[1]);
		break;
	case OP_MovLong:
		r_strbuf_setf (&op->esil, "r%u,r%u,=", r_read_le32 (bytes + 5), r_read_le32 (bytes + 1));
		break;

	/* 3-register ALU and ternary-mnemonic ops: r<s2>,r<s1>,<mid>,r<dst>,= */
	case OP_Add: case OP_AddN: E3 ("+")
	case OP_Sub: case OP_SubN: E3 ("-")
	case OP_Mul: case OP_MulN: E3 ("*")
	case OP_Div: case OP_DivN: E3 ("/")
	case OP_Mod: E3 ("%%")
	case OP_Add32: E3 ("+,0xffffffff,&")
	case OP_Sub32: E3 ("-,0xffffffff,&")
	case OP_Mul32: E3 ("*,0xffffffff,&")
	case OP_Divi32: E3 ("~/,0xffffffff,&")
	case OP_Divu32: E3 ("/,0xffffffff,&")
	case OP_BitAnd: E3 ("&")
	case OP_BitOr: E3 ("|")
	case OP_BitXor: E3 ("^")
	case OP_LShift: E3 ("<<")
	case OP_RShift: E3 (">>")
	case OP_URshift: E3 ("0x1f,&,>>")
	case OP_Eq: case OP_StrictEq: E3 ("==")
	case OP_Neq: case OP_StrictNeq: E3 ("==,!")
	case OP_Less: E3 ("<")
	case OP_Greater: E3 (">")
	case OP_LessEq: E3 ("<=")
	case OP_GreaterEq: E3 (">=")
	case OP_GetByVal: E3 ("GETVAL")
	case OP_DelByVal: E3 ("DELVAL")
	case OP_IsIn: E3 ("ISIN")
	case OP_InstanceOf: E3 ("INSTANCEOF")
	case OP_CreateThis: E3 ("CREATETHIS")
	case OP_SelectObject: E3 ("SELECTOBJ")
	case OP_IteratorNext: E3 ("ITERNEXT")
	case OP_Call1: E3 ("CALL1")

	/* 2-register ops: r<src>,<mid>,r<dst>,= */
	case OP_Negate: E2 ("0,-")
	case OP_Not: E2 ("!")
	case OP_BitNot: E2 ("~")
	case OP_TypeOf: E2 ("TYPEOF")
	case OP_GetById: case OP_GetByIdLong: case OP_GetByIdShort: E2 ("GETPROP")
	case OP_TryGetById: case OP_TryGetByIdLong: E2 ("TRYGETPROP")
	case OP_DelById: case OP_DelByIdLong: E2 ("DELPROP")
	case OP_DirectEval: E2 ("EVAL")
	case OP_CoerceThisNS: E2 ("COERCETHIS")
	case OP_ToNumber: E2 ("TONUM")
	case OP_ToNumeric: E2 ("TONUMERIC")
	case OP_ToInt32: E2 ("TOINT32")
	case OP_IteratorBegin: E2 ("ITERBEGIN")
	case OP_Construct: case OP_ConstructLong: E2 ("CONSTRUCT")
	case OP_Call: case OP_CallLong: E2 ("CALL")
	case OP_Call2: E2 ("CALL2")
	case OP_Call3: E2 ("CALL3")
	case OP_Call4: E2 ("CALL4")

	/* destination-only loads: <pre>,r<dst>,= */
	case OP_LoadConstEmpty:
	case OP_LoadConstUndefined:
	case OP_LoadConstNull:
	case OP_LoadConstFalse:
	case OP_LoadConstZero: EDST ("0")
	case OP_LoadConstTrue: EDST ("1")
	case OP_LoadThisNS: EDST ("this")
	case OP_GetNewTarget: EDST ("newtarget")
	case OP_GetGlobalObject: EDST ("global")
	case OP_NewObject: EDST ("NEWOBJ")
	case OP_CreateEnvironment: EDST ("NEWENV")
	case OP_CreateInnerEnvironment: EDST ("INNERENV")
	case OP_CreateClosure: case OP_CreateClosureLongIndex: EDST ("CLOSURE")
	case OP_CreateAsyncClosure: case OP_CreateAsyncClosureLongIndex: EDST ("ASYNCCLOSURE")
	case OP_CreateGeneratorClosure: case OP_CreateGeneratorClosureLongIndex: EDST ("GENCLOSURE")
	case OP_CallDirect: case OP_CallDirectLongIndex: EDST ("CALLDIRECT")
	case OP_Catch: EDST ("CATCH")
	case OP_NewArrayWithBuffer: case OP_NewArrayWithBufferLong: EDST ("NEWARRBUF")
	case OP_NewObjectWithBuffer: case OP_NewObjectWithBufferLong: EDST ("NEWOBJBUF")
	case OP_GetArgumentsPropByVal: case OP_GetArgumentsLength: case OP_ReifyArguments: EDST ("arguments")
	case OP_CreateRegExp: EDST ("REGEXP")
	case OP_CallBuiltin: case OP_CallBuiltinLong: EDST ("BUILTIN")
	case OP_GetBuiltinClosure: EDST ("BUILTINCLOSURE")

	/* increments */
	case OP_Inc:
		r_strbuf_setf (&op->esil, "1,r%u,+,r%u,=", bytes[2], bytes[1]);
		break;
	case OP_Dec:
		r_strbuf_setf (&op->esil, "1,r%u,-,r%u,=", bytes[2], bytes[1]);
		break;

	/* constant loads carrying an immediate */
	case OP_LoadConstUInt8:
		r_strbuf_setf (&op->esil, "%u,r%u,=", bytes[2], bytes[1]);
		break;
	case OP_LoadConstInt:
		r_strbuf_setf (&op->esil, "%d,r%u,=", (i32)r_read_le32 (bytes + 2), bytes[1]);
		break;
	case OP_LoadConstString:
	case OP_LoadConstBigInt:
		r_strbuf_setf (&op->esil, "%u,r%u,=", r_read_le16 (bytes + 2), bytes[1]);
		break;
	case OP_LoadConstStringLongIndex:
	case OP_LoadConstBigIntLongIndex:
		r_strbuf_setf (&op->esil, "%u,r%u,=", r_read_le32 (bytes + 2), bytes[1]);
		break;
	case OP_LoadParam:
		r_strbuf_setf (&op->esil, "arg%u,r%u,=", bytes[2], bytes[1]);
		break;
	case OP_LoadParamLong:
		r_strbuf_setf (&op->esil, "arg%u,r%u,=", r_read_le32 (bytes + 2), bytes[1]);
		break;
	case OP_NewArray:
		r_strbuf_setf (&op->esil, "%u,NEWARR,r%u,=", r_read_le16 (bytes + 2), bytes[1]);
		break;

	/* environment access */
	case OP_GetEnvironment:
		r_strbuf_setf (&op->esil, "env%u,r%u,=", bytes[2], bytes[1]);
		break;
	case OP_LoadFromEnvironment:
	case OP_LoadFromEnvironmentL:
		r_strbuf_setf (&op->esil, "r%u,%u,ENVLOAD,r%u,=", bytes[2], bytes[3], bytes[1]);
		break;
	case OP_StoreToEnvironment:
	case OP_StoreToEnvironmentL:
	case OP_StoreNPToEnvironment:
	case OP_StoreNPToEnvironmentL:
		r_strbuf_setf (&op->esil, "r%u,r%u,%u,ENVSTORE", bytes[3], bytes[1], bytes[2]);
		break;

	/* property / value stores (no destination assignment) */
	case OP_PutById:
	case OP_PutByIdLong:
		r_strbuf_setf (&op->esil, "r%u,r%u,PUTPROP", bytes[2], bytes[1]);
		break;
	case OP_TryPutById:
	case OP_TryPutByIdLong:
		r_strbuf_setf (&op->esil, "r%u,r%u,TRYPUTPROP", bytes[2], bytes[1]);
		break;
	case OP_PutByVal:
		r_strbuf_setf (&op->esil, "r%u,r%u,r%u,PUTVAL", bytes[3], bytes[2], bytes[1]);
		break;

	/* control transfer (no destination) */
	case OP_Ret:
		r_strbuf_setf (&op->esil, "r%u,ret,=", bytes[1]);
		break;
	case OP_Throw:
		r_strbuf_setf (&op->esil, "r%u,THROW", bytes[1]);
		break;
	case OP_ThrowIfUndefinedInst:
		r_strbuf_setf (&op->esil, "r%u,UNDEFINED,==,?{,THROW,}", bytes[1]);
		break;
	case OP_IteratorClose:
		r_strbuf_setf (&op->esil, "r%u,ITERCLOSE", bytes[1]);
		break;

	/* jumps */
	case OP_Jmp: JMP_S
	case OP_JmpLong: JMP_L
	case OP_JmpTrue: JC1_S ("")
	case OP_JmpTrueLong: JC1_L ("")
	case OP_JmpFalse: JC1_S ("!,")
	case OP_JmpFalseLong: JC1_L ("!,")
	case OP_JmpUndefined: JC1_S ("!,")
	case OP_JmpUndefinedLong: JC1_L ("!,")
	case OP_JLess: case OP_JLessN: JCC_S ("<")
	case OP_JLessLong: case OP_JLessNLong: JCC_L ("<")
	case OP_JNotLess: case OP_JNotLessN: JCC_S (">=")
	case OP_JNotLessLong: case OP_JNotLessNLong: JCC_L (">=")
	case OP_JLessEqual: case OP_JLessEqualN: JCC_S ("<=")
	case OP_JLessEqualLong: case OP_JLessEqualNLong: JCC_L ("<=")
	case OP_JGreater: case OP_JGreaterN: JCC_S (">")
	case OP_JGreaterLong: case OP_JGreaterNLong: JCC_L (">")
	case OP_JGreaterEqual: case OP_JGreaterEqualN: JCC_S (">=")
	case OP_JGreaterEqualLong: case OP_JGreaterEqualNLong: JCC_L (">=")
	case OP_JNotLessEqual: case OP_JNotLessEqualN: JCC_S (">")
	case OP_JNotLessEqualLong: case OP_JNotLessEqualNLong: JCC_L (">")
	case OP_JNotGreater: case OP_JNotGreaterN: JCC_S ("<=")
	case OP_JNotGreaterLong: case OP_JNotGreaterNLong: JCC_L ("<=")
	case OP_JNotGreaterEqual: case OP_JNotGreaterEqualN: JCC_S ("<")
	case OP_JNotGreaterEqualLong: case OP_JNotGreaterEqualNLong: JCC_L ("<")
	case OP_JEqual: JCC_S ("==")
	case OP_JEqualLong: JCC_L ("==")
	case OP_JNotEqual: JCC_S ("==,!")
	case OP_JNotEqualLong: JCC_L ("==,!")
	case OP_JStrictEqual: JCC_S ("==")
	case OP_JStrictEqualLong: JCC_L ("==")
	case OP_JStrictNotEqual: JCC_S ("==,!")
	case OP_JStrictNotEqualLong: JCC_L ("==,!")

	/* aggregate / opaque ops with no precise ESIL model */
	case OP_Unreachable:
		r_strbuf_setf (&op->esil, "UNREACHABLE");
		break;
	case OP_SwitchImm:
		r_strbuf_setf (&op->esil, "SWITCH");
		break;
	case OP_StartGenerator:
	case OP_ResumeGenerator:
	case OP_CompleteGenerator:
	case OP_CreateGenerator:
	case OP_SaveGenerator:
	case OP_SaveGeneratorLong:
		r_strbuf_setf (&op->esil, "GENERATOR");
		break;
	case OP_Debugger:
	case OP_AsyncBreakCheck:
	case OP_ProfilePoint:
	case OP_DebuggerCheck:
	case OP_DeclareGlobalVar:
	case OP_ThrowIfHasRestrictedGlobalProperty:
		r_strbuf_set (&op->esil, "");
		break;
	default:
		break;
	}
#undef E3
#undef E2
#undef EDST
#undef JMP_S
#undef JMP_L
#undef JC1_S
#undef JC1_L
#undef JCC_S
#undef JCC_L
}
