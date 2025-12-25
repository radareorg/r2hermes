static void set_esil(RAnalOp *op, const char *mnemonic, const u8 *bytes, ut64 addr) {
	(void)mnemonic; /* Opcode comes directly from op now */
	int opcode = op->type != R_ANAL_OP_TYPE_UNK? -1: -1;
	/* Note: esil is set by opcode from decode output, not by looking up mnemonic again */
	/* For now, use opcode directly in the switch - caller should set op->val to the opcode */

	/* The actual opcode was already parsed by hbc_dec. Access via the bytes directly */
	if (!bytes || !op) {
		return;
	}
	opcode = bytes[0];

	switch (opcode) {
	case OP_Mov:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,r%u,=", src, dst);
			break;
		}
	case OP_MovLong:
		{
			u32 dst = READ_UINT32 (bytes, 1);
			u32 src = READ_UINT32 (bytes, 5);
			r_strbuf_setf (&op->esil, "r%u,r%u,=", src, dst);
			break;
		}
	case OP_Add:
	case OP_AddN:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,+,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Sub:
	case OP_SubN:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,-,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Mul:
	case OP_MulN:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,*,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Div:
	case OP_DivN:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,/,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Mod:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,%%,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Add32:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,+,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Sub32:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,-,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Mul32:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,*,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Negate:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,0,-,r%u,=", src, dst);
			break;
		}
	case OP_Not:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,!,r%u,=", src, dst);
			break;
		}
	case OP_BitNot:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,~,r%u,=", src, dst);
			break;
		}
	case OP_Inc:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "1,r%u,+,r%u,=", src, dst);
			break;
		}
	case OP_Dec:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "1,r%u,-,r%u,=", src, dst);
			break;
		}
	case OP_BitAnd:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_BitOr:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,|,r%u,=", s2, s1, dst);
			break;
		}
	case OP_BitXor:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,^,r%u,=", s2, s1, dst);
			break;
		}
	case OP_LShift:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,<<,r%u,=", s2, s1, dst);
			break;
		}
	case OP_RShift:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,>>,r%u,=", s2, s1, dst);
			break;
		}
	case OP_URshift:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,0x1f,&,>>,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Divi32:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,~/,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Divu32:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,/,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Eq:
	case OP_StrictEq:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Neq:
	case OP_StrictNeq:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Less:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,<,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Greater:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,>,r%u,=", s2, s1, dst);
			break;
		}
	case OP_LessEq:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,r%u,=", s2, s1, dst);
			break;
		}
	case OP_GreaterEq:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,r%u,=", s2, s1, dst);
			break;
		}
	case OP_TypeOf:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,TYPEOF,r%u,=", src, dst);
			break;
		}
	case OP_GetById:
	case OP_GetByIdLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,GETPROP,r%u,=", obj, dst);
			break;
		}
	case OP_GetByIdShort:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,GETPROP,r%u,=", obj, dst);
			break;
		}
	case OP_TryGetById:
	case OP_TryGetByIdLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,TRYGETPROP,r%u,=", obj, dst);
			break;
		}
	case OP_PutById:
	case OP_PutByIdLong:
		{
			u8 obj = READ_REG8 (bytes, 1);
			u8 val = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,r%u,PUTPROP", val, obj);
			break;
		}
	case OP_TryPutById:
	case OP_TryPutByIdLong:
		{
			u8 obj = READ_REG8 (bytes, 1);
			u8 val = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,r%u,TRYPUTPROP", val, obj);
			break;
		}
	case OP_LoadConstUInt8:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 val = READ_UINT8 (bytes, 2);
			r_strbuf_setf (&op->esil, "%u,r%u,=", val, dst);
			break;
		}
	case OP_LoadConstInt:
		{
			u8 dst = READ_REG8 (bytes, 1);
			i32 val = READ_INT32 (bytes, 2);
			r_strbuf_setf (&op->esil, "%d,r%u,=", val, dst);
			break;
		}
	case OP_LoadConstString:
	case OP_LoadConstBigInt:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u16 idx = READ_UINT16 (bytes, 2);
			r_strbuf_setf (&op->esil, "%u,r%u,=", idx, dst);
			break;
		}
	case OP_LoadConstStringLongIndex:
	case OP_LoadConstBigIntLongIndex:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u32 idx = READ_UINT32 (bytes, 2);
			r_strbuf_setf (&op->esil, "%u,r%u,=", idx, dst);
			break;
		}
	case OP_LoadConstEmpty:
	case OP_LoadConstUndefined:
	case OP_LoadConstNull:
	case OP_LoadConstFalse:
	case OP_LoadConstZero:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "0,r%u,=", dst);
			break;
		}
	case OP_LoadConstTrue:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "1,r%u,=", dst);
			break;
		}
	case OP_LoadParam:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 idx = READ_UINT8 (bytes, 2);
			r_strbuf_setf (&op->esil, "arg%u,r%u,=", idx, dst);
			break;
		}
	case OP_Jmp:
		{
			i8 off = READ_INT8 (bytes, 1);
			r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", addr + off);
			break;
		}
	case OP_JmpLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", addr + off);
			break;
		}
	case OP_JmpTrue:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 cond = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpTrueLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 cond = READ_REG8 (bytes, 5);
			r_strbuf_setf (&op->esil, "r%u,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpFalse:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 cond = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpFalseLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 cond = READ_REG8 (bytes, 5);
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JLess:
	case OP_JLessN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JLessLong:
	case OP_JLessNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JEqual:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JEqualLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotEqual:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotEqualLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictEqual:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictEqualLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictNotEqual:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictNotEqualLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLess:
	case OP_JNotLessN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLessLong:
	case OP_JNotLessNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JLessEqual:
	case OP_JLessEqualN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JLessEqualLong:
	case OP_JLessEqualNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreater:
	case OP_JGreaterN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreaterLong:
	case OP_JGreaterNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreaterEqual:
	case OP_JGreaterEqualN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreaterEqualLong:
	case OP_JGreaterEqualNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLessEqual:
	case OP_JNotLessEqualN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLessEqualLong:
	case OP_JNotLessEqualNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreater:
	case OP_JNotGreaterN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreaterLong:
	case OP_JNotGreaterNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreaterEqual:
	case OP_JNotGreaterEqualN:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 2);
			u8 s2 = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreaterEqualLong:
	case OP_JNotGreaterEqualNLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 s1 = READ_REG8 (bytes, 5);
			u8 s2 = READ_REG8 (bytes, 6);
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JmpUndefined:
		{
			i8 off = READ_INT8 (bytes, 1);
			u8 cond = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpUndefinedLong:
		{
			i32 off = READ_INT32 (bytes, 1);
			u8 cond = READ_REG8 (bytes, 5);
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_LoadThisNS:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "this,r%u,=", dst);
			break;
		}
	case OP_GetNewTarget:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "newtarget,r%u,=", dst);
			break;
		}
	case OP_GetEnvironment:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 idx = READ_UINT8 (bytes, 2);
			r_strbuf_setf (&op->esil, "env%u,r%u,=", idx, dst);
			break;
		}
	case OP_LoadFromEnvironment:
	case OP_LoadFromEnvironmentL:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 env = READ_REG8 (bytes, 2);
			u8 slot = READ_UINT8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,%u,ENVLOAD,r%u,=", env, slot, dst);
			break;
		}
	case OP_StoreToEnvironment:
	case OP_StoreToEnvironmentL:
	case OP_StoreNPToEnvironment:
	case OP_StoreNPToEnvironmentL:
		{
			u8 env = READ_REG8 (bytes, 1);
			u8 slot = READ_UINT8 (bytes, 2);
			u8 val = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,%u,ENVSTORE", val, env, slot);
			break;
		}
	case OP_GetByVal:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			u8 idx = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,GETVAL,r%u,=", idx, obj, dst);
			break;
		}
	case OP_PutByVal:
		{
			u8 obj = READ_REG8 (bytes, 1);
			u8 idx = READ_REG8 (bytes, 2);
			u8 val = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,r%u,PUTVAL", val, idx, obj);
			break;
		}
	case OP_Call1:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 callee = READ_REG8 (bytes, 2);
			u8 arg = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,CALL1,r%u,=", arg, callee, dst);
			break;
		}
	case OP_Call2:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 callee = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,CALL2,r%u,=", callee, dst);
			break;
		}
	case OP_Call3:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 callee = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,CALL3,r%u,=", callee, dst);
			break;
		}
	case OP_Call4:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 callee = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,CALL4,r%u,=", callee, dst);
			break;
		}
	case OP_Construct:
	case OP_ConstructLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 callee = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,CONSTRUCT,r%u,=", callee, dst);
			break;
		}
	case OP_CreateClosure:
	case OP_CreateClosureLongIndex:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "CLOSURE,r%u,=", dst);
			break;
		}
	case OP_LoadParamLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u32 idx = READ_UINT32 (bytes, 2);
			r_strbuf_setf (&op->esil, "arg%u,r%u,=", idx, dst);
			break;
		}
	case OP_Ret:
		{
			u8 val = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "r%u,ret,=", val);
			break;
		}
	case OP_Call:
	case OP_CallLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 callee = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,CALL,r%u,=", callee, dst);
			break;
		}
	case OP_CallDirect:
	case OP_CallDirectLongIndex:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "CALLDIRECT,r%u,=", dst);
			break;
		}
	case OP_NewObject:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "NEWOBJ,r%u,=", dst);
			break;
		}
	case OP_NewArray:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u16 size = READ_UINT16 (bytes, 2);
			r_strbuf_setf (&op->esil, "%u,NEWARR,r%u,=", size, dst);
			break;
		}
	case OP_CreateEnvironment:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "NEWENV,r%u,=", dst);
			break;
		}
	case OP_GetGlobalObject:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "global,r%u,=", dst);
			break;
		}
	case OP_Throw:
		{
			u8 val = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "r%u,THROW", val);
			break;
		}
	case OP_Catch:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "CATCH,r%u,=", dst);
			break;
		}
	case OP_Debugger:
	case OP_AsyncBreakCheck:
	case OP_ProfilePoint:
	case OP_DebuggerCheck:
		r_strbuf_set (&op->esil, "");
		break;
	case OP_ThrowIfUndefinedInst:
		{
			u8 src = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "r%u,UNDEFINED,==,?{,THROW,}", src);
			break;
		}
	case OP_Unreachable:
		r_strbuf_setf (&op->esil, "UNREACHABLE");
		break;
	case OP_DeclareGlobalVar:
		{
			/* DeclareGlobalVar declares a global variable - modeled as a no-op in ESIL */
			r_strbuf_set (&op->esil, "");
			break;
		}
	case OP_DirectEval:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,EVAL,r%u,=", src, dst);
			break;
		}
	case OP_CreateThis:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 proto = READ_REG8 (bytes, 2);
			u8 closure = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,CREATETHIS,r%u,=", closure, proto, dst);
			break;
		}
	case OP_SelectObject:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			u8 base = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,SELECTOBJ,r%u,=", base, obj, dst);
			break;
		}
	case OP_CoerceThisNS:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,COERCETHIS,r%u,=", src, dst);
			break;
		}
	case OP_ToNumber:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,TONUM,r%u,=", src, dst);
			break;
		}
	case OP_ToNumeric:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,TONUMERIC,r%u,=", src, dst);
			break;
		}
	case OP_ToInt32:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,TOINT32,r%u,=", src, dst);
			break;
		}
	case OP_DelById:
	case OP_DelByIdLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,DELPROP,r%u,=", obj, dst);
			break;
		}
	case OP_DelByVal:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			u8 key = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,DELVAL,r%u,=", key, obj, dst);
			break;
		}
	case OP_IsIn:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 key = READ_REG8 (bytes, 2);
			u8 obj = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,ISIN,r%u,=", obj, key, dst);
			break;
		}
	case OP_InstanceOf:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 obj = READ_REG8 (bytes, 2);
			u8 ctor = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,INSTANCEOF,r%u,=", ctor, obj, dst);
			break;
		}
	case OP_NewArrayWithBuffer:
	case OP_NewArrayWithBufferLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "NEWARRBUF,r%u,=", dst);
			break;
		}
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "NEWOBJBUF,r%u,=", dst);
			break;
		}
	case OP_GetArgumentsPropByVal:
	case OP_GetArgumentsLength:
	case OP_ReifyArguments:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "arguments,r%u,=", dst);
			break;
		}
	case OP_CreateRegExp:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "REGEXP,r%u,=", dst);
			break;
		}
	case OP_SwitchImm:
		{
			/* Switch is complex - just mark as a computed jump */
			r_strbuf_setf (&op->esil, "SWITCH");
			break;
		}
	case OP_CallBuiltin:
	case OP_CallBuiltinLong:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "BUILTIN,r%u,=", dst);
			break;
		}
	case OP_GetBuiltinClosure:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "BUILTINCLOSURE,r%u,=", dst);
			break;
		}
	case OP_CreateAsyncClosure:
	case OP_CreateAsyncClosureLongIndex:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "ASYNCCLOSURE,r%u,=", dst);
			break;
		}
	case OP_CreateGeneratorClosure:
	case OP_CreateGeneratorClosureLongIndex:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "GENCLOSURE,r%u,=", dst);
			break;
		}
	case OP_StartGenerator:
	case OP_ResumeGenerator:
	case OP_CompleteGenerator:
	case OP_CreateGenerator:
	case OP_SaveGenerator:
	case OP_SaveGeneratorLong:
		{
			r_strbuf_setf (&op->esil, "GENERATOR");
			break;
		}
	case OP_IteratorBegin:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 src = READ_REG8 (bytes, 2);
			r_strbuf_setf (&op->esil, "r%u,ITERBEGIN,r%u,=", src, dst);
			break;
		}
	case OP_IteratorNext:
		{
			u8 dst = READ_REG8 (bytes, 1);
			u8 iter = READ_REG8 (bytes, 2);
			u8 src = READ_REG8 (bytes, 3);
			r_strbuf_setf (&op->esil, "r%u,r%u,ITERNEXT,r%u,=", src, iter, dst);
			break;
		}
	case OP_IteratorClose:
		{
			u8 iter = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "r%u,ITERCLOSE", iter);
			break;
		}
	case OP_CreateInnerEnvironment:
		{
			u8 dst = READ_REG8 (bytes, 1);
			r_strbuf_setf (&op->esil, "INNERENV,r%u,=", dst);
			break;
		}
	case OP_ThrowIfHasRestrictedGlobalProperty:
		r_strbuf_set (&op->esil, "");
		break;
	default:
		break;
	}
}
