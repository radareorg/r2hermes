static void set_esil(RAnalOp *op, const u8 *bytes, ut64 addr) {
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
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,r%u,=", src, dst);
			break;
		}
	case OP_MovLong:
		{
			const u32 dst = r_read_le32(bytes + 1);
			const u32 src = r_read_le32(bytes + 5);
			r_strbuf_setf (&op->esil, "r%u,r%u,=", src, dst);
			break;
		}
	case OP_Add:
	case OP_AddN:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,+,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Sub:
	case OP_SubN:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,-,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Mul:
	case OP_MulN:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,*,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Div:
	case OP_DivN:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,/,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Mod:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,%%,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Add32:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,+,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Sub32:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,-,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Mul32:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,*,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Negate:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,0,-,r%u,=", src, dst);
			break;
		}
	case OP_Not:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,!,r%u,=", src, dst);
			break;
		}
	case OP_BitNot:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,~,r%u,=", src, dst);
			break;
		}
	case OP_Inc:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "1,r%u,+,r%u,=", src, dst);
			break;
		}
	case OP_Dec:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "1,r%u,-,r%u,=", src, dst);
			break;
		}
	case OP_BitAnd:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_BitOr:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,|,r%u,=", s2, s1, dst);
			break;
		}
	case OP_BitXor:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,^,r%u,=", s2, s1, dst);
			break;
		}
	case OP_LShift:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,<<,r%u,=", s2, s1, dst);
			break;
		}
	case OP_RShift:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,>>,r%u,=", s2, s1, dst);
			break;
		}
	case OP_URshift:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,0x1f,&,>>,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Divi32:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,~/,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Divu32:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,/,0xffffffff,&,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Eq:
	case OP_StrictEq:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Neq:
	case OP_StrictNeq:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Less:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,<,r%u,=", s2, s1, dst);
			break;
		}
	case OP_Greater:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,>,r%u,=", s2, s1, dst);
			break;
		}
	case OP_LessEq:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,r%u,=", s2, s1, dst);
			break;
		}
	case OP_GreaterEq:
		{
			const u8 dst = bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,r%u,=", s2, s1, dst);
			break;
		}
	case OP_TypeOf:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,TYPEOF,r%u,=", src, dst);
			break;
		}
	case OP_GetById:
	case OP_GetByIdLong:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,GETPROP,r%u,=", obj, dst);
			break;
		}
	case OP_GetByIdShort:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,GETPROP,r%u,=", obj, dst);
			break;
		}
	case OP_TryGetById:
	case OP_TryGetByIdLong:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,TRYGETPROP,r%u,=", obj, dst);
			break;
		}
	case OP_PutById:
	case OP_PutByIdLong:
		{
			const u8 obj = bytes[1];
			const u8 val = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,r%u,PUTPROP", val, obj);
			break;
		}
	case OP_TryPutById:
	case OP_TryPutByIdLong:
		{
			const u8 obj = bytes[1];
			const u8 val = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,r%u,TRYPUTPROP", val, obj);
			break;
		}
	case OP_LoadConstUInt8:
		{
			const u8 dst = bytes[1];
			const u8 val = bytes[2];
			r_strbuf_setf (&op->esil, "%u,r%u,=", val, dst);
			break;
		}
	case OP_LoadConstInt:
		{
			const u8 dst = bytes[1];
			const i32 val = (i32)r_read_le32(bytes + 2);
			r_strbuf_setf (&op->esil, "%d,r%u,=", val, dst);
			break;
		}
	case OP_LoadConstString:
	case OP_LoadConstBigInt:
		{
			const u8 dst = bytes[1];
			const u16 idx = r_read_le16(bytes + 2);
			r_strbuf_setf (&op->esil, "%u,r%u,=", idx, dst);
			break;
		}
	case OP_LoadConstStringLongIndex:
	case OP_LoadConstBigIntLongIndex:
		{
			const u8 dst = bytes[1];
			const u32 idx = r_read_le32(bytes + 2);
			r_strbuf_setf (&op->esil, "%u,r%u,=", idx, dst);
			break;
		}
	case OP_LoadConstEmpty:
	case OP_LoadConstUndefined:
	case OP_LoadConstNull:
	case OP_LoadConstFalse:
	case OP_LoadConstZero:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "0,r%u,=", dst);
			break;
		}
	case OP_LoadConstTrue:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "1,r%u,=", dst);
			break;
		}
	case OP_LoadParam:
		{
			const u8 dst = bytes[1];
			const u8 idx = bytes[2];
			r_strbuf_setf (&op->esil, "arg%u,r%u,=", idx, dst);
			break;
		}
	case OP_Jmp:
		{
			const i8 off = (i8)bytes[1];
			r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", addr + off);
			break;
		}
	case OP_JmpLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", addr + off);
			break;
		}
	case OP_JmpTrue:
		{
			const i8 off = (i8)bytes[1];
			const u8 cond = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpTrueLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 cond = bytes[5];
			r_strbuf_setf (&op->esil, "r%u,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpFalse:
		{
			const i8 off = (i8)bytes[1];
			const u8 cond = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpFalseLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 cond = bytes[5];
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JLess:
	case OP_JLessN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JLessLong:
	case OP_JLessNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JEqual:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JEqualLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotEqual:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotEqualLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictEqual:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictEqualLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictNotEqual:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JStrictNotEqualLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,==,!,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLess:
	case OP_JNotLessN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLessLong:
	case OP_JNotLessNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JLessEqual:
	case OP_JLessEqualN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JLessEqualLong:
	case OP_JLessEqualNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreater:
	case OP_JGreaterN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreaterLong:
	case OP_JGreaterNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreaterEqual:
	case OP_JGreaterEqualN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JGreaterEqualLong:
	case OP_JGreaterEqualNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,>=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLessEqual:
	case OP_JNotLessEqualN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotLessEqualLong:
	case OP_JNotLessEqualNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,>,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreater:
	case OP_JNotGreaterN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreaterLong:
	case OP_JNotGreaterNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,<=,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreaterEqual:
	case OP_JNotGreaterEqualN:
		{
			const i8 off = (i8)bytes[1];
			const u8 s1 = bytes[2];
			const u8 s2 = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JNotGreaterEqualLong:
	case OP_JNotGreaterEqualNLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 s1 = bytes[5];
			const u8 s2 = bytes[6];
			r_strbuf_setf (&op->esil, "r%u,r%u,<,?{,0x%" PFMT64x ",pc,=,}", s2, s1, addr + off);
			break;
		}
	case OP_JmpUndefined:
		{
			const i8 off = (i8)bytes[1];
			const u8 cond = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_JmpUndefinedLong:
		{
			const i32 off = (i32)r_read_le32(bytes + 1);
			const u8 cond = bytes[5];
			r_strbuf_setf (&op->esil, "r%u,!,?{,0x%" PFMT64x ",pc,=,}", cond, addr + off);
			break;
		}
	case OP_LoadThisNS:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "this,r%u,=", dst);
			break;
		}
	case OP_GetNewTarget:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "newtarget,r%u,=", dst);
			break;
		}
	case OP_GetEnvironment:
		{
			const u8 dst = bytes[1];
			const u8 idx = bytes[2];
			r_strbuf_setf (&op->esil, "env%u,r%u,=", idx, dst);
			break;
		}
	case OP_LoadFromEnvironment:
	case OP_LoadFromEnvironmentL:
		{
			const u8 dst = bytes[1];
			const u8 env = bytes[2];
			const u8 slot = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,%u,ENVLOAD,r%u,=", env, slot, dst);
			break;
		}
	case OP_StoreToEnvironment:
	case OP_StoreToEnvironmentL:
	case OP_StoreNPToEnvironment:
	case OP_StoreNPToEnvironmentL:
		{
			const u8 env = bytes[1];
			const u8 slot = bytes[2];
			const u8 val = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,%u,ENVSTORE", val, env, slot);
			break;
		}
	case OP_GetByVal:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			const u8 idx = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,GETVAL,r%u,=", idx, obj, dst);
			break;
		}
	case OP_PutByVal:
		{
			const u8 obj = bytes[1];
			const u8 idx = bytes[2];
			const u8 val = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,r%u,PUTVAL", val, idx, obj);
			break;
		}
	case OP_Call1:
		{
			const u8 dst = bytes[1];
			const u8 callee = bytes[2];
			const u8 arg = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,CALL1,r%u,=", arg, callee, dst);
			break;
		}
	case OP_Call2:
		{
			const u8 dst = bytes[1];
			const u8 callee = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,CALL2,r%u,=", callee, dst);
			break;
		}
	case OP_Call3:
		{
			const u8 dst = bytes[1];
			const u8 callee = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,CALL3,r%u,=", callee, dst);
			break;
		}
	case OP_Call4:
		{
			const u8 dst = bytes[1];
			const u8 callee = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,CALL4,r%u,=", callee, dst);
			break;
		}
	case OP_Construct:
	case OP_ConstructLong:
		{
			const u8 dst = bytes[1];
			const u8 callee = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,CONSTRUCT,r%u,=", callee, dst);
			break;
		}
	case OP_CreateClosure:
	case OP_CreateClosureLongIndex:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "CLOSURE,r%u,=", dst);
			break;
		}
	case OP_LoadParamLong:
		{
			const u8 dst = bytes[1];
			const u32 idx = r_read_le32(bytes + 2);
			r_strbuf_setf (&op->esil, "arg%u,r%u,=", idx, dst);
			break;
		}
	case OP_Ret:
		{
			const u8 val = bytes[1];
			r_strbuf_setf (&op->esil, "r%u,ret,=", val);
			break;
		}
	case OP_Call:
	case OP_CallLong:
		{
			const u8 dst = bytes[1];
			const u8 callee = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,CALL,r%u,=", callee, dst);
			break;
		}
	case OP_CallDirect:
	case OP_CallDirectLongIndex:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "CALLDIRECT,r%u,=", dst);
			break;
		}
	case OP_NewObject:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "NEWOBJ,r%u,=", dst);
			break;
		}
	case OP_NewArray:
		{
			const u8 dst = bytes[1];
			const u16 size = r_read_le16(bytes + 2);
			r_strbuf_setf (&op->esil, "%u,NEWARR,r%u,=", size, dst);
			break;
		}
	case OP_CreateEnvironment:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "NEWENV,r%u,=", dst);
			break;
		}
	case OP_GetGlobalObject:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "global,r%u,=", dst);
			break;
		}
	case OP_Throw:
		{
			const u8 val = bytes[1];
			r_strbuf_setf (&op->esil, "r%u,THROW", val);
			break;
		}
	case OP_Catch:
		{
			const u8 dst = bytes[1];
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
			const u8 src = bytes[1];
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
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,EVAL,r%u,=", src, dst);
			break;
		}
	case OP_CreateThis:
		{
			const u8 dst = bytes[1];
			const u8 proto = bytes[2];
			const u8 closure = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,CREATETHIS,r%u,=", closure, proto, dst);
			break;
		}
	case OP_SelectObject:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			const u8 base = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,SELECTOBJ,r%u,=", base, obj, dst);
			break;
		}
	case OP_CoerceThisNS:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,COERCETHIS,r%u,=", src, dst);
			break;
		}
	case OP_ToNumber:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,TONUM,r%u,=", src, dst);
			break;
		}
	case OP_ToNumeric:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,TONUMERIC,r%u,=", src, dst);
			break;
		}
	case OP_ToInt32:
		{
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,TOINT32,r%u,=", src, dst);
			break;
		}
	case OP_DelById:
	case OP_DelByIdLong:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,DELPROP,r%u,=", obj, dst);
			break;
		}
	case OP_DelByVal:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			const u8 key = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,DELVAL,r%u,=", key, obj, dst);
			break;
		}
	case OP_IsIn:
		{
			const u8 dst = bytes[1];
			const u8 key = bytes[2];
			const u8 obj = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,ISIN,r%u,=", obj, key, dst);
			break;
		}
	case OP_InstanceOf:
		{
			const u8 dst = bytes[1];
			const u8 obj = bytes[2];
			const u8 ctor = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,INSTANCEOF,r%u,=", ctor, obj, dst);
			break;
		}
	case OP_NewArrayWithBuffer:
	case OP_NewArrayWithBufferLong:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "NEWARRBUF,r%u,=", dst);
			break;
		}
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "NEWOBJBUF,r%u,=", dst);
			break;
		}
	case OP_GetArgumentsPropByVal:
	case OP_GetArgumentsLength:
	case OP_ReifyArguments:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "arguments,r%u,=", dst);
			break;
		}
	case OP_CreateRegExp:
		{
			const u8 dst = bytes[1];
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
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "BUILTIN,r%u,=", dst);
			break;
		}
	case OP_GetBuiltinClosure:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "BUILTINCLOSURE,r%u,=", dst);
			break;
		}
	case OP_CreateAsyncClosure:
	case OP_CreateAsyncClosureLongIndex:
		{
			const u8 dst = bytes[1];
			r_strbuf_setf (&op->esil, "ASYNCCLOSURE,r%u,=", dst);
			break;
		}
	case OP_CreateGeneratorClosure:
	case OP_CreateGeneratorClosureLongIndex:
		{
			const u8 dst = bytes[1];
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
			const u8 dst = bytes[1];
			const u8 src = bytes[2];
			r_strbuf_setf (&op->esil, "r%u,ITERBEGIN,r%u,=", src, dst);
			break;
		}
	case OP_IteratorNext:
		{
			const u8 dst = bytes[1];
			const u8 iter = bytes[2];
			const u8 src = bytes[3];
			r_strbuf_setf (&op->esil, "r%u,r%u,ITERNEXT,r%u,=", src, iter, dst);
			break;
		}
	case OP_IteratorClose:
		{
			const u8 iter = bytes[1];
			r_strbuf_setf (&op->esil, "r%u,ITERCLOSE", iter);
			break;
		}
	case OP_CreateInnerEnvironment:
		{
			const u8 dst = bytes[1];
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
