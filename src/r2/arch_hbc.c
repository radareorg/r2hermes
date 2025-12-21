/* radare2 - LGPL - Copyright 2025 - libhbc */

#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>
#include <string.h>
#include <ctype.h>

#ifndef R2_VERSION
#define R2_VERSION "6.0.3"
#endif

// Include hermesdec headers
#include <hbc/hbc.h>
#include <hbc/opcodes.h>
#include <hbc/bytecode.h>
#include <hbc/parser.h>

#define MAX_OP_SIZE 16

typedef struct {
	ut32 bytecode_version; /* cached from RBinInfo->cpu if available */
	HBCState *hd; /* Hermes file handle for string table access */
	u32 string_count;
	const void *small_string_table;
	const void *overflow_string_table;
	u64 string_storage_offset;
} HermesArchSession;

/* Forward declarations */
static ut32 detect_version_from_bin(RArchSession *s);
static bool load_string_tables(HermesArchSession *hs, RArchSession *s);
static const Instruction *get_instruction_set_by_version(ut32 version, ut32 *out_count);

static ut32 detect_version_from_bin(RArchSession *s) {
	if (!s || !s->arch || !s->arch->binb.bin) {
		return 96; /* sane default */
	}
	RBin *bin = s->arch->binb.bin;
	RBinInfo *bi = r_bin_get_info (bin);
	if (bi && bi->cpu && *bi->cpu) {
		const char *p = bi->cpu;
		/* Accept optional leading 'v' or 'V' (e.g., "v76") */
		if (p[0] == 'v' || p[0] == 'V') {
			p++;
		}
		/* cpu holds the version string set by bin plugin */
		ut32 v = (ut32)strtoul (p, NULL, 10);
		if (v > 0) {
			return v;
		}
	}
	return 96;
}

#define READ_REG8(b, pos) ((u8) (b)[(pos)])
#define READ_UINT8(b, pos) ((u8) (b)[(pos)])
#define READ_UINT16(b, pos) ((u16) ((b)[(pos)] | ((b)[(pos) + 1] << 8)))
#define READ_UINT32(b, pos) ((u32) ((b)[(pos)] | ((b)[(pos) + 1] << 8) | ((b)[(pos) + 2] << 16) | ((b)[(pos) + 3] << 24)))
#define READ_INT8(b, pos) ((i8) (b)[(pos)])
#define READ_INT32(b, pos) ((i32)READ_UINT32 (b, pos))

static void snake_to_camel(const char *src, char *dst, size_t dst_size) {
	if (!src || !dst || dst_size < 2) {
		if (dst && dst_size > 0) {
			dst[0] = '\0';
		}
		return;
	}
	size_t j = 0;
	bool cap_next = true;
	for (size_t i = 0; src[i] && j + 1 < dst_size; i++) {
		if (src[i] == '_') {
			cap_next = true;
		} else {
			dst[j++] = cap_next? (char)toupper ((unsigned char)src[i]): src[i];
			cap_next = false;
		}
	}
	dst[j] = '\0';
}

static int mnemonic_to_canonical_opcode(const char *mnemonic) {
	if (!mnemonic) {
		return -1;
	}
	/* Move operations */
	if (!strcmp (mnemonic, "Mov")) {
		return OP_Mov;
	}
	if (!strcmp (mnemonic, "MovLong")) {
		return OP_MovLong;
	}
	/* Arithmetic operations */
	if (!strcmp (mnemonic, "Add")) {
		return OP_Add;
	}
	if (!strcmp (mnemonic, "AddN")) {
		return OP_AddN;
	}
	if (!strcmp (mnemonic, "Sub")) {
		return OP_Sub;
	}
	if (!strcmp (mnemonic, "SubN")) {
		return OP_SubN;
	}
	if (!strcmp (mnemonic, "Mul")) {
		return OP_Mul;
	}
	if (!strcmp (mnemonic, "MulN")) {
		return OP_MulN;
	}
	if (!strcmp (mnemonic, "Div")) {
		return OP_Div;
	}
	if (!strcmp (mnemonic, "DivN")) {
		return OP_DivN;
	}
	if (!strcmp (mnemonic, "Mod")) {
		return OP_Mod;
	}
	if (!strcmp (mnemonic, "Add32")) {
		return OP_Add32;
	}
	if (!strcmp (mnemonic, "Sub32")) {
		return OP_Sub32;
	}
	if (!strcmp (mnemonic, "Mul32")) {
		return OP_Mul32;
	}
	if (!strcmp (mnemonic, "Divi32")) {
		return OP_Divi32;
	}
	if (!strcmp (mnemonic, "Divu32")) {
		return OP_Divu32;
	}
	/* Unary operations */
	if (!strcmp (mnemonic, "Negate")) {
		return OP_Negate;
	}
	if (!strcmp (mnemonic, "Not")) {
		return OP_Not;
	}
	if (!strcmp (mnemonic, "BitNot")) {
		return OP_BitNot;
	}
	if (!strcmp (mnemonic, "Inc")) {
		return OP_Inc;
	}
	if (!strcmp (mnemonic, "Dec")) {
		return OP_Dec;
	}
	if (!strcmp (mnemonic, "TypeOf")) {
		return OP_TypeOf;
	}
	if (!strcmp (mnemonic, "ToNumber")) {
		return OP_ToNumber;
	}
	if (!strcmp (mnemonic, "ToNumeric")) {
		return OP_ToNumeric;
	}
	if (!strcmp (mnemonic, "ToInt32")) {
		return OP_ToInt32;
	}
	if (!strcmp (mnemonic, "AddEmptyString")) {
		return OP_AddEmptyString;
	}
	if (!strcmp (mnemonic, "CoerceThisNS")) {
		return OP_CoerceThisNS;
	}
	/* Bitwise operations */
	if (!strcmp (mnemonic, "BitAnd")) {
		return OP_BitAnd;
	}
	if (!strcmp (mnemonic, "BitOr")) {
		return OP_BitOr;
	}
	if (!strcmp (mnemonic, "BitXor")) {
		return OP_BitXor;
	}
	if (!strcmp (mnemonic, "LShift")) {
		return OP_LShift;
	}
	if (!strcmp (mnemonic, "RShift")) {
		return OP_RShift;
	}
	if (!strcmp (mnemonic, "URshift")) {
		return OP_URshift;
	}
	/* Comparison operations */
	if (!strcmp (mnemonic, "Eq")) {
		return OP_Eq;
	}
	if (!strcmp (mnemonic, "StrictEq")) {
		return OP_StrictEq;
	}
	if (!strcmp (mnemonic, "Neq")) {
		return OP_Neq;
	}
	if (!strcmp (mnemonic, "StrictNeq")) {
		return OP_StrictNeq;
	}
	if (!strcmp (mnemonic, "Less")) {
		return OP_Less;
	}
	if (!strcmp (mnemonic, "LessEq")) {
		return OP_LessEq;
	}
	if (!strcmp (mnemonic, "Greater")) {
		return OP_Greater;
	}
	if (!strcmp (mnemonic, "GreaterEq")) {
		return OP_GreaterEq;
	}
	if (!strcmp (mnemonic, "InstanceOf")) {
		return OP_InstanceOf;
	}
	if (!strcmp (mnemonic, "IsIn")) {
		return OP_IsIn;
	}
	/* Load constant operations */
	if (!strcmp (mnemonic, "LoadConstUInt8")) {
		return OP_LoadConstUInt8;
	}
	if (!strcmp (mnemonic, "LoadConstInt")) {
		return OP_LoadConstInt;
	}
	if (!strcmp (mnemonic, "LoadConstDouble")) {
		return OP_LoadConstDouble;
	}
	if (!strcmp (mnemonic, "LoadConstString")) {
		return OP_LoadConstString;
	}
	if (!strcmp (mnemonic, "LoadConstBigInt")) {
		return OP_LoadConstBigInt;
	}
	if (!strcmp (mnemonic, "LoadConstStringLongIndex")) {
		return OP_LoadConstStringLongIndex;
	}
	if (!strcmp (mnemonic, "LoadConstBigIntLongIndex")) {
		return OP_LoadConstBigIntLongIndex;
	}
	if (!strcmp (mnemonic, "LoadConstEmpty")) {
		return OP_LoadConstEmpty;
	}
	if (!strcmp (mnemonic, "LoadConstUndefined")) {
		return OP_LoadConstUndefined;
	}
	if (!strcmp (mnemonic, "LoadConstNull")) {
		return OP_LoadConstNull;
	}
	if (!strcmp (mnemonic, "LoadConstTrue")) {
		return OP_LoadConstTrue;
	}
	if (!strcmp (mnemonic, "LoadConstFalse")) {
		return OP_LoadConstFalse;
	}
	if (!strcmp (mnemonic, "LoadConstZero")) {
		return OP_LoadConstZero;
	}
	/* Load parameter operations */
	if (!strcmp (mnemonic, "LoadParam")) {
		return OP_LoadParam;
	}
	if (!strcmp (mnemonic, "LoadParamLong")) {
		return OP_LoadParamLong;
	}
	/* Special register loads */
	if (!strcmp (mnemonic, "LoadThisNS")) {
		return OP_LoadThisNS;
	}
	if (!strcmp (mnemonic, "GetGlobalObject")) {
		return OP_GetGlobalObject;
	}
	if (!strcmp (mnemonic, "GetNewTarget")) {
		return OP_GetNewTarget;
	}
	/* Environment operations */
	if (!strcmp (mnemonic, "GetEnvironment")) {
		return OP_GetEnvironment;
	}
	if (!strcmp (mnemonic, "CreateEnvironment")) {
		return OP_CreateEnvironment;
	}
	if (!strcmp (mnemonic, "StoreToEnvironment")) {
		return OP_StoreToEnvironment;
	}
	if (!strcmp (mnemonic, "StoreNPToEnvironment")) {
		return OP_StoreNPToEnvironment;
	}
	if (!strcmp (mnemonic, "StoreToEnvironmentL")) {
		return OP_StoreToEnvironmentL;
	}
	if (!strcmp (mnemonic, "StoreNPToEnvironmentL")) {
		return OP_StoreNPToEnvironmentL;
	}
	if (!strcmp (mnemonic, "LoadFromEnvironment")) {
		return OP_LoadFromEnvironment;
	}
	if (!strcmp (mnemonic, "LoadFromEnvironmentL")) {
		return OP_LoadFromEnvironmentL;
	}
	/* Jump operations */
	if (!strcmp (mnemonic, "Jmp")) {
		return OP_Jmp;
	}
	if (!strcmp (mnemonic, "JmpLong")) {
		return OP_JmpLong;
	}
	if (!strcmp (mnemonic, "JmpTrue")) {
		return OP_JmpTrue;
	}
	if (!strcmp (mnemonic, "JmpTrueLong")) {
		return OP_JmpTrueLong;
	}
	if (!strcmp (mnemonic, "JmpFalse")) {
		return OP_JmpFalse;
	}
	if (!strcmp (mnemonic, "JmpFalseLong")) {
		return OP_JmpFalseLong;
	}
	if (!strcmp (mnemonic, "JmpUndefined")) {
		return OP_JmpUndefined;
	}
	if (!strcmp (mnemonic, "JmpUndefinedLong")) {
		return OP_JmpUndefinedLong;
	}
	/* Conditional jumps */
	if (!strcmp (mnemonic, "JLess")) {
		return OP_JLess;
	}
	if (!strcmp (mnemonic, "JLessN")) {
		return OP_JLessN;
	}
	if (!strcmp (mnemonic, "JLessLong")) {
		return OP_JLessLong;
	}
	if (!strcmp (mnemonic, "JLessNLong")) {
		return OP_JLessNLong;
	}
	if (!strcmp (mnemonic, "JNotLess")) {
		return OP_JNotLess;
	}
	if (!strcmp (mnemonic, "JNotLessN")) {
		return OP_JNotLessN;
	}
	if (!strcmp (mnemonic, "JNotLessLong")) {
		return OP_JNotLessLong;
	}
	if (!strcmp (mnemonic, "JNotLessNLong")) {
		return OP_JNotLessNLong;
	}
	if (!strcmp (mnemonic, "JLessEqual")) {
		return OP_JLessEqual;
	}
	if (!strcmp (mnemonic, "JLessEqualN")) {
		return OP_JLessEqualN;
	}
	if (!strcmp (mnemonic, "JLessEqualLong")) {
		return OP_JLessEqualLong;
	}
	if (!strcmp (mnemonic, "JLessEqualNLong")) {
		return OP_JLessEqualNLong;
	}
	if (!strcmp (mnemonic, "JNotLessEqual")) {
		return OP_JNotLessEqual;
	}
	if (!strcmp (mnemonic, "JNotLessEqualN")) {
		return OP_JNotLessEqualN;
	}
	if (!strcmp (mnemonic, "JNotLessEqualLong")) {
		return OP_JNotLessEqualLong;
	}
	if (!strcmp (mnemonic, "JNotLessEqualNLong")) {
		return OP_JNotLessEqualNLong;
	}
	if (!strcmp (mnemonic, "JGreater")) {
		return OP_JGreater;
	}
	if (!strcmp (mnemonic, "JGreaterN")) {
		return OP_JGreaterN;
	}
	if (!strcmp (mnemonic, "JGreaterLong")) {
		return OP_JGreaterLong;
	}
	if (!strcmp (mnemonic, "JGreaterNLong")) {
		return OP_JGreaterNLong;
	}
	if (!strcmp (mnemonic, "JNotGreater")) {
		return OP_JNotGreater;
	}
	if (!strcmp (mnemonic, "JNotGreaterN")) {
		return OP_JNotGreaterN;
	}
	if (!strcmp (mnemonic, "JNotGreaterLong")) {
		return OP_JNotGreaterLong;
	}
	if (!strcmp (mnemonic, "JNotGreaterNLong")) {
		return OP_JNotGreaterNLong;
	}
	if (!strcmp (mnemonic, "JGreaterEqual")) {
		return OP_JGreaterEqual;
	}
	if (!strcmp (mnemonic, "JGreaterEqualN")) {
		return OP_JGreaterEqualN;
	}
	if (!strcmp (mnemonic, "JGreaterEqualLong")) {
		return OP_JGreaterEqualLong;
	}
	if (!strcmp (mnemonic, "JGreaterEqualNLong")) {
		return OP_JGreaterEqualNLong;
	}
	if (!strcmp (mnemonic, "JNotGreaterEqual")) {
		return OP_JNotGreaterEqual;
	}
	if (!strcmp (mnemonic, "JNotGreaterEqualN")) {
		return OP_JNotGreaterEqualN;
	}
	if (!strcmp (mnemonic, "JNotGreaterEqualLong")) {
		return OP_JNotGreaterEqualLong;
	}
	if (!strcmp (mnemonic, "JNotGreaterEqualNLong")) {
		return OP_JNotGreaterEqualNLong;
	}
	if (!strcmp (mnemonic, "JEqual")) {
		return OP_JEqual;
	}
	if (!strcmp (mnemonic, "JEqualLong")) {
		return OP_JEqualLong;
	}
	if (!strcmp (mnemonic, "JNotEqual")) {
		return OP_JNotEqual;
	}
	if (!strcmp (mnemonic, "JNotEqualLong")) {
		return OP_JNotEqualLong;
	}
	if (!strcmp (mnemonic, "JStrictEqual")) {
		return OP_JStrictEqual;
	}
	if (!strcmp (mnemonic, "JStrictEqualLong")) {
		return OP_JStrictEqualLong;
	}
	if (!strcmp (mnemonic, "JStrictNotEqual")) {
		return OP_JStrictNotEqual;
	}
	if (!strcmp (mnemonic, "JStrictNotEqualLong")) {
		return OP_JStrictNotEqualLong;
	}
	/* Return operations */
	if (!strcmp (mnemonic, "Ret")) {
		return OP_Ret;
	}
	/* Call operations */
	if (!strcmp (mnemonic, "Call")) {
		return OP_Call;
	}
	if (!strcmp (mnemonic, "CallLong")) {
		return OP_CallLong;
	}
	if (!strcmp (mnemonic, "Call1")) {
		return OP_Call1;
	}
	if (!strcmp (mnemonic, "Call2")) {
		return OP_Call2;
	}
	if (!strcmp (mnemonic, "Call3")) {
		return OP_Call3;
	}
	if (!strcmp (mnemonic, "Call4")) {
		return OP_Call4;
	}
	if (!strcmp (mnemonic, "CallDirect")) {
		return OP_CallDirect;
	}
	if (!strcmp (mnemonic, "CallDirectLongIndex")) {
		return OP_CallDirectLongIndex;
	}
	if (!strcmp (mnemonic, "Construct")) {
		return OP_Construct;
	}
	if (!strcmp (mnemonic, "ConstructLong")) {
		return OP_ConstructLong;
	}
	if (!strcmp (mnemonic, "CallBuiltin")) {
		return OP_CallBuiltin;
	}
	if (!strcmp (mnemonic, "CallBuiltinLong")) {
		return OP_CallBuiltinLong;
	}
	/* Property access */
	if (!strcmp (mnemonic, "GetByIdShort")) {
		return OP_GetByIdShort;
	}
	if (!strcmp (mnemonic, "GetById")) {
		return OP_GetById;
	}
	if (!strcmp (mnemonic, "GetByIdLong")) {
		return OP_GetByIdLong;
	}
	if (!strcmp (mnemonic, "TryGetById")) {
		return OP_TryGetById;
	}
	if (!strcmp (mnemonic, "TryGetByIdLong")) {
		return OP_TryGetByIdLong;
	}
	if (!strcmp (mnemonic, "GetByVal")) {
		return OP_GetByVal;
	}
	if (!strcmp (mnemonic, "PutById")) {
		return OP_PutById;
	}
	if (!strcmp (mnemonic, "PutByIdLong")) {
		return OP_PutByIdLong;
	}
	if (!strcmp (mnemonic, "TryPutById")) {
		return OP_TryPutById;
	}
	if (!strcmp (mnemonic, "TryPutByIdLong")) {
		return OP_TryPutByIdLong;
	}
	if (!strcmp (mnemonic, "PutByVal")) {
		return OP_PutByVal;
	}
	if (!strcmp (mnemonic, "PutNewOwnByIdShort")) {
		return OP_PutNewOwnByIdShort;
	}
	if (!strcmp (mnemonic, "PutNewOwnById")) {
		return OP_PutNewOwnById;
	}
	if (!strcmp (mnemonic, "PutNewOwnByIdLong")) {
		return OP_PutNewOwnByIdLong;
	}
	if (!strcmp (mnemonic, "PutNewOwnNEById")) {
		return OP_PutNewOwnNEById;
	}
	if (!strcmp (mnemonic, "PutNewOwnNEByIdLong")) {
		return OP_PutNewOwnNEByIdLong;
	}
	if (!strcmp (mnemonic, "PutOwnByIndex")) {
		return OP_PutOwnByIndex;
	}
	if (!strcmp (mnemonic, "PutOwnByIndexL")) {
		return OP_PutOwnByIndexL;
	}
	if (!strcmp (mnemonic, "PutOwnByVal")) {
		return OP_PutOwnByVal;
	}
	if (!strcmp (mnemonic, "DelById")) {
		return OP_DelById;
	}
	if (!strcmp (mnemonic, "DelByIdLong")) {
		return OP_DelByIdLong;
	}
	if (!strcmp (mnemonic, "DelByVal")) {
		return OP_DelByVal;
	}
	/* Object/Array creation */
	if (!strcmp (mnemonic, "NewObject")) {
		return OP_NewObject;
	}
	if (!strcmp (mnemonic, "NewObjectWithParent")) {
		return OP_NewObjectWithParent;
	}
	if (!strcmp (mnemonic, "NewObjectWithBuffer")) {
		return OP_NewObjectWithBuffer;
	}
	if (!strcmp (mnemonic, "NewObjectWithBufferLong")) {
		return OP_NewObjectWithBufferLong;
	}
	if (!strcmp (mnemonic, "NewArray")) {
		return OP_NewArray;
	}
	if (!strcmp (mnemonic, "NewArrayWithBuffer")) {
		return OP_NewArrayWithBuffer;
	}
	if (!strcmp (mnemonic, "NewArrayWithBufferLong")) {
		return OP_NewArrayWithBufferLong;
	}
	/* Closure/Generator creation */
	if (!strcmp (mnemonic, "CreateClosure")) {
		return OP_CreateClosure;
	}
	if (!strcmp (mnemonic, "CreateClosureLongIndex")) {
		return OP_CreateClosureLongIndex;
	}
	if (!strcmp (mnemonic, "CreateGeneratorClosure")) {
		return OP_CreateGeneratorClosure;
	}
	if (!strcmp (mnemonic, "CreateGeneratorClosureLongIndex")) {
		return OP_CreateGeneratorClosureLongIndex;
	}
	if (!strcmp (mnemonic, "CreateAsyncClosure")) {
		return OP_CreateAsyncClosure;
	}
	if (!strcmp (mnemonic, "CreateAsyncClosureLongIndex")) {
		return OP_CreateAsyncClosureLongIndex;
	}
	if (!strcmp (mnemonic, "CreateGenerator")) {
		return OP_CreateGenerator;
	}
	if (!strcmp (mnemonic, "CreateGeneratorLongIndex")) {
		return OP_CreateGeneratorLongIndex;
	}
	if (!strcmp (mnemonic, "CreateThis")) {
		return OP_CreateThis;
	}
	if (!strcmp (mnemonic, "SelectObject")) {
		return OP_SelectObject;
	}
	/* Exception handling */
	if (!strcmp (mnemonic, "Throw")) {
		return OP_Throw;
	}
	if (!strcmp (mnemonic, "ThrowIfEmpty")) {
		return OP_ThrowIfEmpty;
	}
	if (!strcmp (mnemonic, "Catch")) {
		return OP_Catch;
	}
	/* Memory operations */
	if (!strcmp (mnemonic, "Loadi8")) {
		return OP_Loadi8;
	}
	if (!strcmp (mnemonic, "Loadu8")) {
		return OP_Loadu8;
	}
	if (!strcmp (mnemonic, "Loadi16")) {
		return OP_Loadi16;
	}
	if (!strcmp (mnemonic, "Loadu16")) {
		return OP_Loadu16;
	}
	if (!strcmp (mnemonic, "Loadi32")) {
		return OP_Loadi32;
	}
	if (!strcmp (mnemonic, "Loadu32")) {
		return OP_Loadu32;
	}
	if (!strcmp (mnemonic, "Store8")) {
		return OP_Store8;
	}
	if (!strcmp (mnemonic, "Store16")) {
		return OP_Store16;
	}
	if (!strcmp (mnemonic, "Store32")) {
		return OP_Store32;
	}
	/* Arguments operations */
	if (!strcmp (mnemonic, "GetArgumentsPropByVal")) {
		return OP_GetArgumentsPropByVal;
	}
	if (!strcmp (mnemonic, "GetArgumentsLength")) {
		return OP_GetArgumentsLength;
	}
	if (!strcmp (mnemonic, "ReifyArguments")) {
		return OP_ReifyArguments;
	}
	/* Iterator operations */
	if (!strcmp (mnemonic, "IteratorBegin")) {
		return OP_IteratorBegin;
	}
	if (!strcmp (mnemonic, "IteratorNext")) {
		return OP_IteratorNext;
	}
	if (!strcmp (mnemonic, "IteratorClose")) {
		return OP_IteratorClose;
	}
	if (!strcmp (mnemonic, "GetPNameList")) {
		return OP_GetPNameList;
	}
	if (!strcmp (mnemonic, "GetNextPName")) {
		return OP_GetNextPName;
	}
	/* Generator operations */
	if (!strcmp (mnemonic, "StartGenerator")) {
		return OP_StartGenerator;
	}
	if (!strcmp (mnemonic, "ResumeGenerator")) {
		return OP_ResumeGenerator;
	}
	if (!strcmp (mnemonic, "CompleteGenerator")) {
		return OP_CompleteGenerator;
	}
	if (!strcmp (mnemonic, "SaveGenerator")) {
		return OP_SaveGenerator;
	}
	if (!strcmp (mnemonic, "SaveGeneratorLong")) {
		return OP_SaveGeneratorLong;
	}
	/* Direct eval */
	if (!strcmp (mnemonic, "DirectEval")) {
		return OP_DirectEval;
	}
	/* Debug/profiling */
	if (!strcmp (mnemonic, "Unreachable")) {
		return OP_Unreachable;
	}
	if (!strcmp (mnemonic, "Debugger")) {
		return OP_Debugger;
	}
	if (!strcmp (mnemonic, "AsyncBreakCheck")) {
		return OP_AsyncBreakCheck;
	}
	if (!strcmp (mnemonic, "ProfilePoint")) {
		return OP_ProfilePoint;
	}
	/* Other operations */
	if (!strcmp (mnemonic, "GetBuiltinClosure")) {
		return OP_GetBuiltinClosure;
	}
	if (!strcmp (mnemonic, "CreateRegExp")) {
		return OP_CreateRegExp;
	}
	if (!strcmp (mnemonic, "SwitchImm")) {
		return OP_SwitchImm;
	}
	if (!strcmp (mnemonic, "DeclareGlobalVar")) {
		return OP_DeclareGlobalVar;
	}
	if (!strcmp (mnemonic, "ThrowIfHasRestrictedGlobalProperty")) {
		return OP_ThrowIfHasRestrictedGlobalProperty;
	}
	if (!strcmp (mnemonic, "CreateInnerEnvironment")) {
		return OP_CreateInnerEnvironment;
	}
	if (!strcmp (mnemonic, "PutOwnGetterSetterByVal")) {
		return OP_PutOwnGetterSetterByVal;
	}
	return -1;
}

static void set_esil(RAnalOp *op, const char *mnemonic, const u8 *bytes, ut64 addr) {
	int opcode = mnemonic_to_canonical_opcode (mnemonic);
	if (opcode < 0) {
		return;
	}
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
		r_strbuf_setf (&op->esil, "");
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
			r_strbuf_setf (&op->esil, "");
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
		{
			r_strbuf_setf (&op->esil, "");
			break;
		}
	default:
		break;
	}
}

static bool load_string_tables(HermesArchSession *hs, RArchSession *s) {
	if (!hs || !s || !s->arch || !s->arch->binb.bin) {
		return false;
	}

	RBin *bin = s->arch->binb.bin;
	RBinInfo *bi = r_bin_get_info (bin);
	if (!bi || !bi->file) {
		return false;
	}

	/* Try to open the file with hermesdec */
	if (hs->hd) {
		hbc_close (hs->hd);
		hs->hd = NULL;
	}

	Result res = hbc_open (bi->file, &hs->hd);
	if (res.code != RESULT_SUCCESS) {
		return false;
	}

	/* If we can, get the file header to determine exact bytecode version */
	HBCHeader hh;
	if (hbc_get_header (hs->hd, &hh).code == RESULT_SUCCESS) {
		/* Cache version for instruction set selection */
		hs->bytecode_version = hh.version;
	}

	/* Get string count */
	hs->string_count = hbc_string_count (hs->hd);

	/* Extract string tables using the API */
	HBCStringTables tables;
	Result table_res = hbc_get_string_tables (hs->hd, &tables);
	if (table_res.code != RESULT_SUCCESS) {
		return false;
	}
	hs->string_count = tables.string_count;
	hs->small_string_table = tables.small_string_table;
	hs->overflow_string_table = tables.overflow_string_table;
	hs->string_storage_offset = tables.string_storage_offset;

	return true;
}

static const Instruction *get_instruction_set_by_version(ut32 version, ut32 *out_count) {
	HBCISA isa = hbc_isa_getv (version);
	if (out_count) {
		*out_count = isa.count;
	}
	return isa.instructions;
}

static bool opcode_is_conditional(u8 opcode) {
	switch (opcode) {
	case OP_JmpTrue:
	case OP_JmpTrueLong:
	case OP_JmpFalse:
	case OP_JmpFalseLong:
	case OP_JmpUndefined:
	case OP_JmpUndefinedLong:
		return true;
	default:
		break;
	}
	/* Relational and equality conditional jumps occupy 152..191 */
	if (opcode >= OP_JLess && opcode <= OP_JStrictNotEqualLong) {
		return true;
	}
	return false;
}

static void parse_operands_and_set_ptr(RAnalOp *op, const ut8 *bytes, ut32 size, ut8 opcode, HermesArchSession *hs) {
	ut32 count;
	const Instruction *inst_set = get_instruction_set_by_version (hs->bytecode_version, &count);
	if (!inst_set || opcode >= count) {
		return;
	}

	const Instruction *inst = &inst_set[opcode];
	if (!inst) {
		return;
	}

	// Parse operands
	ut32 operand_values[6] = { 0 };
	size_t pos = 1; // Skip opcode byte

	for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
		if (pos >= size) {
			break;
		}

		switch (inst->operands[i].operand_type) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_UINT8:
		case OPERAND_TYPE_ADDR8:
			if (pos < size) {
				operand_values[i] = bytes[pos];
				pos += 1;
			}
			break;
		case OPERAND_TYPE_UINT16:
			if (pos + 1 < size) {
				operand_values[i] = (bytes[pos + 1] << 8) | bytes[pos];
				pos += 2;
			}
			break;
		case OPERAND_TYPE_REG32:
		case OPERAND_TYPE_UINT32:
		case OPERAND_TYPE_ADDR32:
			if (pos + 3 < size) {
				operand_values[i] = (bytes[pos + 3] << 24) | (bytes[pos + 2] << 16) |
					(bytes[pos + 1] << 8) | bytes[pos];
				pos += 4;
			}
			break;
		default:
			break;
		}

		// Check if this operand is a string ID
		if (inst->operands[i].operand_meaning == OPERAND_MEANING_STRING_ID) {
			ut32 string_id = operand_values[i];
			if (string_id < hs->string_count && hs->hd) {
				HBCStringMeta meta;
				Result meta_result = hbc_get_string_meta (hs->hd, string_id, &meta);
				if (meta_result.code == RESULT_SUCCESS) {
					/* Set op->ptr to the virtual address of the string.
					 * The binary is loaded at 0x10000000, so add the string offset to that. */
					op->ptr = (st64) (0x10000000 + hs->string_storage_offset + meta.offset);
				}
			}
		}
		// Check if this operand is a function ID
		else if (inst->operands[i].operand_meaning == OPERAND_MEANING_FUNCTION_ID) {
			ut32 function_id = operand_values[i];
			if (hs->hd) {
				ut32 offset = 0;
				HBCFunctionInfo fi;
				Result func_result = hbc_get_function_info (hs->hd, function_id, &fi);
				if (func_result.code == RESULT_SUCCESS) {
					// name = fi.name;
					offset = fi.offset;
					(void)fi.size;
					(void)fi.param_count;
					// Set op->ptr to the function address as a file offset
					op->ptr = (st64)offset;
				}
			}
		}
	}
}

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (s && op, false);
	(void)mask;

	if (!op->bytes) {
		return false;
	}

	HermesArchSession *hs = (HermesArchSession *)s->data;
	if (!hs) {
		return false;
	}

	if (!hs->bytecode_version) {
		hs->bytecode_version = detect_version_from_bin (s);
	}

	/* Load string tables if not already loaded */
	if (!hs->hd) {
		load_string_tables (hs, s);
	}

	/* Build decode context */
	HBCStringTables string_tables = {
		.string_count = hs->string_count,
		.small_string_table = hs->small_string_table,
		.overflow_string_table = hs->overflow_string_table,
		.string_storage_offset = hs->string_storage_offset
	};
	HBCDecodeContext ctx = {
		.bytes = op->bytes,
		.len = MAX_OP_SIZE,
		.pc = op->addr,
		.bytecode_version = hs->bytecode_version,
		.asm_syntax = true,
		.resolve_string_ids = true,
		.string_tables = &string_tables
	};

	HBCSingleInstructionInfo sinfo;
	if (hbc_decode (&ctx, &sinfo).code != RESULT_SUCCESS) {
		return false;
	}

	op->mnemonic = sinfo.text? strdup (sinfo.text): strdup ("unk");
	op->size = sinfo.size? sinfo.size: 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;

	/* Parse operands and set ptr for string/function references */
	parse_operands_and_set_ptr (op, op->bytes, op->size, sinfo.opcode, hs);

	if (sinfo.text) {
		char mnemonic_raw[64];
		const char *end = sinfo.text;
		while (*end && *end != ' ' && *end != '\t') {
			end++;
		}
		size_t len = end - sinfo.text;
		if (len > 0 && len < sizeof (mnemonic_raw)) {
			memcpy (mnemonic_raw, sinfo.text, len);
			mnemonic_raw[len] = '\0';
			char mnemonic[64];
			snake_to_camel (mnemonic_raw, mnemonic, sizeof (mnemonic));
			set_esil (op, mnemonic, op->bytes, op->addr);
		}
	}

	if (sinfo.opcode == OP_Ret) {
		op->type = R_ANAL_OP_TYPE_RET;
		return true;
	}

	if (opcode_is_conditional (sinfo.opcode)) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = sinfo.jump_target;
		op->fail = op->addr + op->size;
		return true;
	}

	if (sinfo.is_jump) {
		op->type = R_ANAL_OP_TYPE_JMP;
	}

	if (sinfo.opcode == OP_Jmp || sinfo.opcode == OP_JmpLong) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = sinfo.jump_target;
		return true;
	}

	if (sinfo.is_call) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = sinfo.jump_target;
		op->fail = op->addr + op->size;
		return true;
	}

	/* Classify opcode type */
	u8 opc = sinfo.opcode;

	switch (opc) {
	/* Arithmetic operations */
	case OP_Add:
	case OP_AddN:
	case OP_Add32:
	case OP_AddEmptyString:
	case OP_Inc:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case OP_Sub:
	case OP_SubN:
	case OP_Sub32:
	case OP_Dec:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case OP_Mul:
	case OP_MulN:
	case OP_Mul32:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case OP_Div:
	case OP_DivN:
	case OP_Divi32:
	case OP_Divu32:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case OP_Mod:
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	/* Bitwise operations */
	case OP_BitAnd:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case OP_BitOr:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case OP_BitXor:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case OP_BitNot:
	case OP_Not:
	case OP_Negate:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case OP_LShift:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case OP_RShift:
	case OP_URshift:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	/* Move operations */
	case OP_Mov:
	case OP_MovLong:
	case OP_Catch:
	case OP_SelectObject:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	/* Load operations */
	case OP_Loadi8:
	case OP_Loadu8:
	case OP_Loadi16:
	case OP_Loadu16:
	case OP_Loadi32:
	case OP_Loadu32:
	case OP_GetById:
	case OP_GetByIdLong:
	case OP_GetByIdShort:
	case OP_GetByVal:
	case OP_TryGetById:
	case OP_TryGetByIdLong:
	case OP_LoadFromEnvironment:
	case OP_LoadFromEnvironmentL:
	case OP_GetEnvironment:
	case OP_LoadParam:
	case OP_LoadParamLong:
	case OP_LoadConstUInt8:
	case OP_LoadConstInt:
	case OP_LoadConstDouble:
	case OP_LoadConstBigInt:
	case OP_LoadConstBigIntLongIndex:
	case OP_LoadConstString:
	case OP_LoadConstStringLongIndex:
	case OP_LoadConstEmpty:
	case OP_LoadConstUndefined:
	case OP_LoadConstNull:
	case OP_LoadConstTrue:
	case OP_LoadConstFalse:
	case OP_LoadConstZero:
	case OP_LoadThisNS:
	case OP_GetBuiltinClosure:
	case OP_GetGlobalObject:
	case OP_GetNewTarget:
	case OP_GetArgumentsPropByVal:
	case OP_GetArgumentsLength:
	case OP_GetPNameList:
	case OP_GetNextPName:
	case OP_IteratorBegin:
	case OP_IteratorNext:
	case OP_IteratorClose:
	case OP_ReifyArguments:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	/* Store operations */
	case OP_Store8:
	case OP_Store16:
	case OP_Store32:
	case OP_PutById:
	case OP_PutByIdLong:
	case OP_PutByVal:
	case OP_TryPutById:
	case OP_TryPutByIdLong:
	case OP_PutNewOwnById:
	case OP_PutNewOwnByIdLong:
	case OP_PutNewOwnByIdShort:
	case OP_PutNewOwnNEById:
	case OP_PutNewOwnNEByIdLong:
	case OP_PutOwnByIndex:
	case OP_PutOwnByIndexL:
	case OP_PutOwnByVal:
	case OP_PutOwnGetterSetterByVal:
	case OP_StoreToEnvironment:
	case OP_StoreToEnvironmentL:
	case OP_StoreNPToEnvironment:
	case OP_StoreNPToEnvironmentL:
	case OP_CreateEnvironment:
	case OP_CreateInnerEnvironment:
	case OP_DeclareGlobalVar:
	case OP_ThrowIfHasRestrictedGlobalProperty:
	case OP_DelById:
	case OP_DelByIdLong:
	case OP_DelByVal:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	/* Comparison operations */
	case OP_Eq:
	case OP_StrictEq:
	case OP_Neq:
	case OP_StrictNeq:
	case OP_Less:
	case OP_Greater:
	case OP_LessEq:
	case OP_GreaterEq:
	case OP_IsIn:
	case OP_InstanceOf:
	case OP_TypeOf:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	/* Object/Array creation */
	case OP_NewObject:
	case OP_NewObjectWithParent:
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
	case OP_NewArray:
	case OP_NewArrayWithBuffer:
	case OP_NewArrayWithBufferLong:
	case OP_CreateClosure:
	case OP_CreateClosureLongIndex:
	case OP_CreateGeneratorClosure:
	case OP_CreateGeneratorClosureLongIndex:
	case OP_CreateAsyncClosure:
	case OP_CreateAsyncClosureLongIndex:
	case OP_CreateGenerator:
	case OP_CreateGeneratorLongIndex:
	case OP_CreateThis:
	case OP_CreateRegExp:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	/* Type conversion operations */
	case OP_ToNumber:
	case OP_ToNumeric:
	case OP_ToInt32:
	case OP_CoerceThisNS:
		op->type = R_ANAL_OP_TYPE_CAST;
		break;
	/* Switch operations */
	case OP_SwitchImm:
		op->type = R_ANAL_OP_TYPE_SWITCH;
		break;
	/* Special operations */
	case OP_Unreachable:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case OP_Throw:
	case OP_ThrowIfEmpty:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case OP_Debugger:
		op->type = R_ANAL_OP_TYPE_DEBUG;
		break;
	case OP_AsyncBreakCheck:
	case OP_ProfilePoint:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case OP_StartGenerator:
	case OP_ResumeGenerator:
	case OP_CompleteGenerator:
	case OP_SaveGenerator:
	case OP_SaveGeneratorLong:
	case OP_DirectEval:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	default:
		break;
	}
	return true;
}

static int info(RArchSession *s, ut32 q) {
	(void)s;
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 1;
	case R_ARCH_INFO_ISVM:
		return R_ARCH_INFO_ISVM;
	case R_ARCH_INFO_MAXOP_SIZE:
		return MAX_OP_SIZE;
	case R_ARCH_INFO_INVOP_SIZE:
		return 1;
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return 0;
}

static char *mnemonics(RArchSession *s, int id, bool json) {
	(void)s;
	(void)id;
	(void)json;
	return NULL;
}

static bool encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	(void)mask;
	R_RETURN_VAL_IF_FAIL (s && op, false);

	HermesArchSession *hs = (HermesArchSession *)s->data;
	if (!hs || !op->mnemonic) {
		return false;
	}

	if (!hs->bytecode_version) {
		hs->bytecode_version = detect_version_from_bin (s);
		if (!hs->bytecode_version) {
			hs->bytecode_version = 96;
		}
	}

	const char *asm_line = op->mnemonic;

	/* Conservative buffer for a single instruction */
	ut8 tmp[MAX_OP_SIZE];
	size_t written = 0;

	HBCEncodeBuffer outbuf = { .buffer = tmp, .buffer_size = sizeof (tmp), .bytes_written = 0 };
	Result res = hbc_encode_instruction (
		asm_line,
		hs->bytecode_version,
		&outbuf);
	written = outbuf.bytes_written;
	if (res.code != RESULT_SUCCESS || written == 0 || written > sizeof (tmp)) {
		return false;
	}

	/* Store into op */
	free (op->bytes);
	op->bytes = (ut8 *)malloc (written);
	if (!op->bytes) {
		op->size = 0;
		return false;
	}
	memcpy (op->bytes, tmp, written);
	op->size = (int)written;
	return true;
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	s->data = R_NEW0 (HermesArchSession);
	HermesArchSession *hs = (HermesArchSession *)s->data;
	hs->bytecode_version = 0;
	return true;
}

static bool fini(RArchSession *s) {
	if (!s) {
		return false;
	}
	HermesArchSession *hs = (HermesArchSession *)s->data;
	if (hs) {
		if (hs->hd) {
			hbc_close (hs->hd);
			hs->hd = NULL;
		}
		free (hs);
		s->data = NULL;
	}
	return true;
}

/* Register profile for ESIL emulation */
static char *regs(RArchSession *s) {
	(void)s;
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}

	/* Define special registers */
	r_strbuf_append (sb, "=PC\tpc\n");
	r_strbuf_append (sb, "=SP\tr0\n");
	r_strbuf_append (sb, "=BP\tr1\n");
	r_strbuf_append (sb, "=A0\tr2\n");
	r_strbuf_append (sb, "=A1\tr3\n");
	r_strbuf_append (sb, "=A2\tr4\n");
	r_strbuf_append (sb, "=A3\tr5\n");

	/* Program counter - 64 bits at offset 0 */
	r_strbuf_append (sb, "gpr\tpc\t.64\t0\t0\n");

	/* Hermes VM has r0-r255 registers (256 total) */
	for (int i = 0; i < 256; i++) {
		r_strbuf_appendf (sb, "gpr\tr%d\t.64\t%d\t0\n", i, 8 + (i * 8));
	}

	return r_strbuf_drain (sb);
}

const RArchPlugin r_arch_plugin_hermes = {
	.meta = {
		.name = "hbc.arch",
		.author = "pancake",
		.desc = "Hermes bytecode disassembler",
		.license = "BSD",
	},
	.arch = "hbc",
	.bits = R_SYS_BITS_PACK1 (64),
	.cpus = "v76,v90,v91,v92,v93,v94,v95,v96",
	.decode = &decode,
	.encode = &encode,
	.regs = regs,
	.info = info,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = (void *)&r_arch_plugin_hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
