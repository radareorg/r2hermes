#include "../../include/opcodes/hermes_opcodes.h"
#include <stdlib.h>

/* Define instruction set for bytecode version 96 */
static Instruction *get_instruction_set_v96(u32 *out_count) {
	/* Allocate memory for the instruction set */
	const u32 instruction_count = 256; /* Support all possible opcode values */
	Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
	if (!instructions) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	/* Initialize all instructions to NULL/invalid */
	for (u32 i = 0; i < instruction_count; i++) {
		instructions[i] = (Instruction){
			(u8)i, "Unknown",
			{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
			1 /* Assume 1 byte size for unknown instructions */
		};
	}

	/* Report count to caller */
	if (out_count) {
		*out_count = instruction_count;
	}

	/* Add basic instructions based on hbc95.py */
	/* Simple moves and unary ops */
	
/* removed duplicate definition of OP_Mov */


	
/* removed duplicate definition of OP_MovLong */


	instructions[OP_Negate] = (Instruction){
		OP_Negate, "Negate",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	
/* removed duplicate definition of OP_Not */


	
/* removed duplicate definition of OP_BitNot */


	/* Equality and relational */
	
/* removed duplicate definition of OP_Eq */


	
/* removed duplicate definition of OP_Less */


	
/* removed duplicate definition of OP_LessEq */


	
/* removed duplicate definition of OP_Greater */


	
/* removed duplicate definition of OP_GreaterEq */


	instructions[OP_AddN] = (Instruction){
		OP_AddN, "AddN",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_SubN] = (Instruction){
		OP_SubN, "SubN",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_MulN] = (Instruction){
		OP_MulN, "MulN",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_DivN] = (Instruction){
		OP_DivN, "DivN",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	
/* removed duplicate definition of OP_LShift */


	
/* removed duplicate definition of OP_RShift */


	
/* removed duplicate definition of OP_URshift */


	instructions[OP_Inc] = (Instruction){
		OP_Inc, "Inc",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_Dec] = (Instruction){
		OP_Dec, "Dec",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_IsIn] = (Instruction){
		OP_IsIn, "IsIn",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	/* Environment load/store */
	
/* removed duplicate definition of OP_StoreToEnvironment */


	instructions[OP_StoreToEnvironmentL] = (Instruction){
		OP_StoreToEnvironmentL, "StoreToEnvironmentL",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		6 /* opcode + 1 + 2 + 1 */
	};

	instructions[OP_StoreNPToEnvironment] = (Instruction){
		OP_StoreNPToEnvironment, "StoreNPToEnvironment",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_StoreNPToEnvironmentL] = (Instruction){
		OP_StoreNPToEnvironmentL, "StoreNPToEnvironmentL",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		6
	};

	
/* removed duplicate definition of OP_LoadFromEnvironment */


	instructions[OP_LoadFromEnvironmentL] = (Instruction){
		OP_LoadFromEnvironmentL, "LoadFromEnvironmentL",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE } },
		5
	};
	instructions[OP_Unreachable] = (Instruction){
		OP_Unreachable, "Unreachable",
		{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
		1 /* opcode only */
	};

	instructions[OP_NewObjectWithBuffer] = (Instruction){
		OP_NewObjectWithBuffer, "NewObjectWithBuffer",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Key count */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Value count */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_OBJ_KEY_ID }, /* Keys id */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_OBJ_VAL_ID } }, /* Values id */
		10 /* opcode + 1 + 2 + 2 + 2 + 2 */
	};

	instructions[OP_NewArrayWithBuffer] = (Instruction){
		OP_NewArrayWithBuffer, "NewArrayWithBuffer",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Key count */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Value count */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_ARRAY_ID } }, /* Array idx */
		8 /* opcode + 1 + 2 + 2 + 2 */
	};

	instructions[OP_NewArrayWithBufferLong] = (Instruction){
		OP_NewArrayWithBufferLong, "NewArrayWithBufferLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Key count */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Value count */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_ARRAY_ID } }, /* Array idx */
		10 /* opcode + 1 + 2 + 2 + 4 */
	};

	instructions[OP_NewObjectWithBufferLong] = (Instruction){
		OP_NewObjectWithBufferLong, "NewObjectWithBufferLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Key count */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, /* Value count */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_OBJ_KEY_ID }, /* Keys id */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_OBJ_VAL_ID } }, /* Values id */
		14 /* opcode + 1 + 2 + 2 + 4 + 4 */
	};

	
/* removed duplicate definition of OP_Jmp */


	instructions[OP_JmpTrue] = (Instruction){
		OP_JmpTrue, "JmpTrue",
		{ { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3 /* opcode + offset + reg */
	};

	instructions[OP_JmpFalse] = (Instruction){
		OP_JmpFalse, "JmpFalse",
		{ { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3 /* opcode + offset + reg */
	};

	instructions[OP_JmpUndefined] = (Instruction){
		OP_JmpUndefined, "JmpUndefined",
		{ { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3 /* opcode + offset + reg */
	};

	
/* removed duplicate definition of OP_JmpLong */


	instructions[OP_Catch] = (Instruction){
		OP_Catch, "Catch",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		2 /* opcode + reg */
	};

	instructions[OP_Throw] = (Instruction){
		OP_Throw, "Throw",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		2 /* opcode + reg */
	};

	instructions[OP_ThrowIfEmpty] = (Instruction){
		OP_ThrowIfEmpty, "ThrowIfEmpty",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_ThrowIfUndefinedInst] = (Instruction){
		OP_ThrowIfUndefinedInst, "ThrowIfUndefinedInst",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		2
	};

	instructions[OP_JmpTrueLong] = (Instruction){
		OP_JmpTrueLong, "JmpTrueLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE } },
		6 /* opcode + reg + long offset */
	};

	instructions[OP_JmpFalseLong] = (Instruction){
		OP_JmpFalseLong, "JmpFalseLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE } },
		6 /* opcode + reg + long offset */
	};

	instructions[OP_JmpUndefinedLong] = (Instruction){
		OP_JmpUndefinedLong, "JmpUndefinedLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE } },
		6 /* opcode + reg + long offset */
	};

	/* Call instructions */
	
/* removed duplicate definition of OP_Call */


	instructions[OP_CallLong] = (Instruction){
		OP_CallLong, "CallLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Callee */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* This */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Argc */
		6
	};

	instructions[OP_Construct] = (Instruction){
		OP_Construct, "Construct",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Callee */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* This */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Argc */
		4
	};

	instructions[OP_ConstructLong] = (Instruction){
		OP_ConstructLong, "ConstructLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Callee */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* This */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Argc */
		6
	};

	/* CallN is not present in the current opcode set */

	/* ConstructN is not present in the current opcode set */

	
/* removed duplicate definition of OP_CallDirect */


	instructions[OP_CallDirectLongIndex] = (Instruction){
		OP_CallDirectLongIndex, "CallDirectLongIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* This */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Argc */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_FUNCTION_ID } }, /* Function ID */
		7
	};

	instructions[OP_CallBuiltin] = (Instruction){
		OP_CallBuiltin, "CallBuiltin",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* This */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_BUILTIN_ID }, /* Builtin ID */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Argc */
		4
	};

	instructions[OP_CallBuiltinLong] = (Instruction){
		OP_CallBuiltinLong, "CallBuiltinLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* This */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_BUILTIN_ID }, /* Builtin ID */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Argc (u32) */
		7
	};

	/* Builtin closure accessor */
	instructions[OP_GetBuiltinClosure] = (Instruction){
		OP_GetBuiltinClosure, "GetBuiltinClosure",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_BUILTIN_ID } },
		3
	};

	/* Load/Store instructions */
	instructions[OP_LoadParam] = (Instruction){
		OP_LoadParam, "LoadParam",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Parameter index */
		3 /* opcode + 2 operands */
	};

	instructions[OP_LoadParamLong] = (Instruction){
		OP_LoadParamLong, "LoadParamLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Parameter index (u32) */
		6 /* opcode + 1 + 4 */
	};

	instructions[OP_LoadConstZero] = (Instruction){
		OP_LoadConstZero, "LoadConstZero",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Destination register */
		2 /* opcode + 1 operand */
	};

	
/* removed duplicate definition of OP_LoadConstUndefined */


	
/* removed duplicate definition of OP_LoadConstNull */


	
/* removed duplicate definition of OP_LoadConstTrue */


	
/* removed duplicate definition of OP_LoadConstFalse */


	/* Additional core ops in v95 */
	instructions[OP_ToInt32] = (Instruction){
		OP_ToInt32, "ToInt32",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_AddEmptyString] = (Instruction){
		OP_AddEmptyString, "AddEmptyString",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_GetArgumentsPropByVal] = (Instruction){
		OP_GetArgumentsPropByVal, "GetArgumentsPropByVal",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_GetArgumentsLength] = (Instruction){
		OP_GetArgumentsLength, "GetArgumentsLength",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_ReifyArguments] = (Instruction){
		OP_ReifyArguments, "ReifyArguments",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		2
	};

	/* Missing PutOwnByVal */
	instructions[OP_PutOwnByVal] = (Instruction){
		OP_PutOwnByVal, "PutOwnByVal",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Obj */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Key */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Val */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Attrs */
		5
	};

	
/* removed duplicate definition of OP_LoadConstString */


	instructions[OP_LoadConstStringLongIndex] = (Instruction){
		OP_LoadConstStringLongIndex, "LoadConstStringLongIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* String ID */
		6 /* opcode + reg + 4-byte string ID */
	};

	/* Using OP_LoadConstDouble instead of LoadConstNumber */
	
/* removed duplicate definition of OP_LoadConstDouble */


	instructions[OP_LoadConstBigInt] = (Instruction){
		OP_LoadConstBigInt, "LoadConstBigInt",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_BIGINT_ID } }, /* BigInt ID */
		4 /* opcode + reg + 2-byte bigint ID */
	};

	instructions[OP_LoadConstBigIntLongIndex] = (Instruction){
		OP_LoadConstBigIntLongIndex, "LoadConstBigIntLongIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_BIGINT_ID } }, /* BigInt ID (u32) */
		6 /* opcode + reg + 4 */
	};

	instructions[OP_LoadConstEmpty] = (Instruction){
		OP_LoadConstEmpty, "LoadConstEmpty",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Destination register */
		2 /* opcode + 1 operand */
	};

	/* Using OP_LoadThisNS instead of LoadThis */
	instructions[OP_LoadThisNS] = (Instruction){
		OP_LoadThisNS, "LoadThisNS",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Destination register */
		2 /* opcode + 1 operand */
	};

	/* Basic arithmetic operations */
	
/* removed duplicate definition of OP_Add */


	
/* removed duplicate definition of OP_Sub */


	
/* removed duplicate definition of OP_Mul */


	
/* removed duplicate definition of OP_Div */


	
/* removed duplicate definition of OP_Mod */


	/* Unary operations */
	instructions[OP_Not] = (Instruction){
		OP_Not, "Not",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Source operand */
		3 /* opcode + 2 regs */
	};

	instructions[OP_BitNot] = (Instruction){
		OP_BitNot, "BitNot",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Source operand */
		3 /* opcode + 2 regs */
	};

	/* Bitwise operations */
	
/* removed duplicate definition of OP_BitAnd */


	
/* removed duplicate definition of OP_BitOr */


	
/* removed duplicate definition of OP_BitXor */


	/* Using OP_LShift instead of BitShl */
	instructions[OP_LShift] = (Instruction){
		OP_LShift, "LShift",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERA
/* removed duplicate definition of OP_LShift */


	/* Using OP_RShift instead of BitShr */
	instructions[OP_RShift] = (Instruction){
		OP_RShift, "RShift",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERA
/* removed duplicate definition of OP_RShift */


	/* Using OP_URshift instead of BitUshr */
	instructions[OP_URshift] = (Instruction){
		OP_URshift, "URshift",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPER
/* removed duplicate definition of OP_URshift */


	/* Comparison instructions */
	instructions[OP_Less] = (Instruction){
		OP_Less, "Less",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERAND
/* removed duplicate definition of OP_Less */


	instructions[OP_Greater] = (Instruction){
		OP_Greater, "Greater",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPER
/* removed duplicate definition of OP_Greater */


	instructions[OP_LessEq] = (Instruction){
		OP_LessEq, "LessEq",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERA
/* removed duplicate definition of OP_LessEq */


	instructions[OP_GreaterEq] = (Instruction){
		OP_GreaterEq, "GreaterEq",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OP
/* removed duplicate definition of OP_GreaterEq */


	instructions[OP_Eq] = (Instruction){
		OP_Eq, "Eq",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERAND_M
/* removed duplicate definition of OP_Eq */


	
/* removed duplicate definition of OP_StrictEq */


	
/* removed duplicate definition of OP_Neq */


	
/* removed duplicate definition of OP_StrictNeq */


	/* Object property access instructions */
	
/* removed duplicate definition of OP_GetByVal */


	
/* removed duplicate definition of OP_PutByVal */


	
/* removed duplicate definition of OP_GetById */


	instructions[OP_GetByIdLong] = (Instruction){
		OP_GetByIdLong, "GetByIdLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Obj */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Flags */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name id */
		8
	};

	instructions[OP_GetByIdShort] = (Instruction){
		OP_GetByIdShort, "GetByIdShort",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Obj */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Flags */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_STRING_ID } }, /* Name id */
		5
	};

	/* TryGetById family */
	instructions[OP_TryGetById] = (Instruction){
		OP_TryGetById, "TryGetById",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Flags/opt */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, /* Name id */
		6 /* 1 +1+1+1+2 */
	};

	instructions[OP_TryGetByIdLong] = (Instruction){
		OP_TryGetByIdLong, "TryGetByIdLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Flags/opt */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name id */
		8 /* 1 +1+1+1+4 */
	};

	/* TryPutById family */
	instructions[OP_TryPutById] = (Instruction){
		OP_TryPutById, "TryPutById",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Flags/opt */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, /* Name id */
		6
	};

	instructions[OP_TryPutByIdLong] = (Instruction){
		OP_TryPutByIdLong, "TryPutByIdLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Flags/opt */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name id */
		8
	};

	/* PutNewOwnById family */
	instructions[OP_PutNewOwnByIdShort] = (Instruction){
		OP_PutNewOwnByIdShort, "PutNewOwnByIdShort",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_STRING_ID } }, /* Name id */
		4
	};

	instructions[OP_PutNewOwnById] = (Instruction){
		OP_PutNewOwnById, "PutNewOwnById",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, /* Name id */
		5
	};

	instructions[OP_PutNewOwnByIdLong] = (Instruction){
		OP_PutNewOwnByIdLong, "PutNewOwnByIdLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name id */
		7
	};

	instructions[OP_PutNewOwnNEById] = (Instruction){
		OP_PutNewOwnNEById, "PutNewOwnNEById",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, /* Name id */
		5
	};

	instructions[OP_PutNewOwnNEByIdLong] = (Instruction){
		OP_PutNewOwnNEByIdLong, "PutNewOwnNEByIdLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name id */
		7
	};

	/* PutOwnByIndex */
	instructions[OP_PutOwnByIndex] = (Instruction){
		OP_PutOwnByIndex, "PutOwnByIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Index */
		4
	};

	instructions[OP_PutOwnByIndexL] = (Instruction){
		OP_PutOwnByIndexL, "PutOwnByIndexL",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Index */
		7
	};

	/* Delete by id */
	instructions[OP_DelById] = (Instruction){
		OP_DelById, "DelById",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, /* Name id */
		5
	};

	instructions[OP_DelByIdLong] = (Instruction){
		OP_DelByIdLong, "DelByIdLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name id */
		7
	};

	/* Delete by val */
	instructions[OP_DelByVal] = (Instruction){
		OP_DelByVal, "DelByVal",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Key */
		4
	};

	instructions[OP_PutOwnGetterSetterByVal] = (Instruction){
		OP_PutOwnGetterSetterByVal, "PutOwnGetterSetterByVal",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Prop */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Getter */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Setter */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Attrs */
		6
	};

	/* Property name enumeration */
	instructions[OP_GetPNameList] = (Instruction){
		OP_GetPNameList, "GetPNameList",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		5
	};

	instructions[OP_GetNextPName] = (Instruction){
		OP_GetNextPName, "GetNextPName",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		6
	};
	
/* removed duplicate definition of OP_PutById */


	instructions[OP_PutByIdLong] = (Instruction){
		OP_PutByIdLong, "PutByIdLong",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, /* Flags */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name id */
		8
	};

	/* Creation/manipulation instructions */
	
/* removed duplicate definition of OP_NewObject */


	instructions[OP_NewObjectWithParent] = (Instruction){
		OP_NewObjectWithParent, "NewObjectWithParent",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Parent */
		3
	};

	
/* removed duplicate definition of OP_NewArray */


	/* Note: NewObjectWithBuffer/NewArrayWithBuffer variants are defined earlier with correct layouts/sizes */

	/* Generators */
	instructions[OP_StartGenerator] = (Instruction){
		OP_StartGenerator, "StartGenerator",
		{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
		1
	};

	instructions[OP_ResumeGenerator] = (Instruction){
		OP_ResumeGenerator, "ResumeGenerator",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_CompleteGenerator] = (Instruction){
		OP_CompleteGenerator, "CompleteGenerator",
		{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
		1
	};

	instructions[OP_CreateGenerator] = (Instruction){
		OP_CreateGenerator, "CreateGenerator",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_FUNCTION_ID } },
		5
	};

	instructions[OP_CreateGeneratorLongIndex] = (Instruction){
		OP_CreateGeneratorLongIndex, "CreateGeneratorLongIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_FUNCTION_ID } },
		7
	};

	/* SaveGenerator: stores the resume target (short/long address) */
	instructions[OP_SaveGenerator] = (Instruction){
		OP_SaveGenerator, "SaveGenerator",
		{ { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE } },
		2 /* opcode + addr8 */
	};

	instructions[OP_SaveGeneratorLong] = (Instruction){
		OP_SaveGeneratorLong, "SaveGeneratorLong",
		{ { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE } },
		5 /* opcode + addr32 */
	};

	instructions[OP_CreateRegExp] = (Instruction){
		OP_CreateRegExp, "CreateRegExp",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, /* Pattern string ID */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, /* Flags string ID */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Extra */
		13 /* opcode + reg + 3*u32 */
	};

	/* Environment operations */
	
/* removed duplicate definition of OP_CreateEnvironment */


	instructions[OP_CreateInnerEnvironment] = (Instruction){
		OP_CreateInnerEnvironment, "CreateInnerEnvironment",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* New env dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Outer env reg */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Captured count */
		7 /* opcode + 2 regs + u32 */
	};

	instructions[OP_GetEnvironment] = (Instruction){
		OP_GetEnvironment, "GetEnvironment",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Depth */
		3 /* opcode + reg + u8 */
	};

	instructions[OP_GetGlobalObject] = (Instruction){
		OP_GetGlobalObject, "GetGlobalObject",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Dest */
		2 /* opcode + reg */
	};

	instructions[OP_GetNewTarget] = (Instruction){
		OP_GetNewTarget, "GetNewTarget",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Dest */
		2 /* opcode + reg */
	};

	instructions[OP_DeclareGlobalVar] = (Instruction){
		OP_DeclareGlobalVar, "DeclareGlobalVar",
		{ { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name string id */
		5 /* opcode + u32 */
	};

	instructions[OP_ThrowIfHasRestrictedGlobalProperty] = (Instruction){
		OP_ThrowIfHasRestrictedGlobalProperty, "ThrowIfHasRestrictedGlobalProperty",
		{ { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID } }, /* Name string id */
		5 /* opcode + u32 */
	};

	/* Special instructions */
	instructions[OP_SwitchImm] = (Instruction){
		OP_SwitchImm, "SwitchImm",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Value to switch on */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, /* Jump table offset */
			{ OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, /* Default address */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, /* Minimum value */
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE } }, /* Maximum value */
		18 /* opcode + 1 + 4 + 4 + 4 + 4 = 18 */
	};

	instructions[OP_Debugger] = (Instruction){
		OP_Debugger, "Debugger",
		{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
		1 /* opcode only */
	};

	instructions[OP_DebuggerCheck] = (Instruction){
		OP_DebuggerCheck, "DebuggerCheck",
		{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
		1
	};

	
/* removed duplicate definition of OP_Ret */


	instructions[OP_DirectEval] = (Instruction){
		OP_DirectEval, "DirectEval",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_AsyncBreakCheck] = (Instruction){
		OP_AsyncBreakCheck, "AsyncBreakCheck",
		{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
		1
	};

	instructions[OP_ProfilePoint] = (Instruction){
		OP_ProfilePoint, "ProfilePoint",
		{ { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE } },
		3
	};

	/* Fixed-arg call helpers */
	instructions[OP_Call1] = (Instruction){
		OP_Call1, "Call1",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_Call2] = (Instruction){
		OP_Call2, "Call2",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		5
	};

	instructions[OP_Call3] = (Instruction){
		OP_Call3, "Call3",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		6
	};

	instructions[OP_Call4] = (Instruction){
		OP_Call4, "Call4",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		7
	};

	/* TypedArrays and other modern features */
	instructions[OP_TypeOf] = (Instruction){
		OP_TypeOf, "TypeOf",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Source register */
		3 /* opcode + 2 regs */
	};

	instructions[OP_InstanceOf] = (Instruction){
		OP_InstanceOf, "InstanceOf",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Destination register */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Object */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Constructor */
		4 /* opcode + 3 regs */
	};

	/* Simple loads */
	instructions[OP_LoadConstUInt8] = (Instruction){
		OP_LoadConstUInt8, "LoadConstUInt8",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Value */
		3
	};

	
/* removed duplicate definition of OP_LoadConstInt */


	/* This + object selection */
	instructions[OP_CoerceThisNS] = (Instruction){
		OP_CoerceThisNS, "CoerceThisNS",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* This */
		3
	};

	instructions[OP_CreateThis] = (Instruction){
		OP_CreateThis, "CreateThis",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Func */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* NewTarget */
		4
	};

	instructions[OP_SelectObject] = (Instruction){
		OP_SelectObject, "SelectObject",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Dest */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, /* Obj1 */
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, /* Obj2 */
		4
	};

	/* Closures */
	
/* removed duplicate definition of OP_CreateClosure */


	instructions[OP_CreateClosureLongIndex] = (Instruction){
		OP_CreateClosureLongIndex, "CreateClosureLongIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_FUNCTION_ID } },
		7
	};

	instructions[OP_CreateGeneratorClosure] = (Instruction){
		OP_CreateGeneratorClosure, "CreateGeneratorClosure",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_FUNCTION_ID } },
		5
	};

	instructions[OP_CreateGeneratorClosureLongIndex] = (Instruction){
		OP_CreateGeneratorClosureLongIndex, "CreateGeneratorClosureLongIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_FUNCTION_ID } },
		7
	};

	instructions[OP_CreateAsyncClosure] = (Instruction){
		OP_CreateAsyncClosure, "CreateAsyncClosure",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT16, OPERAND_MEANING_FUNCTION_ID } },
		5
	};

	instructions[OP_CreateAsyncClosureLongIndex] = (Instruction){
		OP_CreateAsyncClosureLongIndex, "CreateAsyncClosureLongIndex",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT32, OPERAND_MEANING_FUNCTION_ID } },
		7
	};

	/* Conversions */
	instructions[OP_ToNumber] = (Instruction){
		OP_ToNumber, "ToNumber",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_ToNumeric] = (Instruction){
		OP_ToNumeric, "ToNumeric",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	/* Iterators */
	instructions[OP_IteratorBegin] = (Instruction){
		OP_IteratorBegin, "IteratorBegin",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		3
	};

	instructions[OP_IteratorNext] = (Instruction){
		OP_IteratorNext, "IteratorNext",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } },
		4
	};

	instructions[OP_IteratorClose] = (Instruction){
		OP_IteratorClose, "IteratorClose",
		{ { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE },
			{ OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, /* Hint */
		3
	};

	/* Compare-and-jump family (Addr, Reg, Reg) */
	instructions[OP_JLess] = (Instruction){ OP_JLess, "JLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JLessLong] = (Instruction){ OP_JLessLong, "JLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotLess] = (Instruction){ OP_JNotLess, "JNotLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotLessLong] = (Instruction){ OP_JNotLessLong, "JNotLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JLessN] = (Instruction){ OP_JLessN, "JLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JLessNLong] = (Instruction){ OP_JLessNLong, "JLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotLessN] = (Instruction){ OP_JNotLessN, "JNotLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotLessNLong] = (Instruction){ OP_JNotLessNLong, "JNotLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JLessEqual] = (Instruction){ OP_JLessEqual, "JLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JLessEqualLong] = (Instruction){ OP_JLessEqualLong, "JLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotLessEqual] = (Instruction){ OP_JNotLessEqual, "JNotLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotLessEqualLong] = (Instruction){ OP_JNotLessEqualLong, "JNotLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JLessEqualN] = (Instruction){ OP_JLessEqualN, "JLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JLessEqualNLong] = (Instruction){ OP_JLessEqualNLong, "JLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotLessEqualN] = (Instruction){ OP_JNotLessEqualN, "JNotLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotLessEqualNLong] = (Instruction){ OP_JNotLessEqualNLong, "JNotLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JGreater] = (Instruction){ OP_JGreater, "JGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JGreaterLong] = (Instruction){ OP_JGreaterLong, "JGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotGreater] = (Instruction){ OP_JNotGreater, "JNotGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotGreaterLong] = (Instruction){ OP_JNotGreaterLong, "JNotGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JGreaterN] = (Instruction){ OP_JGreaterN, "JGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JGreaterNLong] = (Instruction){ OP_JGreaterNLong, "JGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotGreaterN] = (Instruction){ OP_JNotGreaterN, "JNotGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotGreaterNLong] = (Instruction){ OP_JNotGreaterNLong, "JNotGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JGreaterEqual] = (Instruction){ OP_JGreaterEqual, "JGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JGreaterEqualLong] = (Instruction){ OP_JGreaterEqualLong, "JGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotGreaterEqual] = (Instruction){ OP_JNotGreaterEqual, "JNotGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotGreaterEqualLong] = (Instruction){ OP_JNotGreaterEqualLong, "JNotGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JGreaterEqualN] = (Instruction){ OP_JGreaterEqualN, "JGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JGreaterEqualNLong] = (Instruction){ OP_JGreaterEqualNLong, "JGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotGreaterEqualN] = (Instruction){ OP_JNotGreaterEqualN, "JNotGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotGreaterEqualNLong] = (Instruction){ OP_JNotGreaterEqualNLong, "JNotGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JEqual] = (Instruction){ OP_JEqual, "JEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JEqualLong] = (Instruction){ OP_JEqualLong, "JEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JNotEqual] = (Instruction){ OP_JNotEqual, "JNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JNotEqualLong] = (Instruction){ OP_JNotEqualLong, "JNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JStrictEqual] = (Instruction){ OP_JStrictEqual, "JStrictEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JStrictEqualLong] = (Instruction){ OP_JStrictEqualLong, "JStrictEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
	instructions[OP_JStrictNotEqual] = (Instruction){ OP_JStrictNotEqual, "JStrictNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_JStrictNotEqualLong] = (Instruction){ OP_JStrictNotEqualLong, "JStrictNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };

	/* Typed arithmetic and memory ops */
	instructions[OP_Add32] = (Instruction){ OP_Add32, "Add32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Sub32] = (Instruction){ OP_Sub32, "Sub32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Mul32] = (Instruction){ OP_Mul32, "Mul32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Divi32] = (Instruction){ OP_Divi32, "Divi32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Divu32] = (Instruction){ OP_Divu32, "Divu32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Loadi8] = (Instruction){ OP_Loadi8, "Loadi8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Loadu8] = (Instruction){ OP_Loadu8, "Loadu8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Loadi16] = (Instruction){ OP_Loadi16, "Loadi16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Loadu16] = (Instruction){ OP_Loadu16, "Loadu16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Loadi32] = (Instruction){ OP_Loadi32, "Loadi32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Loadu32] = (Instruction){ OP_Loadu32, "Loadu32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Store8] = (Instruction){ OP_Store8, "Store8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Store16] = (Instruction){ OP_Store16, "Store16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Store32] = (Instruction){ OP_Store32, "Store32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };

	if (out_count) {
		 *out_count = instruction_count; /* Return full set for array indexing */
	}

	// XXX this is called too many times
	// fprintf (stderr, "Initialized %u instruction definitions\n", defined_count);
	return instructions;
}

/* Helper function - check if an opcode is an arithmetic instruction */
bool is_arithmetic_instruction(u8 opcode) {
	switch (opcode) {
	case OP_Add:
	case OP_AddN:
	case OP_Add32:
	case OP_AddEmptyString:
	case OP_Sub:
	case OP_SubN:
	case OP_Sub32:
	case OP_Mul:
	case OP_MulN:
	case OP_Mul32:
	case OP_Div:
	case OP_DivN:
	case OP_Divi32:
	case OP_Divu32:
	case OP_Mod:
	case OP_Inc:
	case OP_Dec:
	case OP_Negate:
		return true;
	default:
		return false;
	}
}

/* Helper function - check if an opcode is a bitwise instruction */
bool is_bitwise_instruction(u8 opcode) {
	switch (opcode) {
	case OP_BitAnd:
	case OP_BitOr:
	case OP_BitXor:
	case OP_BitNot:
	case OP_LShift:
	case OP_RShift:
	case OP_URshift:
		return true;
	default:
		return false;
	}
}

/* Helper function - check if an opcode is a load instruction */
bool is_load_instruction(u8 opcode) {
	switch (opcode) {
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
	case OP_ReifyArguments:
		return true;
	default:
		return false;
	}
}

/* Helper function - check if an opcode is a store instruction */
bool is_store_instruction(u8 opcode) {
	switch (opcode) {
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
	case OP_DelById:
	case OP_DelByIdLong:
	case OP_DelByVal:
	case OP_CreateEnvironment:
	case OP_CreateInnerEnvironment:
	case OP_DeclareGlobalVar:
	case OP_ThrowIfHasRestrictedGlobalProperty:
		return true;
	default:
		return false;
	}
}

/* Helper function - check if an opcode is a comparison instruction */
bool is_comparison_instruction(u8 opcode) {
	switch (opcode) {
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
		return true;
	default:
		return false;
	}
}

/* Version-specific opcode table generators */

/* Generate instruction set for version 90 (based on early Hermes bytecode) */
static Instruction *get_instruction_set_v90(u32 *out_count) {
	const u32 instruction_count = 256;
	Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
	if (!instructions) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	/* Initialize all to unknown */
	for (u32 i = 0; i < instruction_count; i++) {
		instructions[i] = (Instruction){
			(u8)i, "Unknown",
			{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
			1
		};
	}

	/* Version 90 specific opcodes - early Hermes had fewer instructions */
	/* Basic operations */
	instructions[OP_Mov] = (Instruction){ OP_Mov, "Mov", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 3 };
	instructions[OP_LoadConstString] = (Instruction){ OP_LoadConstString, "LoadConstString", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, 4 };
	instructions[OP_LoadConstDouble] = (Instruction){ OP_LoadConstDouble, "LoadConstDouble", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_DOUBLE, OPERAND_MEANING_NONE } }, 9 };
	instructions[OP_Add] = (Instruction){ OP_Add, "Add", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Sub] = (Instruction){ OP_Sub, "Sub", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Jmp] = (Instruction){ OP_Jmp, "Jmp", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE } }, 2 };
	instructions[OP_Ret] = (Instruction){ OP_Ret, "Ret", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 2 };
	instructions[OP_Call] = (Instruction){ OP_Call, "Call", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, 4 };

	/* Note: v90 had fewer opcodes, many later ones don't exist */

	if (out_count) {
		*out_count = instruction_count;
	}
	return instructions;
}

/* Generate instruction set for version 91 */
static Instruction *get_instruction_set_v91(u32 *out_count) {
	const u32 instruction_count = 256;
	Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
	if (!instructions) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	/* Initialize all to unknown */
	for (u32 i = 0; i < instruction_count; i++) {
		instructions[i] = (Instruction){
			(u8)i, "Unknown",
			{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
			1
		};
	}

	/* Copy v90 as base and add v91 specific changes */
	Instruction *v90_base = get_instruction_set_v90 (NULL);
	if (v90_base) {
		memcpy (instructions, v90_base, instruction_count * sizeof (Instruction));
		free (v90_base);
	}

	/* v91 additions - some new instructions were added */
	instructions[OP_LoadConstInt] = (Instruction){ OP_LoadConstInt, "LoadConstInt", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE } }, 6 };
	instructions[OP_NewObject] = (Instruction){ OP_NewObject, "NewObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 2 };

	if (out_count) {
		*out_count = instruction_count;
	}
	return instructions;
}

/* Generate instruction set for version 92 */
static Instruction *get_instruction_set_v92(u32 *out_count) {
	const u32 instruction_count = 256;
	Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
	if (!instructions) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	/* Initialize all to unknown */
	for (u32 i = 0; i < instruction_count; i++) {
		instructions[i] = (Instruction){
			(u8)i, "Unknown",
			{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
			1
		};
	}

	/* Copy v91 as base */
	Instruction *v91_base = get_instruction_set_v91 (NULL);
	if (v91_base) {
		memcpy (instructions, v91_base, instruction_count * sizeof (Instruction));
		free (v91_base);
	}

	/* v92 additions */
	instructions[OP_GetById] = (Instruction){ OP_GetById, "GetById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, 6 };
	instructions[OP_PutById] = (Instruction){ OP_PutById, "PutById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID } }, 6 };

	if (out_count) {
		*out_count = instruction_count;
	}
	return instructions;
}

/* Generate instruction set for version 93 */
static Instruction *get_instruction_set_v93(u32 *out_count) {
	const u32 instruction_count = 256;
	Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
	if (!instructions) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	/* Initialize all to unknown */
	for (u32 i = 0; i < instruction_count; i++) {
		instructions[i] = (Instruction){
			(u8)i, "Unknown",
			{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
			1
		};
	}

	/* Copy v92 as base */
	Instruction *v92_base = get_instruction_set_v92 (NULL);
	if (v92_base) {
		memcpy (instructions, v92_base, instruction_count * sizeof (Instruction));
		free (v92_base);
	}

	/* v93 additions - environment and closure support */
	instructions[OP_CreateEnvironment] = (Instruction){ OP_CreateEnvironment, "CreateEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 2 };
	instructions[OP_LoadFromEnvironment] = (Instruction){ OP_LoadFromEnvironment, "LoadFromEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_StoreToEnvironment] = (Instruction){ OP_StoreToEnvironment, "StoreToEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };

	if (out_count) {
		*out_count = instruction_count;
	}
	return instructions;
}

/* Generate instruction set for version 94 */
static Instruction *get_instruction_set_v94(u32 *out_count) {
	const u32 instruction_count = 256;
	Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
	if (!instructions) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	/* Initialize all to unknown */
	for (u32 i = 0; i < instruction_count; i++) {
		instructions[i] = (Instruction){
			(u8)i, "Unknown",
			{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
			1
		};
	}

	/* Copy v93 as base */
	Instruction *v93_base = get_instruction_set_v93 (NULL);
	if (v93_base) {
		memcpy (instructions, v93_base, instruction_count * sizeof (Instruction));
		free (v93_base);
	}

	/* v94 additions - more object operations */
	instructions[OP_NewArray] = (Instruction){ OP_NewArray, "NewArray", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_GetByVal] = (Instruction){ OP_GetByVal, "GetByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_PutByVal] = (Instruction){ OP_PutByVal, "PutByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };

	if (out_count) {
		*out_count = instruction_count;
	}
	return instructions;
}

/* Generate instruction set for version 95 */
static Instruction *get_instruction_set_v95(u32 *out_count) {
	const u32 instruction_count = 256;
	Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
	if (!instructions) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	/* Initialize all to unknown */
	for (u32 i = 0; i < instruction_count; i++) {
		instructions[i] = (Instruction){
			(u8)i, "Unknown",
			{ { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } },
			1
		};
	}

	/* Copy v94 as base and extend to nearly v96 compatibility */
	Instruction *v94_base = get_instruction_set_v94 (NULL);
	if (v94_base) {
		memcpy (instructions, v94_base, instruction_count * sizeof (Instruction));
		free (v94_base);
	}

	/* v95 additions - most instructions from v96 but some missing */
	/* Add most v96 instructions except the newest ones */
	instructions[OP_MovLong] = (Instruction){ OP_MovLong, "MovLong", { { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE } }, 9 };
	instructions[OP_CallDirect] = (Instruction){ OP_CallDirect, "CallDirect", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_FUNCTION_ID } }, 5 };
	instructions[OP_CreateClosure] = (Instruction){ OP_CreateClosure, "CreateClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_FUNCTION_ID } }, 5 };
	instructions[OP_JmpLong] = (Instruction){ OP_JmpLong, "JmpLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE } }, 5 };
	instructions[OP_LoadConstUndefined] = (Instruction){ OP_LoadConstUndefined, "LoadConstUndefined", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 2 };
	instructions[OP_LoadConstNull] = (Instruction){ OP_LoadConstNull, "LoadConstNull", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 2 };
	instructions[OP_LoadConstTrue] = (Instruction){ OP_LoadConstTrue, "LoadConstTrue", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 2 };
	instructions[OP_LoadConstFalse] = (Instruction){ OP_LoadConstFalse, "LoadConstFalse", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 2 };

	/* Most arithmetic and logical operations */
	instructions[OP_Mul] = (Instruction){ OP_Mul, "Mul", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Div] = (Instruction){ OP_Div, "Div", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Mod] = (Instruction){ OP_Mod, "Mod", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_BitAnd] = (Instruction){ OP_BitAnd, "BitAnd", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_BitOr] = (Instruction){ OP_BitOr, "BitOr", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_BitXor] = (Instruction){ OP_BitXor, "BitXor", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_LShift] = (Instruction){ OP_LShift, "LShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_RShift] = (Instruction){ OP_RShift, "RShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_URshift] = (Instruction){ OP_URshift, "URshift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };

	/* Comparisons */
	instructions[OP_Eq] = (Instruction){ OP_Eq, "Eq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_StrictEq] = (Instruction){ OP_StrictEq, "StrictEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Neq] = (Instruction){ OP_Neq, "Neq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_StrictNeq] = (Instruction){ OP_StrictNeq, "StrictNeq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Less] = (Instruction){ OP_Less, "Less", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_LessEq] = (Instruction){ OP_LessEq, "LessEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_Greater] = (Instruction){ OP_Greater, "Greater", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };
	instructions[OP_GreaterEq] = (Instruction){ OP_GreaterEq, "GreaterEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 4 };

	if (out_count) {
		*out_count = instruction_count;
	}
	return instructions;
}

/* v76 table auto-generated from third_party/hermes_rs/def_versions/76.def */
static Instruction *get_instruction_set_v76(u32 *out_count) {
    const u32 instruction_count = 256;
    Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
    if (!instructions) { if (out_count) *out_count = 0; return NULL; }
    for (u32 i=0;i<instruction_count;i++) instructions[i] = (Instruction){ (u8)i, "Unknown", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[0] = (Instruction){ 0, "NewObjectWithBuffer", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[1] = (Instruction){ 1, "NewObjectWithBufferLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 14 };
    instructions[2] = (Instruction){ 2, "NewObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[3] = (Instruction){ 3, "NewObjectWithParent", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[4] = (Instruction){ 4, "NewArrayWithBuffer", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[5] = (Instruction){ 5, "NewArrayWithBufferLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[6] = (Instruction){ 6, "NewArray", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[7] = (Instruction){ 7, "Mov", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[8] = (Instruction){ 8, "MovLong", { { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 9 };
    instructions[9] = (Instruction){ 9, "Negate", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[10] = (Instruction){ 10, "Not", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[11] = (Instruction){ 11, "BitNot", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[12] = (Instruction){ 12, "TypeOf", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[13] = (Instruction){ 13, "Eq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[14] = (Instruction){ 14, "StrictEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[15] = (Instruction){ 15, "Neq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[16] = (Instruction){ 16, "StrictNeq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[17] = (Instruction){ 17, "Less", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[18] = (Instruction){ 18, "LessEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[19] = (Instruction){ 19, "Greater", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[20] = (Instruction){ 20, "GreaterEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[21] = (Instruction){ 21, "Add", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[22] = (Instruction){ 22, "AddN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[23] = (Instruction){ 23, "Mul", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[24] = (Instruction){ 24, "MulN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[25] = (Instruction){ 25, "Div", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[26] = (Instruction){ 26, "DivN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[27] = (Instruction){ 27, "Mod", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[28] = (Instruction){ 28, "Sub", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[29] = (Instruction){ 29, "SubN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[30] = (Instruction){ 30, "LShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[31] = (Instruction){ 31, "RShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[32] = (Instruction){ 32, "URshift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[33] = (Instruction){ 33, "BitAnd", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[34] = (Instruction){ 34, "BitXor", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[35] = (Instruction){ 35, "BitOr", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[36] = (Instruction){ 36, "InstanceOf", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[37] = (Instruction){ 37, "IsIn", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[38] = (Instruction){ 38, "GetEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[39] = (Instruction){ 39, "StoreToEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[40] = (Instruction){ 40, "StoreToEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[41] = (Instruction){ 41, "StoreNPToEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[42] = (Instruction){ 42, "StoreNPToEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[43] = (Instruction){ 43, "LoadFromEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[44] = (Instruction){ 44, "LoadFromEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[45] = (Instruction){ 45, "GetGlobalObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[46] = (Instruction){ 46, "GetNewTarget", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[47] = (Instruction){ 47, "CreateEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[48] = (Instruction){ 48, "DeclareGlobalVar", { { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[49] = (Instruction){ 49, "GetByIdShort", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[50] = (Instruction){ 50, "GetById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[51] = (Instruction){ 51, "GetByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[52] = (Instruction){ 52, "TryGetById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[53] = (Instruction){ 53, "TryGetByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[54] = (Instruction){ 54, "PutById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[55] = (Instruction){ 55, "PutByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[56] = (Instruction){ 56, "TryPutById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[57] = (Instruction){ 57, "TryPutByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[58] = (Instruction){ 58, "PutNewOwnByIdShort", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[59] = (Instruction){ 59, "PutNewOwnById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[60] = (Instruction){ 60, "PutNewOwnByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[61] = (Instruction){ 61, "PutNewOwnNEById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[62] = (Instruction){ 62, "PutNewOwnNEByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[63] = (Instruction){ 63, "PutOwnByIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[64] = (Instruction){ 64, "PutOwnByIndexL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[65] = (Instruction){ 65, "PutOwnByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[66] = (Instruction){ 66, "DelById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[67] = (Instruction){ 67, "DelByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[68] = (Instruction){ 68, "GetByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[69] = (Instruction){ 69, "PutByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[70] = (Instruction){ 70, "DelByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[71] = (Instruction){ 71, "PutOwnGetterSetterByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[72] = (Instruction){ 72, "GetPNameList", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[73] = (Instruction){ 73, "GetNextPName", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[74] = (Instruction){ 74, "Call", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[75] = (Instruction){ 75, "Construct", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[76] = (Instruction){ 76, "Call1", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[77] = (Instruction){ 77, "CallDirect", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[78] = (Instruction){ 78, "Call2", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[79] = (Instruction){ 79, "Call3", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[80] = (Instruction){ 80, "Call4", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
    instructions[81] = (Instruction){ 81, "CallLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[82] = (Instruction){ 82, "ConstructLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[83] = (Instruction){ 83, "CallDirectLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[84] = (Instruction){ 84, "CallBuiltin", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[85] = (Instruction){ 85, "Ret", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[86] = (Instruction){ 86, "Catch", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[87] = (Instruction){ 87, "DirectEval", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[88] = (Instruction){ 88, "Throw", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[89] = (Instruction){ 89, "ThrowIfUndefinedInst", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[90] = (Instruction){ 90, "Debugger", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[91] = (Instruction){ 91, "AsyncBreakCheck", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[92] = (Instruction){ 92, "ProfilePoint", { { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[93] = (Instruction){ 93, "Unreachable", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[94] = (Instruction){ 94, "CreateClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[95] = (Instruction){ 95, "CreateClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[96] = (Instruction){ 96, "CreateGeneratorClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[97] = (Instruction){ 97, "CreateGeneratorClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[98] = (Instruction){ 98, "CreateThis", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[99] = (Instruction){ 99, "SelectObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[100] = (Instruction){ 100, "LoadParam", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[101] = (Instruction){ 101, "LoadParamLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[102] = (Instruction){ 102, "LoadConstUInt8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[103] = (Instruction){ 103, "LoadConstInt", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[104] = (Instruction){ 104, "LoadConstDouble", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_DOUBLE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[105] = (Instruction){ 105, "LoadConstString", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[106] = (Instruction){ 106, "LoadConstStringLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[107] = (Instruction){ 107, "LoadConstUndefined", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[108] = (Instruction){ 108, "LoadConstNull", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[109] = (Instruction){ 109, "LoadConstTrue", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[110] = (Instruction){ 110, "LoadConstFalse", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[111] = (Instruction){ 111, "LoadConstZero", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[112] = (Instruction){ 112, "CoerceThisNS", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[113] = (Instruction){ 113, "LoadThisNS", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[114] = (Instruction){ 114, "ToNumber", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[115] = (Instruction){ 115, "ToInt32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[116] = (Instruction){ 116, "AddEmptyString", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[117] = (Instruction){ 117, "GetArgumentsPropByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[118] = (Instruction){ 118, "GetArgumentsLength", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[119] = (Instruction){ 119, "ReifyArguments", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[120] = (Instruction){ 120, "CreateRegExp", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_STRING_ID }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 14 };
    instructions[121] = (Instruction){ 121, "SwitchImm", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 18 };
    instructions[122] = (Instruction){ 122, "StartGenerator", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[123] = (Instruction){ 123, "ResumeGenerator", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[124] = (Instruction){ 124, "CompleteGenerator", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[125] = (Instruction){ 125, "CreateGenerator", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[126] = (Instruction){ 126, "CreateGeneratorLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[127] = (Instruction){ 127, "IteratorBegin", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[128] = (Instruction){ 128, "IteratorNext", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[129] = (Instruction){ 129, "IteratorClose", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[130] = (Instruction){ 130, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[131] = (Instruction){ 131, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[132] = (Instruction){ 132, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[133] = (Instruction){ 133, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[134] = (Instruction){ 134, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[135] = (Instruction){ 135, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[136] = (Instruction){ 136, "Jmp", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[137] = (Instruction){ 137, "JmpLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[138] = (Instruction){ 138, "JmpTrue", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[139] = (Instruction){ 139, "JmpTrueLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[140] = (Instruction){ 140, "JmpFalse", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[141] = (Instruction){ 141, "JmpFalseLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[142] = (Instruction){ 142, "JmpUndefined", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[143] = (Instruction){ 143, "JmpUndefinedLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[144] = (Instruction){ 144, "SaveGenerator", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[145] = (Instruction){ 145, "SaveGeneratorLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[146] = (Instruction){ 146, "JLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[147] = (Instruction){ 147, "JLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[148] = (Instruction){ 148, "JNotLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[149] = (Instruction){ 149, "JNotLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[150] = (Instruction){ 150, "JLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[151] = (Instruction){ 151, "JLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[152] = (Instruction){ 152, "JNotLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[153] = (Instruction){ 153, "JNotLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[154] = (Instruction){ 154, "JLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[155] = (Instruction){ 155, "JLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[156] = (Instruction){ 156, "JNotLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[157] = (Instruction){ 157, "JNotLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[158] = (Instruction){ 158, "JLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[159] = (Instruction){ 159, "JLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[160] = (Instruction){ 160, "JNotLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[161] = (Instruction){ 161, "JNotLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[162] = (Instruction){ 162, "JGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[163] = (Instruction){ 163, "JGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[164] = (Instruction){ 164, "JNotGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[165] = (Instruction){ 165, "JNotGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[166] = (Instruction){ 166, "JGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[167] = (Instruction){ 167, "JGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[168] = (Instruction){ 168, "JNotGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[169] = (Instruction){ 169, "JNotGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[170] = (Instruction){ 170, "JGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[171] = (Instruction){ 171, "JGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[172] = (Instruction){ 172, "JNotGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[173] = (Instruction){ 173, "JNotGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[174] = (Instruction){ 174, "JGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[175] = (Instruction){ 175, "JGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[176] = (Instruction){ 176, "JNotGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[177] = (Instruction){ 177, "JNotGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[178] = (Instruction){ 178, "JEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[179] = (Instruction){ 179, "JEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[180] = (Instruction){ 180, "JNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[181] = (Instruction){ 181, "JNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[182] = (Instruction){ 182, "JStrictEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[183] = (Instruction){ 183, "JStrictEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[184] = (Instruction){ 184, "JStrictNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[185] = (Instruction){ 185, "JStrictNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    if (out_count) *out_count = instruction_count;
    return instructions;
}

/* v84 table auto-generated */
static Instruction *get_instruction_set_v84(u32 *out_count) {
    const u32 instruction_count = 256;
    Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
    if (!instructions) { if (out_count) *out_count = 0; return NULL; }
    for (u32 i=0;i<instruction_count;i++) instructions[i] = (Instruction){ (u8)i, "Unknown", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[0] = (Instruction){ 0, "Unreachable", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[1] = (Instruction){ 1, "NewObjectWithBuffer", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[2] = (Instruction){ 2, "NewObjectWithBufferLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 14 };
    instructions[3] = (Instruction){ 3, "NewObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[4] = (Instruction){ 4, "NewObjectWithParent", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[5] = (Instruction){ 5, "NewArrayWithBuffer", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[6] = (Instruction){ 6, "NewArrayWithBufferLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[7] = (Instruction){ 7, "NewArray", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[8] = (Instruction){ 8, "Mov", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[9] = (Instruction){ 9, "MovLong", { { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 9 };
    instructions[10] = (Instruction){ 10, "Negate", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[11] = (Instruction){ 11, "Not", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[12] = (Instruction){ 12, "BitNot", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[13] = (Instruction){ 13, "TypeOf", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[14] = (Instruction){ 14, "Eq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[15] = (Instruction){ 15, "StrictEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[16] = (Instruction){ 16, "Neq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[17] = (Instruction){ 17, "StrictNeq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[18] = (Instruction){ 18, "Less", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[19] = (Instruction){ 19, "LessEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[20] = (Instruction){ 20, "Greater", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[21] = (Instruction){ 21, "GreaterEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[22] = (Instruction){ 22, "Add", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[23] = (Instruction){ 23, "AddN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[24] = (Instruction){ 24, "Mul", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[25] = (Instruction){ 25, "MulN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[26] = (Instruction){ 26, "Div", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[27] = (Instruction){ 27, "DivN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[28] = (Instruction){ 28, "Mod", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[29] = (Instruction){ 29, "Sub", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[30] = (Instruction){ 30, "SubN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[31] = (Instruction){ 31, "LShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[32] = (Instruction){ 32, "RShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[33] = (Instruction){ 33, "URshift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[34] = (Instruction){ 34, "BitAnd", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[35] = (Instruction){ 35, "BitXor", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[36] = (Instruction){ 36, "BitOr", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[37] = (Instruction){ 37, "InstanceOf", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[38] = (Instruction){ 38, "IsIn", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[39] = (Instruction){ 39, "GetEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[40] = (Instruction){ 40, "StoreToEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[41] = (Instruction){ 41, "StoreToEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[42] = (Instruction){ 42, "StoreNPToEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[43] = (Instruction){ 43, "StoreNPToEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[44] = (Instruction){ 44, "LoadFromEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[45] = (Instruction){ 45, "LoadFromEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[46] = (Instruction){ 46, "GetGlobalObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[47] = (Instruction){ 47, "GetNewTarget", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[48] = (Instruction){ 48, "CreateEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[49] = (Instruction){ 49, "DeclareGlobalVar", { { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[50] = (Instruction){ 50, "GetByIdShort", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[51] = (Instruction){ 51, "GetById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[52] = (Instruction){ 52, "GetByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[53] = (Instruction){ 53, "TryGetById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[54] = (Instruction){ 54, "TryGetByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[55] = (Instruction){ 55, "PutById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[56] = (Instruction){ 56, "PutByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[57] = (Instruction){ 57, "TryPutById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[58] = (Instruction){ 58, "TryPutByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[59] = (Instruction){ 59, "PutNewOwnByIdShort", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[60] = (Instruction){ 60, "PutNewOwnById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[61] = (Instruction){ 61, "PutNewOwnByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[62] = (Instruction){ 62, "PutNewOwnNEById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[63] = (Instruction){ 63, "PutNewOwnNEByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[64] = (Instruction){ 64, "PutOwnByIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[65] = (Instruction){ 65, "PutOwnByIndexL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[66] = (Instruction){ 66, "PutOwnByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[67] = (Instruction){ 67, "DelById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[68] = (Instruction){ 68, "DelByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[69] = (Instruction){ 69, "GetByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[70] = (Instruction){ 70, "PutByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[71] = (Instruction){ 71, "DelByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[72] = (Instruction){ 72, "PutOwnGetterSetterByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[73] = (Instruction){ 73, "GetPNameList", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[74] = (Instruction){ 74, "GetNextPName", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[75] = (Instruction){ 75, "Call", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[76] = (Instruction){ 76, "Construct", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[77] = (Instruction){ 77, "Call1", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[78] = (Instruction){ 78, "CallDirect", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[79] = (Instruction){ 79, "Call2", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[80] = (Instruction){ 80, "Call3", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[81] = (Instruction){ 81, "Call4", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
    instructions[82] = (Instruction){ 82, "CallLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[83] = (Instruction){ 83, "ConstructLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[84] = (Instruction){ 84, "CallDirectLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[85] = (Instruction){ 85, "CallBuiltin", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[86] = (Instruction){ 86, "CallBuiltinLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[87] = (Instruction){ 87, "GetBuiltinClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[88] = (Instruction){ 88, "Ret", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[89] = (Instruction){ 89, "Catch", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[90] = (Instruction){ 90, "DirectEval", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[91] = (Instruction){ 91, "Throw", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[92] = (Instruction){ 92, "ThrowIfEmpty", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[93] = (Instruction){ 93, "Debugger", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[94] = (Instruction){ 94, "AsyncBreakCheck", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[95] = (Instruction){ 95, "ProfilePoint", { { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[96] = (Instruction){ 96, "CreateClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[97] = (Instruction){ 97, "CreateClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[98] = (Instruction){ 98, "CreateGeneratorClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[99] = (Instruction){ 99, "CreateGeneratorClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[100] = (Instruction){ 100, "CreateAsyncClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[101] = (Instruction){ 101, "CreateAsyncClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[102] = (Instruction){ 102, "CreateThis", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[103] = (Instruction){ 103, "SelectObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[104] = (Instruction){ 104, "LoadParam", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[105] = (Instruction){ 105, "LoadParamLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[106] = (Instruction){ 106, "LoadConstUInt8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[107] = (Instruction){ 107, "LoadConstInt", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[108] = (Instruction){ 108, "LoadConstDouble", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_DOUBLE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[109] = (Instruction){ 109, "LoadConstString", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[110] = (Instruction){ 110, "LoadConstStringLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[111] = (Instruction){ 111, "LoadConstEmpty", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[112] = (Instruction){ 112, "LoadConstUndefined", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[113] = (Instruction){ 113, "LoadConstNull", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[114] = (Instruction){ 114, "LoadConstTrue", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[115] = (Instruction){ 115, "LoadConstFalse", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[116] = (Instruction){ 116, "LoadConstZero", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[117] = (Instruction){ 117, "CoerceThisNS", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[118] = (Instruction){ 118, "LoadThisNS", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[119] = (Instruction){ 119, "ToNumber", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[120] = (Instruction){ 120, "ToInt32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[121] = (Instruction){ 121, "AddEmptyString", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[122] = (Instruction){ 122, "GetArgumentsPropByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[123] = (Instruction){ 123, "GetArgumentsLength", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[124] = (Instruction){ 124, "ReifyArguments", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[125] = (Instruction){ 125, "CreateRegExp", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 14 };
    instructions[126] = (Instruction){ 126, "SwitchImm", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 18 };
    instructions[127] = (Instruction){ 127, "StartGenerator", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[128] = (Instruction){ 128, "ResumeGenerator", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[129] = (Instruction){ 129, "CompleteGenerator", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[130] = (Instruction){ 130, "CreateGenerator", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[131] = (Instruction){ 131, "CreateGeneratorLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[132] = (Instruction){ 132, "IteratorBegin", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[133] = (Instruction){ 133, "IteratorNext", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[134] = (Instruction){ 134, "IteratorClose", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[135] = (Instruction){ 135, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[136] = (Instruction){ 136, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[137] = (Instruction){ 137, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[138] = (Instruction){ 138, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[139] = (Instruction){ 139, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[140] = (Instruction){ 140, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[141] = (Instruction){ 141, "Jmp", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[142] = (Instruction){ 142, "JmpLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[143] = (Instruction){ 143, "JmpTrue", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[144] = (Instruction){ 144, "JmpTrueLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[145] = (Instruction){ 145, "JmpFalse", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[146] = (Instruction){ 146, "JmpFalseLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[147] = (Instruction){ 147, "JmpUndefined", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[148] = (Instruction){ 148, "JmpUndefinedLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[149] = (Instruction){ 149, "SaveGenerator", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[150] = (Instruction){ 150, "SaveGeneratorLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[151] = (Instruction){ 151, "JLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[152] = (Instruction){ 152, "JLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[153] = (Instruction){ 153, "JNotLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[154] = (Instruction){ 154, "JNotLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[155] = (Instruction){ 155, "JLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[156] = (Instruction){ 156, "JLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[157] = (Instruction){ 157, "JNotLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[158] = (Instruction){ 158, "JNotLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[159] = (Instruction){ 159, "JLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[160] = (Instruction){ 160, "JLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[161] = (Instruction){ 161, "JNotLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[162] = (Instruction){ 162, "JNotLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[163] = (Instruction){ 163, "JLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[164] = (Instruction){ 164, "JLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[165] = (Instruction){ 165, "JNotLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[166] = (Instruction){ 166, "JNotLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[167] = (Instruction){ 167, "JGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[168] = (Instruction){ 168, "JGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[169] = (Instruction){ 169, "JNotGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[170] = (Instruction){ 170, "JNotGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[171] = (Instruction){ 171, "JGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[172] = (Instruction){ 172, "JGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[173] = (Instruction){ 173, "JNotGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[174] = (Instruction){ 174, "JNotGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[175] = (Instruction){ 175, "JGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[176] = (Instruction){ 176, "JGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[177] = (Instruction){ 177, "JNotGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[178] = (Instruction){ 178, "JNotGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[179] = (Instruction){ 179, "JGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[180] = (Instruction){ 180, "JGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[181] = (Instruction){ 181, "JNotGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[182] = (Instruction){ 182, "JNotGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[183] = (Instruction){ 183, "JEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[184] = (Instruction){ 184, "JEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[185] = (Instruction){ 185, "JNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[186] = (Instruction){ 186, "JNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[187] = (Instruction){ 187, "JStrictEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[188] = (Instruction){ 188, "JStrictEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[189] = (Instruction){ 189, "JStrictNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[190] = (Instruction){ 190, "JStrictNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[191] = (Instruction){ 191, "Add32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[192] = (Instruction){ 192, "Sub32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[193] = (Instruction){ 193, "Mul32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[194] = (Instruction){ 194, "Divi32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[195] = (Instruction){ 195, "Divu32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[196] = (Instruction){ 196, "Loadi8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[197] = (Instruction){ 197, "Loadu8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[198] = (Instruction){ 198, "Loadi16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[199] = (Instruction){ 199, "Loadu16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[200] = (Instruction){ 200, "Loadi32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[201] = (Instruction){ 201, "Loadu32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[202] = (Instruction){ 202, "Store8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[203] = (Instruction){ 203, "Store16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[204] = (Instruction){ 204, "Store32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    if (out_count) *out_count = instruction_count;
    return instructions;
}
/* v89 table auto-generated */
static Instruction *get_instruction_set_v89(u32 *out_count) {
    const u32 instruction_count = 256;
    Instruction *instructions = (Instruction *)malloc (instruction_count * sizeof (Instruction));
    if (!instructions) { if (out_count) *out_count = 0; return NULL; }
    for (u32 i=0;i<instruction_count;i++) instructions[i] = (Instruction){ (u8)i, "Unknown", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[0] = (Instruction){ 0, "Unreachable", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[1] = (Instruction){ 1, "NewObjectWithBuffer", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[2] = (Instruction){ 2, "NewObjectWithBufferLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 14 };
    instructions[3] = (Instruction){ 3, "NewObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[4] = (Instruction){ 4, "NewObjectWithParent", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[5] = (Instruction){ 5, "NewArrayWithBuffer", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[6] = (Instruction){ 6, "NewArrayWithBufferLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[7] = (Instruction){ 7, "NewArray", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[8] = (Instruction){ 8, "Mov", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[9] = (Instruction){ 9, "MovLong", { { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 9 };
    instructions[10] = (Instruction){ 10, "Negate", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[11] = (Instruction){ 11, "Not", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[12] = (Instruction){ 12, "BitNot", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[13] = (Instruction){ 13, "TypeOf", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[14] = (Instruction){ 14, "Eq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[15] = (Instruction){ 15, "StrictEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[16] = (Instruction){ 16, "Neq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[17] = (Instruction){ 17, "StrictNeq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[18] = (Instruction){ 18, "Less", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[19] = (Instruction){ 19, "LessEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[20] = (Instruction){ 20, "Greater", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[21] = (Instruction){ 21, "GreaterEq", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[22] = (Instruction){ 22, "Add", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[23] = (Instruction){ 23, "AddN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[24] = (Instruction){ 24, "Mul", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[25] = (Instruction){ 25, "MulN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[26] = (Instruction){ 26, "Div", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[27] = (Instruction){ 27, "DivN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[28] = (Instruction){ 28, "Mod", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[29] = (Instruction){ 29, "Sub", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[30] = (Instruction){ 30, "SubN", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[31] = (Instruction){ 31, "LShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[32] = (Instruction){ 32, "RShift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[33] = (Instruction){ 33, "URshift", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[34] = (Instruction){ 34, "BitAnd", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[35] = (Instruction){ 35, "BitXor", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[36] = (Instruction){ 36, "BitOr", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[37] = (Instruction){ 37, "Inc", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[38] = (Instruction){ 38, "Dec", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[39] = (Instruction){ 39, "InstanceOf", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[40] = (Instruction){ 40, "IsIn", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[41] = (Instruction){ 41, "GetEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[42] = (Instruction){ 42, "StoreToEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[43] = (Instruction){ 43, "StoreToEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[44] = (Instruction){ 44, "StoreNPToEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[45] = (Instruction){ 45, "StoreNPToEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[46] = (Instruction){ 46, "LoadFromEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[47] = (Instruction){ 47, "LoadFromEnvironmentL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[48] = (Instruction){ 48, "GetGlobalObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[49] = (Instruction){ 49, "GetNewTarget", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[50] = (Instruction){ 50, "CreateEnvironment", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[51] = (Instruction){ 51, "DeclareGlobalVar", { { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[52] = (Instruction){ 52, "GetByIdShort", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[53] = (Instruction){ 53, "GetById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[54] = (Instruction){ 54, "GetByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[55] = (Instruction){ 55, "TryGetById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[56] = (Instruction){ 56, "TryGetByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[57] = (Instruction){ 57, "PutById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[58] = (Instruction){ 58, "PutByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[59] = (Instruction){ 59, "TryPutById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[60] = (Instruction){ 60, "TryPutByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 8 };
    instructions[61] = (Instruction){ 61, "PutNewOwnByIdShort", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[62] = (Instruction){ 62, "PutNewOwnById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[63] = (Instruction){ 63, "PutNewOwnByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[64] = (Instruction){ 64, "PutNewOwnNEById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[65] = (Instruction){ 65, "PutNewOwnNEByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[66] = (Instruction){ 66, "PutOwnByIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[67] = (Instruction){ 67, "PutOwnByIndexL", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[68] = (Instruction){ 68, "PutOwnByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[69] = (Instruction){ 69, "DelById", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[70] = (Instruction){ 70, "DelByIdLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[71] = (Instruction){ 71, "GetByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[72] = (Instruction){ 72, "PutByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[73] = (Instruction){ 73, "DelByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[74] = (Instruction){ 74, "PutOwnGetterSetterByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[75] = (Instruction){ 75, "GetPNameList", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[76] = (Instruction){ 76, "GetNextPName", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[77] = (Instruction){ 77, "Call", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[78] = (Instruction){ 78, "Construct", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[79] = (Instruction){ 79, "Call1", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[80] = (Instruction){ 80, "CallDirect", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[81] = (Instruction){ 81, "Call2", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[82] = (Instruction){ 82, "Call3", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[83] = (Instruction){ 83, "Call4", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE } }, 7 };
    instructions[84] = (Instruction){ 84, "CallLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[85] = (Instruction){ 85, "ConstructLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[86] = (Instruction){ 86, "CallDirectLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[87] = (Instruction){ 87, "CallBuiltin", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[88] = (Instruction){ 88, "CallBuiltinLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[89] = (Instruction){ 89, "GetBuiltinClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[90] = (Instruction){ 90, "Ret", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[91] = (Instruction){ 91, "Catch", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[92] = (Instruction){ 92, "DirectEval", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[93] = (Instruction){ 93, "Throw", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[94] = (Instruction){ 94, "ThrowIfEmpty", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[95] = (Instruction){ 95, "Debugger", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[96] = (Instruction){ 96, "AsyncBreakCheck", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[97] = (Instruction){ 97, "ProfilePoint", { { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[98] = (Instruction){ 98, "CreateClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[99] = (Instruction){ 99, "CreateClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[100] = (Instruction){ 100, "CreateGeneratorClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[101] = (Instruction){ 101, "CreateGeneratorClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[102] = (Instruction){ 102, "CreateAsyncClosure", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[103] = (Instruction){ 103, "CreateAsyncClosureLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[104] = (Instruction){ 104, "CreateThis", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[105] = (Instruction){ 105, "SelectObject", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[106] = (Instruction){ 106, "LoadParam", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[107] = (Instruction){ 107, "LoadParamLong", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[108] = (Instruction){ 108, "LoadConstUInt8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[109] = (Instruction){ 109, "LoadConstInt", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[110] = (Instruction){ 110, "LoadConstDouble", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_DOUBLE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 10 };
    instructions[111] = (Instruction){ 111, "LoadConstBigInt", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[112] = (Instruction){ 112, "LoadConstBigIntLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[113] = (Instruction){ 113, "LoadConstString", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[114] = (Instruction){ 114, "LoadConstStringLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[115] = (Instruction){ 115, "LoadConstEmpty", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[116] = (Instruction){ 116, "LoadConstUndefined", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[117] = (Instruction){ 117, "LoadConstNull", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[118] = (Instruction){ 118, "LoadConstTrue", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[119] = (Instruction){ 119, "LoadConstFalse", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[120] = (Instruction){ 120, "LoadConstZero", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[121] = (Instruction){ 121, "CoerceThisNS", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[122] = (Instruction){ 122, "LoadThisNS", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[123] = (Instruction){ 123, "ToNumber", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[124] = (Instruction){ 124, "ToNumeric", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[125] = (Instruction){ 125, "ToInt32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[126] = (Instruction){ 126, "AddEmptyString", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[127] = (Instruction){ 127, "GetArgumentsPropByVal", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[128] = (Instruction){ 128, "GetArgumentsLength", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[129] = (Instruction){ 129, "ReifyArguments", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[130] = (Instruction){ 130, "CreateRegExp", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 14 };
    instructions[131] = (Instruction){ 131, "SwitchImm", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 18 };
    instructions[132] = (Instruction){ 132, "StartGenerator", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[133] = (Instruction){ 133, "ResumeGenerator", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[134] = (Instruction){ 134, "CompleteGenerator", { { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 1 };
    instructions[135] = (Instruction){ 135, "CreateGenerator", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT16, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[136] = (Instruction){ 136, "CreateGeneratorLongIndex", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[137] = (Instruction){ 137, "IteratorBegin", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[138] = (Instruction){ 138, "IteratorNext", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[139] = (Instruction){ 139, "IteratorClose", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_UINT8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[140] = (Instruction){ 140, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[141] = (Instruction){ 141, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[142] = (Instruction){ 142, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[143] = (Instruction){ 143, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[144] = (Instruction){ 144, "name", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[145] = (Instruction){ 145, "name##Long", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[146] = (Instruction){ 146, "Jmp", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[147] = (Instruction){ 147, "JmpLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[148] = (Instruction){ 148, "JmpTrue", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[149] = (Instruction){ 149, "JmpTrueLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[150] = (Instruction){ 150, "JmpFalse", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[151] = (Instruction){ 151, "JmpFalseLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[152] = (Instruction){ 152, "JmpUndefined", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 3 };
    instructions[153] = (Instruction){ 153, "JmpUndefinedLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 6 };
    instructions[154] = (Instruction){ 154, "SaveGenerator", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 2 };
    instructions[155] = (Instruction){ 155, "SaveGeneratorLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 5 };
    instructions[156] = (Instruction){ 156, "JLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[157] = (Instruction){ 157, "JLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[158] = (Instruction){ 158, "JNotLess", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[159] = (Instruction){ 159, "JNotLessLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[160] = (Instruction){ 160, "JLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[161] = (Instruction){ 161, "JLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[162] = (Instruction){ 162, "JNotLessN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[163] = (Instruction){ 163, "JNotLessNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[164] = (Instruction){ 164, "JLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[165] = (Instruction){ 165, "JLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[166] = (Instruction){ 166, "JNotLessEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[167] = (Instruction){ 167, "JNotLessEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[168] = (Instruction){ 168, "JLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[169] = (Instruction){ 169, "JLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[170] = (Instruction){ 170, "JNotLessEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[171] = (Instruction){ 171, "JNotLessEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[172] = (Instruction){ 172, "JGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[173] = (Instruction){ 173, "JGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[174] = (Instruction){ 174, "JNotGreater", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[175] = (Instruction){ 175, "JNotGreaterLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[176] = (Instruction){ 176, "JGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[177] = (Instruction){ 177, "JGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[178] = (Instruction){ 178, "JNotGreaterN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[179] = (Instruction){ 179, "JNotGreaterNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[180] = (Instruction){ 180, "JGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[181] = (Instruction){ 181, "JGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[182] = (Instruction){ 182, "JNotGreaterEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[183] = (Instruction){ 183, "JNotGreaterEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[184] = (Instruction){ 184, "JGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[185] = (Instruction){ 185, "JGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[186] = (Instruction){ 186, "JNotGreaterEqualN", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[187] = (Instruction){ 187, "JNotGreaterEqualNLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[188] = (Instruction){ 188, "JEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[189] = (Instruction){ 189, "JEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[190] = (Instruction){ 190, "JNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[191] = (Instruction){ 191, "JNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[192] = (Instruction){ 192, "JStrictEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[193] = (Instruction){ 193, "JStrictEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[194] = (Instruction){ 194, "JStrictNotEqual", { { OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[195] = (Instruction){ 195, "JStrictNotEqualLong", { { OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 7 };
    instructions[196] = (Instruction){ 196, "Add32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[197] = (Instruction){ 197, "Sub32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[198] = (Instruction){ 198, "Mul32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[199] = (Instruction){ 199, "Divi32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[200] = (Instruction){ 200, "Divu32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[201] = (Instruction){ 201, "Loadi8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[202] = (Instruction){ 202, "Loadu8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[203] = (Instruction){ 203, "Loadi16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[204] = (Instruction){ 204, "Loadu16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[205] = (Instruction){ 205, "Loadi32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[206] = (Instruction){ 206, "Loadu32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[207] = (Instruction){ 207, "Store8", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[208] = (Instruction){ 208, "Store16", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    instructions[209] = (Instruction){ 209, "Store32", { { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_REG8, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE }, { OPERAND_TYPE_NONE, OPERAND_MEANING_NONE } }, 4 };
    if (out_count) *out_count = instruction_count;
    return instructions;
}
/* Public API for getting instruction set by version */
HBCISA hbc_isa_getv(int version) {
	u32 count;
	Instruction *result = NULL;

	switch (version) {
	case 90:
		result = get_instruction_set_v90 (&count);
		break;
	case 89:
		result = get_instruction_set_v89 (&count);
		break;
	case 84:
		result = get_instruction_set_v84 (&count);
		break;
	case 91:
		result = get_instruction_set_v91 (&count);
		break;
	case 92:
		result = get_instruction_set_v92 (&count);
		break;
	case 93:
		result = get_instruction_set_v93 (&count);
		break;
	case 94:
		result = get_instruction_set_v94 (&count);
		break;
	case 95:
		result = get_instruction_set_v95 (&count);
		break;
	case 96:
		result = get_instruction_set_v96 (&count);
		break;
	case 76:
		result = get_instruction_set_v76 (&count);
		break;
	default:
		/* For versions 72-89, use v90 as fallback */
		if (version >= 72 && version < 90) {
			result = get_instruction_set_v90 (&count);
		} else {
			/* For versions > 96, use v96 as fallback */
			result = get_instruction_set_v96 (&count);
		}
		break;
	}

	return (HBCISA){ .count = count, .instructions = result };
}
