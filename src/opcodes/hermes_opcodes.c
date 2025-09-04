#include "../../include/opcodes/hermes_opcodes.h"
#include <stdlib.h>

/* Define instruction set for bytecode version 96 */
Instruction* get_instruction_set_v96(u32* out_count) {
    /* Allocate memory for the instruction set */
    const u32 instruction_count = 256; /* Support all possible opcode values */
    Instruction* instructions = (Instruction*)malloc(instruction_count * sizeof(Instruction));
    if (!instructions) {
        if (out_count) *out_count = 0;
        return NULL;
    }
    
    /* Initialize all instructions to NULL/invalid */
    for (u32 i = 0; i < instruction_count; i++) {
        instructions[i] = (Instruction) {
            (u8)i, "Unknown", 
            {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}}, 
            1 /* Assume 1 byte size for unknown instructions */
        };
    }
    
    /* Report count to caller */
    if (out_count) {
        *out_count = instruction_count;
    }

    /* Add basic instructions based on hbc95.py */
    /* Simple moves and unary ops */
    instructions[OP_Mov] = (Instruction) {
        OP_Mov, "Mov",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Src */
        3
    };

    instructions[OP_MovLong] = (Instruction) {
        OP_MovLong, "MovLong",
        {{OPERAND_TYPE_REG32, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG32, OPERAND_MEANING_NONE}}, /* Src */
        9 /* opcode + 4 + 4 */
    };

    instructions[OP_Negate] = (Instruction) {
        OP_Negate, "Negate",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_Not] = (Instruction) {
        OP_Not, "Not",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_BitNot] = (Instruction) {
        OP_BitNot, "BitNot",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    /* Equality and relational */
    instructions[OP_Eq] = (Instruction) {
        OP_Eq, "Eq",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_Less] = (Instruction) {
        OP_Less, "Less",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_LessEq] = (Instruction) {
        OP_LessEq, "LessEq",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_Greater] = (Instruction) {
        OP_Greater, "Greater",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_GreaterEq] = (Instruction) {
        OP_GreaterEq, "GreaterEq",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_AddN] = (Instruction) {
        OP_AddN, "AddN",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_SubN] = (Instruction) {
        OP_SubN, "SubN",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_MulN] = (Instruction) {
        OP_MulN, "MulN",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_DivN] = (Instruction) {
        OP_DivN, "DivN",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_LShift] = (Instruction) {
        OP_LShift, "LShift",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_RShift] = (Instruction) {
        OP_RShift, "RShift",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_URshift] = (Instruction) {
        OP_URshift, "URshift",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_Inc] = (Instruction) {
        OP_Inc, "Inc",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_Dec] = (Instruction) {
        OP_Dec, "Dec",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_IsIn] = (Instruction) {
        OP_IsIn, "IsIn",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    /* Environment load/store */
    instructions[OP_StoreToEnvironment] = (Instruction) {
        OP_StoreToEnvironment, "StoreToEnvironment",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Env */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}, /* Index */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Value */
        4
    };

    instructions[OP_StoreToEnvironmentL] = (Instruction) {
        OP_StoreToEnvironmentL, "StoreToEnvironmentL",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        6 /* opcode + 1 + 2 + 1 */
    };

    instructions[OP_StoreNPToEnvironment] = (Instruction) {
        OP_StoreNPToEnvironment, "StoreNPToEnvironment",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_StoreNPToEnvironmentL] = (Instruction) {
        OP_StoreNPToEnvironmentL, "StoreNPToEnvironmentL",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        6
    };

    instructions[OP_LoadFromEnvironment] = (Instruction) {
        OP_LoadFromEnvironment, "LoadFromEnvironment",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Env */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Index */
        4
    };

    instructions[OP_LoadFromEnvironmentL] = (Instruction) {
        OP_LoadFromEnvironmentL, "LoadFromEnvironmentL",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}},
        5
    };
    instructions[OP_Unreachable] = (Instruction) {
        OP_Unreachable, "Unreachable", 
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1 /* opcode only */
    };
    
    instructions[OP_NewObjectWithBuffer] = (Instruction) {
        OP_NewObjectWithBuffer, "NewObjectWithBuffer", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Key count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Value count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_OBJ_KEY_ID}, /* Keys id */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_OBJ_VAL_ID}}, /* Values id */
        10 /* opcode + 1 + 2 + 2 + 2 + 2 */
    };

    instructions[OP_NewArrayWithBuffer] = (Instruction) {
        OP_NewArrayWithBuffer, "NewArrayWithBuffer",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Key count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Value count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_ARRAY_ID}}, /* Array idx */
        8 /* opcode + 1 + 2 + 2 + 2 */
    };

    instructions[OP_NewArrayWithBufferLong] = (Instruction) {
        OP_NewArrayWithBufferLong, "NewArrayWithBufferLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Key count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Value count */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_ARRAY_ID}}, /* Array idx */
        10 /* opcode + 1 + 2 + 2 + 4 */
    };

    instructions[OP_NewObjectWithBufferLong] = (Instruction) {
        OP_NewObjectWithBufferLong, "NewObjectWithBufferLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Key count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}, /* Value count */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_OBJ_KEY_ID}, /* Keys id */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_OBJ_VAL_ID}}, /* Values id */
        14 /* opcode + 1 + 2 + 2 + 4 + 4 */
    };
    
    instructions[OP_Jmp] = (Instruction) {
        OP_Jmp, "Jmp", 
        {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        2 /* opcode + offset */
    };
    
    instructions[OP_JmpTrue] = (Instruction) {
        OP_JmpTrue, "JmpTrue", 
        {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3 /* opcode + offset + reg */
    };
    
    instructions[OP_JmpFalse] = (Instruction) {
        OP_JmpFalse, "JmpFalse", 
        {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3 /* opcode + offset + reg */
    };
    
    instructions[OP_JmpUndefined] = (Instruction) {
        OP_JmpUndefined, "JmpUndefined", 
        {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3 /* opcode + offset + reg */
    };
    
    instructions[OP_JmpLong] = (Instruction) {
        OP_JmpLong, "JmpLong", 
        {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        5 /* opcode + long offset */
    };
    
    instructions[OP_Catch] = (Instruction) {
        OP_Catch, "Catch", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        2 /* opcode + reg */
    };
    
    instructions[OP_Throw] = (Instruction) {
        OP_Throw, "Throw", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        2 /* opcode + reg */
    };
    
    instructions[OP_ThrowIfEmpty] = (Instruction) {
        OP_ThrowIfEmpty, "ThrowIfEmpty", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };
    
    instructions[OP_JmpTrueLong] = (Instruction) {
        OP_JmpTrueLong, "JmpTrueLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        6 /* opcode + reg + long offset */
    };
    
    instructions[OP_JmpFalseLong] = (Instruction) {
        OP_JmpFalseLong, "JmpFalseLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        6 /* opcode + reg + long offset */
    };
    
    instructions[OP_JmpUndefinedLong] = (Instruction) {
        OP_JmpUndefinedLong, "JmpUndefinedLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        6 /* opcode + reg + long offset */
    };
    
    /* Call instructions */
    instructions[OP_Call] = (Instruction) {
        OP_Call, "Call", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Callee */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argc */
        4
    };
    
    instructions[OP_CallLong] = (Instruction) {
        OP_CallLong, "CallLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Callee */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Argc */
        6
    };
    
    instructions[OP_Construct] = (Instruction) {
        OP_Construct, "Construct", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Callee */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argc */
        4
    };
    
    instructions[OP_ConstructLong] = (Instruction) {
        OP_ConstructLong, "ConstructLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Callee */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Argc */
        6
    };
    
    /* CallN is not present in the current opcode set */
    
    /* ConstructN is not present in the current opcode set */
    
    instructions[OP_CallDirect] = (Instruction) {
        OP_CallDirect, "CallDirect", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}, /* Argc */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_FUNCTION_ID}}, /* Function ID */
        5
    };
    
    instructions[OP_CallDirectLongIndex] = (Instruction) {
        OP_CallDirectLongIndex, "CallDirectLongIndex", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}, /* Argc */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_FUNCTION_ID}}, /* Function ID */
        7
    };
    
    instructions[OP_CallBuiltin] = (Instruction) {
        OP_CallBuiltin, "CallBuiltin", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_BUILTIN_ID}, /* Builtin ID */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argc */
        4
    };

    instructions[OP_CallBuiltinLong] = (Instruction) {
        OP_CallBuiltinLong, "CallBuiltinLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_BUILTIN_ID}, /* Builtin ID */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Argc (u32) */
        7
    };

    /* Builtin closure accessor */
    instructions[OP_GetBuiltinClosure] = (Instruction) {
        OP_GetBuiltinClosure, "GetBuiltinClosure",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_BUILTIN_ID}},
        3
    };
    
    /* Load/Store instructions */
    instructions[OP_LoadParam] = (Instruction) {
        OP_LoadParam, "LoadParam", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Parameter index */
        3 /* opcode + 2 operands */
    };

    instructions[OP_LoadParamLong] = (Instruction) {
        OP_LoadParamLong, "LoadParamLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Parameter index (u32) */
        6 /* opcode + 1 + 4 */
    };
    
    instructions[OP_LoadConstZero] = (Instruction) {
        OP_LoadConstZero, "LoadConstZero", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[OP_LoadConstUndefined] = (Instruction) {
        OP_LoadConstUndefined, "LoadConstUndefined", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[OP_LoadConstNull] = (Instruction) {
        OP_LoadConstNull, "LoadConstNull", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[OP_LoadConstTrue] = (Instruction) {
        OP_LoadConstTrue, "LoadConstTrue", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[OP_LoadConstFalse] = (Instruction) {
        OP_LoadConstFalse, "LoadConstFalse", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    /* Additional core ops in v95 */
    instructions[OP_ToInt32] = (Instruction) {
        OP_ToInt32, "ToInt32",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_AddEmptyString] = (Instruction) {
        OP_AddEmptyString, "AddEmptyString",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_GetArgumentsPropByVal] = (Instruction) {
        OP_GetArgumentsPropByVal, "GetArgumentsPropByVal",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_GetArgumentsLength] = (Instruction) {
        OP_GetArgumentsLength, "GetArgumentsLength",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_ReifyArguments] = (Instruction) {
        OP_ReifyArguments, "ReifyArguments",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        2
    };

    /* Missing PutOwnByVal */
    instructions[OP_PutOwnByVal] = (Instruction) {
        OP_PutOwnByVal, "PutOwnByVal",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Obj */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Key */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Val */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Attrs */
        5
    };
    
    instructions[OP_LoadConstString] = (Instruction) {
        OP_LoadConstString, "LoadConstString", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* String ID */
        4 /* opcode + reg + 2-byte string ID */
    };
    
    instructions[OP_LoadConstStringLongIndex] = (Instruction) {
        OP_LoadConstStringLongIndex, "LoadConstStringLongIndex", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* String ID */
        6 /* opcode + reg + 4-byte string ID */
    };
    
    /* Using OP_LoadConstDouble instead of LoadConstNumber */
    instructions[OP_LoadConstDouble] = (Instruction) {
        OP_LoadConstDouble, "LoadConstDouble", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}, /* low32 */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* high32 */
        10 /* opcode + reg + 4 + 4 */
    };
    
    instructions[OP_LoadConstBigInt] = (Instruction) {
        OP_LoadConstBigInt, "LoadConstBigInt", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_BIGINT_ID}}, /* BigInt ID */
        4 /* opcode + reg + 2-byte bigint ID */
    };

    instructions[OP_LoadConstBigIntLongIndex] = (Instruction) {
        OP_LoadConstBigIntLongIndex, "LoadConstBigIntLongIndex",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_BIGINT_ID}}, /* BigInt ID (u32) */
        6 /* opcode + reg + 4 */
    };
    
    instructions[OP_LoadConstEmpty] = (Instruction) {
        OP_LoadConstEmpty, "LoadConstEmpty", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    /* Using OP_LoadThisNS instead of LoadThis */
    instructions[OP_LoadThisNS] = (Instruction) {
        OP_LoadThisNS, "LoadThisNS", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    /* Basic arithmetic operations */
    instructions[OP_Add] = (Instruction) {
        OP_Add, "Add", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_Sub] = (Instruction) {
        OP_Sub, "Sub", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_Mul] = (Instruction) {
        OP_Mul, "Mul", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_Div] = (Instruction) {
        OP_Div, "Div", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_Mod] = (Instruction) {
        OP_Mod, "Mod", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    /* Unary operations */
    instructions[OP_Not] = (Instruction) {
        OP_Not, "Not", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Source operand */
        3 /* opcode + 2 regs */
    };
    
    instructions[OP_BitNot] = (Instruction) {
        OP_BitNot, "BitNot", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Source operand */
        3 /* opcode + 2 regs */
    };
    
    /* Bitwise operations */
    instructions[OP_BitAnd] = (Instruction) {
        OP_BitAnd, "BitAnd", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_BitOr] = (Instruction) {
        OP_BitOr, "BitOr", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_BitXor] = (Instruction) {
        OP_BitXor, "BitXor", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    /* Using OP_LShift instead of BitShl */
    instructions[OP_LShift] = (Instruction) {
        OP_LShift, "LShift", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    /* Using OP_RShift instead of BitShr */
    instructions[OP_RShift] = (Instruction) {
        OP_RShift, "RShift", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    /* Using OP_URshift instead of BitUshr */
    instructions[OP_URshift] = (Instruction) {
        OP_URshift, "URshift", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    /* Comparison instructions */
    instructions[OP_Less] = (Instruction) {
        OP_Less, "Less", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_Greater] = (Instruction) {
        OP_Greater, "Greater", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_LessEq] = (Instruction) {
        OP_LessEq, "LessEq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_GreaterEq] = (Instruction) {
        OP_GreaterEq, "GreaterEq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_Eq] = (Instruction) {
        OP_Eq, "Eq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_StrictEq] = (Instruction) {
        OP_StrictEq, "StrictEq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_Neq] = (Instruction) {
        OP_Neq, "Neq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_StrictNeq] = (Instruction) {
        OP_StrictNeq, "StrictNeq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    /* Object property access instructions */
    instructions[OP_GetByVal] = (Instruction) {
        OP_GetByVal, "GetByVal", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Property name/index */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_PutByVal] = (Instruction) {
        OP_PutByVal, "PutByVal", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Property name/index */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Value */
        4 /* opcode + 3 regs */
    };
    
    instructions[OP_GetById] = (Instruction) {
        OP_GetById, "GetById", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Obj */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Name id */
        6
    };
    
    instructions[OP_GetByIdLong] = (Instruction) {
        OP_GetByIdLong, "GetByIdLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Obj */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name id */
        8
    };
    
    instructions[OP_GetByIdShort] = (Instruction) {
        OP_GetByIdShort, "GetByIdShort", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Obj */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}, /* Flags */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_STRING_ID}}, /* Name id */
        5
    };
    
    /* TryGetById family */
    instructions[OP_TryGetById] = (Instruction) {
        OP_TryGetById, "TryGetById",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags/opt */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Name id */
        6 /* 1 +1+1+1+2 */
    };

    instructions[OP_TryGetByIdLong] = (Instruction) {
        OP_TryGetByIdLong, "TryGetByIdLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags/opt */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name id */
        8 /* 1 +1+1+1+4 */
    };

    /* TryPutById family */
    instructions[OP_TryPutById] = (Instruction) {
        OP_TryPutById, "TryPutById",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags/opt */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Name id */
        6
    };

    instructions[OP_TryPutByIdLong] = (Instruction) {
        OP_TryPutByIdLong, "TryPutByIdLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags/opt */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name id */
        8
    };

    /* PutNewOwnById family */
    instructions[OP_PutNewOwnByIdShort] = (Instruction) {
        OP_PutNewOwnByIdShort, "PutNewOwnByIdShort",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_STRING_ID}}, /* Name id */
        4
    };

    instructions[OP_PutNewOwnById] = (Instruction) {
        OP_PutNewOwnById, "PutNewOwnById",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Name id */
        5
    };

    instructions[OP_PutNewOwnByIdLong] = (Instruction) {
        OP_PutNewOwnByIdLong, "PutNewOwnByIdLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name id */
        7
    };

    instructions[OP_PutNewOwnNEById] = (Instruction) {
        OP_PutNewOwnNEById, "PutNewOwnNEById",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Name id */
        5
    };

    instructions[OP_PutNewOwnNEByIdLong] = (Instruction) {
        OP_PutNewOwnNEByIdLong, "PutNewOwnNEByIdLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name id */
        7
    };

    /* PutOwnByIndex */
    instructions[OP_PutOwnByIndex] = (Instruction) {
        OP_PutOwnByIndex, "PutOwnByIndex",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Index */
        4
    };

    instructions[OP_PutOwnByIndexL] = (Instruction) {
        OP_PutOwnByIndexL, "PutOwnByIndexL",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Index */
        7
    };

    /* Delete by id */
    instructions[OP_DelById] = (Instruction) {
        OP_DelById, "DelById",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Name id */
        5
    };

    instructions[OP_DelByIdLong] = (Instruction) {
        OP_DelByIdLong, "DelByIdLong",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name id */
        7
    };

    /* Delete by val */
    instructions[OP_DelByVal] = (Instruction) {
        OP_DelByVal, "DelByVal",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Key */
        4
    };

    instructions[OP_PutOwnGetterSetterByVal] = (Instruction) {
        OP_PutOwnGetterSetterByVal, "PutOwnGetterSetterByVal",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Prop */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Getter */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Setter */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Attrs */
        6
    };

    /* Property name enumeration */
    instructions[OP_GetPNameList] = (Instruction) {
        OP_GetPNameList, "GetPNameList",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        5
    };

    instructions[OP_GetNextPName] = (Instruction) {
        OP_GetNextPName, "GetNextPName",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        6
    };
    instructions[OP_PutById] = (Instruction) {
        OP_PutById, "PutById", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Name id */
        6
    };
    
    instructions[OP_PutByIdLong] = (Instruction) {
        OP_PutByIdLong, "PutByIdLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE},  /* Flags */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name id */
        8
    };
    
    /* Creation/manipulation instructions */
    instructions[OP_NewObject] = (Instruction) {
        OP_NewObject, "NewObject", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 reg */
    };
    
    instructions[OP_NewObjectWithParent] = (Instruction) {
        OP_NewObjectWithParent, "NewObjectWithParent",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Parent */
        3
    };
    
    instructions[OP_NewArray] = (Instruction) {
        OP_NewArray, "NewArray", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}}, /* Count */
        4 /* opcode + 1 + 2 */
    };
    
    /* Note: NewObjectWithBuffer/NewArrayWithBuffer variants are defined earlier with correct layouts/sizes */

    /* Generators */
    instructions[OP_StartGenerator] = (Instruction) {
        OP_StartGenerator, "StartGenerator",
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1
    };

    instructions[OP_ResumeGenerator] = (Instruction) {
        OP_ResumeGenerator, "ResumeGenerator",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_CompleteGenerator] = (Instruction) {
        OP_CompleteGenerator, "CompleteGenerator",
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1
    };

    instructions[OP_CreateGenerator] = (Instruction) {
        OP_CreateGenerator, "CreateGenerator",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_FUNCTION_ID}},
        5
    };

    instructions[OP_CreateGeneratorLongIndex] = (Instruction) {
        OP_CreateGeneratorLongIndex, "CreateGeneratorLongIndex",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_FUNCTION_ID}},
        7
    };

    /* SaveGenerator: stores the resume target (short/long address) */
    instructions[OP_SaveGenerator] = (Instruction) {
        OP_SaveGenerator, "SaveGenerator",
        {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        2 /* opcode + addr8 */
    };

    instructions[OP_SaveGeneratorLong] = (Instruction) {
        OP_SaveGeneratorLong, "SaveGeneratorLong",
        {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        5 /* opcode + addr32 */
    };
    
    instructions[OP_CreateRegExp] = (Instruction) {
        OP_CreateRegExp, "CreateRegExp", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}, /* Pattern string ID */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}, /* Flags string ID */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Extra */
        13 /* opcode + reg + 3*u32 */
    };
    
    /* Environment operations */
    instructions[OP_CreateEnvironment] = (Instruction) {
        OP_CreateEnvironment, "CreateEnvironment", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Environment register */
        2 /* opcode + 1 reg */
    };

    instructions[OP_CreateInnerEnvironment] = (Instruction) {
        OP_CreateInnerEnvironment, "CreateInnerEnvironment",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* New env dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Outer env reg */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Captured count */
        7 /* opcode + 2 regs + u32 */
    };

    instructions[OP_GetEnvironment] = (Instruction) {
        OP_GetEnvironment, "GetEnvironment",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Depth */
        3 /* opcode + reg + u8 */
    };

    instructions[OP_GetGlobalObject] = (Instruction) {
        OP_GetGlobalObject, "GetGlobalObject",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Dest */
        2 /* opcode + reg */
    };

    instructions[OP_GetNewTarget] = (Instruction) {
        OP_GetNewTarget, "GetNewTarget",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Dest */
        2 /* opcode + reg */
    };

    instructions[OP_DeclareGlobalVar] = (Instruction) {
        OP_DeclareGlobalVar, "DeclareGlobalVar",
        {{OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name string id */
        5 /* opcode + u32 */
    };

    instructions[OP_ThrowIfHasRestrictedGlobalProperty] = (Instruction) {
        OP_ThrowIfHasRestrictedGlobalProperty, "ThrowIfHasRestrictedGlobalProperty",
        {{OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Name string id */
        5 /* opcode + u32 */
    };
    
    /* Special instructions */
    instructions[OP_SwitchImm] = (Instruction) {
        OP_SwitchImm, "SwitchImm", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value to switch on */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}, /* Jump table offset */
         {OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}, /* Default address */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}, /* Minimum value */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Maximum value */
        18 /* opcode + 1 + 4 + 4 + 4 + 4 = 18 */
    };
    
    instructions[OP_Debugger] = (Instruction) {
        OP_Debugger, "Debugger", 
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1 /* opcode only */
    };

    instructions[OP_Ret] = (Instruction) {
        OP_Ret, "Ret",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        2
    };

    instructions[OP_DirectEval] = (Instruction) {
        OP_DirectEval, "DirectEval",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_AsyncBreakCheck] = (Instruction) {
        OP_AsyncBreakCheck, "AsyncBreakCheck",
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1
    };

    instructions[OP_ProfilePoint] = (Instruction) {
        OP_ProfilePoint, "ProfilePoint",
        {{OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}},
        3
    };

    /* Fixed-arg call helpers */
    instructions[OP_Call1] = (Instruction) {
        OP_Call1, "Call1",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_Call2] = (Instruction) {
        OP_Call2, "Call2",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        5
    };

    instructions[OP_Call3] = (Instruction) {
        OP_Call3, "Call3",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        6
    };

    instructions[OP_Call4] = (Instruction) {
        OP_Call4, "Call4",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        7
    };
    
    /* TypedArrays and other modern features */
    instructions[OP_TypeOf] = (Instruction) {
        OP_TypeOf, "TypeOf", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Source register */
        3 /* opcode + 2 regs */
    };
    
    instructions[OP_InstanceOf] = (Instruction) {
        OP_InstanceOf, "InstanceOf", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Constructor */
        4 /* opcode + 3 regs */
    };
    
    /* Simple loads */
    instructions[OP_LoadConstUInt8] = (Instruction) {
        OP_LoadConstUInt8, "LoadConstUInt8",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Value */
        3
    };

    instructions[OP_LoadConstInt] = (Instruction) {
        OP_LoadConstInt, "LoadConstInt",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Value */
        6
    };

    /* This + object selection */
    instructions[OP_CoerceThisNS] = (Instruction) {
        OP_CoerceThisNS, "CoerceThisNS",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* This */
        3
    };

    instructions[OP_CreateThis] = (Instruction) {
        OP_CreateThis, "CreateThis",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Func */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* NewTarget */
        4
    };

    instructions[OP_SelectObject] = (Instruction) {
        OP_SelectObject, "SelectObject",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Obj1 */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Obj2 */
        4
    };

    /* Closures */
    instructions[OP_CreateClosure] = (Instruction) {
        OP_CreateClosure, "CreateClosure",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Dest */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* This/Env */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_FUNCTION_ID}}, /* Func id */
        5
    };

    instructions[OP_CreateClosureLongIndex] = (Instruction) {
        OP_CreateClosureLongIndex, "CreateClosureLongIndex",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_FUNCTION_ID}},
        7
    };

    instructions[OP_CreateGeneratorClosure] = (Instruction) {
        OP_CreateGeneratorClosure, "CreateGeneratorClosure",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_FUNCTION_ID}},
        5
    };

    instructions[OP_CreateGeneratorClosureLongIndex] = (Instruction) {
        OP_CreateGeneratorClosureLongIndex, "CreateGeneratorClosureLongIndex",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_FUNCTION_ID}},
        7
    };

    instructions[OP_CreateAsyncClosure] = (Instruction) {
        OP_CreateAsyncClosure, "CreateAsyncClosure",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_FUNCTION_ID}},
        5
    };

    instructions[OP_CreateAsyncClosureLongIndex] = (Instruction) {
        OP_CreateAsyncClosureLongIndex, "CreateAsyncClosureLongIndex",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_FUNCTION_ID}},
        7
    };

    /* Conversions */
    instructions[OP_ToNumber] = (Instruction) {
        OP_ToNumber, "ToNumber",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_ToNumeric] = (Instruction) {
        OP_ToNumeric, "ToNumeric",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    /* Iterators */
    instructions[OP_IteratorBegin] = (Instruction) {
        OP_IteratorBegin, "IteratorBegin",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        3
    };

    instructions[OP_IteratorNext] = (Instruction) {
        OP_IteratorNext, "IteratorNext",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        4
    };

    instructions[OP_IteratorClose] = (Instruction) {
        OP_IteratorClose, "IteratorClose",
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Hint */
        3
    };
    
    /* Compare-and-jump family (Addr, Reg, Reg) */
    instructions[OP_JLess] = (Instruction) { OP_JLess, "JLess", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JLessLong] = (Instruction) { OP_JLessLong, "JLessLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotLess] = (Instruction) { OP_JNotLess, "JNotLess", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotLessLong] = (Instruction) { OP_JNotLessLong, "JNotLessLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JLessN] = (Instruction) { OP_JLessN, "JLessN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JLessNLong] = (Instruction) { OP_JLessNLong, "JLessNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotLessN] = (Instruction) { OP_JNotLessN, "JNotLessN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotLessNLong] = (Instruction) { OP_JNotLessNLong, "JNotLessNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JLessEqual] = (Instruction) { OP_JLessEqual, "JLessEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JLessEqualLong] = (Instruction) { OP_JLessEqualLong, "JLessEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotLessEqual] = (Instruction) { OP_JNotLessEqual, "JNotLessEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotLessEqualLong] = (Instruction) { OP_JNotLessEqualLong, "JNotLessEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JLessEqualN] = (Instruction) { OP_JLessEqualN, "JLessEqualN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JLessEqualNLong] = (Instruction) { OP_JLessEqualNLong, "JLessEqualNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotLessEqualN] = (Instruction) { OP_JNotLessEqualN, "JNotLessEqualN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotLessEqualNLong] = (Instruction) { OP_JNotLessEqualNLong, "JNotLessEqualNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JGreater] = (Instruction) { OP_JGreater, "JGreater", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JGreaterLong] = (Instruction) { OP_JGreaterLong, "JGreaterLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotGreater] = (Instruction) { OP_JNotGreater, "JNotGreater", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotGreaterLong] = (Instruction) { OP_JNotGreaterLong, "JNotGreaterLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JGreaterN] = (Instruction) { OP_JGreaterN, "JGreaterN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JGreaterNLong] = (Instruction) { OP_JGreaterNLong, "JGreaterNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotGreaterN] = (Instruction) { OP_JNotGreaterN, "JNotGreaterN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotGreaterNLong] = (Instruction) { OP_JNotGreaterNLong, "JNotGreaterNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JGreaterEqual] = (Instruction) { OP_JGreaterEqual, "JGreaterEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JGreaterEqualLong] = (Instruction) { OP_JGreaterEqualLong, "JGreaterEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotGreaterEqual] = (Instruction) { OP_JNotGreaterEqual, "JNotGreaterEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotGreaterEqualLong] = (Instruction) { OP_JNotGreaterEqualLong, "JNotGreaterEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JGreaterEqualN] = (Instruction) { OP_JGreaterEqualN, "JGreaterEqualN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JGreaterEqualNLong] = (Instruction) { OP_JGreaterEqualNLong, "JGreaterEqualNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotGreaterEqualN] = (Instruction) { OP_JNotGreaterEqualN, "JNotGreaterEqualN", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotGreaterEqualNLong] = (Instruction) { OP_JNotGreaterEqualNLong, "JNotGreaterEqualNLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JEqual] = (Instruction) { OP_JEqual, "JEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JEqualLong] = (Instruction) { OP_JEqualLong, "JEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JNotEqual] = (Instruction) { OP_JNotEqual, "JNotEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JNotEqualLong] = (Instruction) { OP_JNotEqualLong, "JNotEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JStrictEqual] = (Instruction) { OP_JStrictEqual, "JStrictEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JStrictEqualLong] = (Instruction) { OP_JStrictEqualLong, "JStrictEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };
    instructions[OP_JStrictNotEqual] = (Instruction) { OP_JStrictNotEqual, "JStrictNotEqual", {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_JStrictNotEqualLong] = (Instruction) { OP_JStrictNotEqualLong, "JStrictNotEqualLong", {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 7 };

    /* Typed arithmetic and memory ops */
    instructions[OP_Add32] = (Instruction) { OP_Add32, "Add32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Sub32] = (Instruction) { OP_Sub32, "Sub32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Mul32] = (Instruction) { OP_Mul32, "Mul32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Divi32] = (Instruction) { OP_Divi32, "Divi32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Divu32] = (Instruction) { OP_Divu32, "Divu32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Loadi8] = (Instruction) { OP_Loadi8, "Loadi8", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Loadu8] = (Instruction) { OP_Loadu8, "Loadu8", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Loadi16] = (Instruction) { OP_Loadi16, "Loadi16", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Loadu16] = (Instruction) { OP_Loadu16, "Loadu16", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Loadi32] = (Instruction) { OP_Loadi32, "Loadi32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Loadu32] = (Instruction) { OP_Loadu32, "Loadu32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Store8] = (Instruction) { OP_Store8, "Store8", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Store16] = (Instruction) { OP_Store16, "Store16", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    instructions[OP_Store32] = (Instruction) { OP_Store32, "Store32", {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, 4 };
    
    /* Count the number of actual defined opcodes */
    u32 defined_count = 0;
    for (u32 i = 0; i < instruction_count; i++) {
        if (strcmp(instructions[i].name, "Unknown") != 0) {
            defined_count++;
        }
    }
    
    if (out_count) *out_count = instruction_count; /* Return full set for array indexing */
    
    fprintf(stderr, "Initialized %u instruction definitions\n", defined_count);
    return instructions;
}
