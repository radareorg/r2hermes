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
    
    /* Add basic instructions based on hbc95.py */
    instructions[OP_Unreachable] = (Instruction) {
        OP_Unreachable, "Unreachable", 
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1 /* opcode only */
    };
    
    instructions[OP_NewObjectWithBuffer] = (Instruction) {
        OP_NewObjectWithBuffer, "NewObjectWithBuffer", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_OBJ_KEY_ID},
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_OBJ_VAL_ID}},
        8 /* opcode + 5 operands */
    };
    
    instructions[OP_Jmp] = (Instruction) {
        OP_Jmp, "Jmp", 
        {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        2 /* opcode + offset */
    };
    
    instructions[OP_JmpTrue] = (Instruction) {
        OP_JmpTrue, "JmpTrue", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        3 /* opcode + reg + offset */
    };
    
    instructions[OP_JmpFalse] = (Instruction) {
        OP_JmpFalse, "JmpFalse", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        3 /* opcode + reg + offset */
    };
    
    instructions[OP_JmpUndefined] = (Instruction) {
        OP_JmpUndefined, "JmpUndefined", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        3 /* opcode + reg + offset */
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
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Error message */
        4 /* opcode + reg + message id */
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
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Target function */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* 'this' value */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        6 /* opcode + 5 operands */
    };
    
    instructions[OP_CallLong] = (Instruction) {
        OP_CallLong, "CallLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Target function */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* 'this' value */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}}, /* Argument count */
        7 /* opcode + 5 operands (with 2-byte arg count) */
    };
    
    instructions[OP_Construct] = (Instruction) {
        OP_Construct, "Construct", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Target function */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        5 /* opcode + 4 operands */
    };
    
    instructions[OP_ConstructLong] = (Instruction) {
        OP_ConstructLong, "ConstructLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Target function */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_NONE}}, /* Argument count */
        6 /* opcode + 4 operands (with 2-byte arg count) */
    };
    
    /* CallN is not present in the current opcode set */
    
    /* ConstructN is not present in the current opcode set */
    
    instructions[OP_CallDirect] = (Instruction) {
        OP_CallDirect, "CallDirect", 
        {{OPERAND_TYPE_IMM16, OPERAND_MEANING_FUNCTION_ID}, /* Function ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        6 /* opcode + 2-byte func ID + 3 operands */
    };
    
    instructions[OP_CallDirectLongIndex] = (Instruction) {
        OP_CallDirectLongIndex, "CallDirectLongIndex", 
        {{OPERAND_TYPE_IMM32, OPERAND_MEANING_FUNCTION_ID}, /* Function ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        8 /* opcode + 4-byte func ID + 3 operands */
    };
    
    instructions[OP_CallBuiltin] = (Instruction) {
        OP_CallBuiltin, "CallBuiltin", 
        {{OPERAND_TYPE_IMM8, OPERAND_MEANING_BUILTIN_ID}, /* Builtin ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        5 /* opcode + 4 operands */
    };
    
    /* Load/Store instructions */
    instructions[OP_LoadParam] = (Instruction) {
        OP_LoadParam, "LoadParam", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Parameter index */
        3 /* opcode + 2 operands */
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
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Number value (encoded as u32) */
        6 /* opcode + reg + 4-byte number */
    };
    
    instructions[OP_LoadConstBigInt] = (Instruction) {
        OP_LoadConstBigInt, "LoadConstBigInt", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_BIGINT_ID}}, /* BigInt ID */
        4 /* opcode + reg + 2-byte bigint ID */
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
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Property name ID */
        5 /* opcode + 2 regs + 2-byte string ID */
    };
    
    instructions[OP_GetByIdLong] = (Instruction) {
        OP_GetByIdLong, "GetByIdLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}}, /* Property name ID */
        7 /* opcode + 2 regs + 4-byte string ID */
    };
    
    instructions[OP_GetByIdShort] = (Instruction) {
        OP_GetByIdShort, "GetByIdShort", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_STRING_ID}}, /* Property name ID */
        4 /* opcode + 2 regs + 1-byte string ID */
    };
    
    instructions[OP_PutById] = (Instruction) {
        OP_PutById, "PutById", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}, /* Property name ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Value */
        5 /* opcode + reg + 2-byte string ID + reg */
    };
    
    instructions[OP_PutByIdLong] = (Instruction) {
        OP_PutByIdLong, "PutByIdLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_STRING_ID}, /* Property name ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Value */
        7 /* opcode + reg + 4-byte string ID + reg */
    };
    
    /* Creation/manipulation instructions */
    instructions[OP_NewObject] = (Instruction) {
        OP_NewObject, "NewObject", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 reg */
    };
    
    instructions[OP_NewObjectWithBuffer] = (Instruction) {
        OP_NewObjectWithBuffer, "NewObjectWithBuffer", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Prototype */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}, /* Property count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_OBJ_KEY_ID}, /* Keys index */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_OBJ_VAL_ID}}, /* Values index */
        8 /* opcode + 2 regs + 1-byte count + 2 2-byte indices */
    };
    
    instructions[OP_NewArray] = (Instruction) {
        OP_NewArray, "NewArray", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First element register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Element count */
        4 /* opcode + 2 regs + count */
    };
    
    instructions[OP_NewArrayWithBuffer] = (Instruction) {
        OP_NewArrayWithBuffer, "NewArrayWithBuffer", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Prototype */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}, /* Element count */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_ARRAY_ID}}, /* Array index */
        6 /* opcode + 2 regs + 1-byte count + 2-byte index */
    };
    
    instructions[OP_CreateRegExp] = (Instruction) {
        OP_CreateRegExp, "CreateRegExp", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}, /* Pattern string ID */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Flags */
        5 /* opcode + reg + 2-byte string ID + flags */
    };
    
    /* Environment operations */
    instructions[OP_CreateEnvironment] = (Instruction) {
        OP_CreateEnvironment, "CreateEnvironment", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Environment register */
        2 /* opcode + 1 reg */
    };
    
    /* Special instructions */
    instructions[OP_SwitchImm] = (Instruction) {
        OP_SwitchImm, "SwitchImm", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value to switch on */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}, /* Jump table offset */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Default target register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}, /* Minimum value */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Maximum value */
        8 /* opcode + reg + 4-byte offset + reg + min + max */
    };
    
    instructions[OP_Debugger] = (Instruction) {
        OP_Debugger, "Debugger", 
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1 /* opcode only */
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

