#include "../../include/opcodes/hermes_opcodes.h"
#include <stdlib.h>

/* Define instruction set for bytecode version 96 */
Instruction* get_instruction_set_v96(u32* out_count) {
    /* Allocate memory for the instruction set */
    const u32 instruction_count = 100; /* Approximate number of opcodes */
    Instruction* instructions = (Instruction*)malloc(instruction_count * sizeof(Instruction));
    if (!instructions) {
        if (out_count) *out_count = 0;
        return NULL;
    }
    
    u32 index = 0;
    
    /* Control flow */
    instructions[index++] = (Instruction) {
        OP_Ret, "Ret", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        2 /* opcode + reg */
    };
    
    instructions[index++] = (Instruction) {
        OP_RetUndefined, "RetUndefined", 
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1 /* opcode only */
    };
    
    instructions[index++] = (Instruction) {
        OP_Jmp, "Jmp", 
        {{OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        2 /* opcode + offset */
    };
    
    instructions[index++] = (Instruction) {
        OP_JmpTrue, "JmpTrue", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        3 /* opcode + reg + offset */
    };
    
    instructions[index++] = (Instruction) {
        OP_JmpFalse, "JmpFalse", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR8, OPERAND_MEANING_NONE}},
        3 /* opcode + reg + offset */
    };
    
    instructions[index++] = (Instruction) {
        OP_JmpLong, "JmpLong", 
        {{OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        5 /* opcode + long offset */
    };
    
    instructions[index++] = (Instruction) {
        OP_JmpTrueLong, "JmpTrueLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        6 /* opcode + reg + long offset */
    };
    
    instructions[index++] = (Instruction) {
        OP_JmpFalseLong, "JmpFalseLong", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, 
         {OPERAND_TYPE_ADDR32, OPERAND_MEANING_NONE}},
        6 /* opcode + reg + long offset */
    };
    
    instructions[index++] = (Instruction) {
        OP_Throw, "Throw", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}},
        2 /* opcode + reg */
    };
    
    /* Calls */
    instructions[index++] = (Instruction) {
        OP_Call, "Call", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Target function */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* 'this' value */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        6 /* opcode + 5 operands */
    };
    
    instructions[index++] = (Instruction) {
        OP_Construct, "Construct", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Target function */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        5 /* opcode + 4 operands */
    };
    
    instructions[index++] = (Instruction) {
        OP_CallDirect, "CallDirect", 
        {{OPERAND_TYPE_IMM16, OPERAND_MEANING_FUNCTION_ID}, /* Function ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        6 /* opcode + 2-byte func ID + 3 operands */
    };
    
    instructions[index++] = (Instruction) {
        OP_CallBuiltin, "CallBuiltin", 
        {{OPERAND_TYPE_IMM8, OPERAND_MEANING_BUILTIN_ID}, /* Builtin ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First argument */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Return register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Argument count */
        5 /* opcode + 4 operands */
    };
    
    /* Load/Store */
    instructions[index++] = (Instruction) {
        OP_LoadParam, "LoadParam", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Parameter index */
        3 /* opcode + 2 operands */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstZero, "LoadConstZero", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstUndefined, "LoadConstUndefined", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstNull, "LoadConstNull", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstTrue, "LoadConstTrue", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstFalse, "LoadConstFalse", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstString, "LoadConstString", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* String ID */
        4 /* opcode + reg + 2-byte string ID */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstNumber, "LoadConstNumber", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Number value (encoded as u32) */
        6 /* opcode + reg + 4-byte number */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadConstBigInt, "LoadConstBigInt", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_BIGINT_ID}}, /* BigInt ID */
        4 /* opcode + reg + 2-byte bigint ID */
    };
    
    instructions[index++] = (Instruction) {
        OP_LoadThis, "LoadThis", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 operand */
    };
    
    /* Operations */
    instructions[index++] = (Instruction) {
        OP_Add, "Add", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_Sub, "Sub", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_Mul, "Mul", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_Div, "Div", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_Not, "Not", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Source operand */
        3 /* opcode + 2 regs */
    };
    
    /* Comparisons */
    instructions[index++] = (Instruction) {
        OP_Less, "Less", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_Greater, "Greater", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_Eq, "Eq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_StrictEq, "StrictEq", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Left operand */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Right operand */
        4 /* opcode + 3 regs */
    };
    
    /* Object operations */
    instructions[index++] = (Instruction) {
        OP_GetByVal, "GetByVal", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Property name/index */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_PutByVal, "PutByVal", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Property name/index */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Value */
        4 /* opcode + 3 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_GetById, "GetById", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}}, /* Property name ID */
        5 /* opcode + 2 regs + 2-byte string ID */
    };
    
    instructions[index++] = (Instruction) {
        OP_PutById, "PutById", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}, /* Property name ID */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Value */
        5 /* opcode + reg + 2-byte string ID + reg */
    };
    
    /* Creation/manipulation */
    instructions[index++] = (Instruction) {
        OP_NewObject, "NewObject", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Destination register */
        2 /* opcode + 1 reg */
    };
    
    instructions[index++] = (Instruction) {
        OP_NewArray, "NewArray", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* First element register */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Element count */
        4 /* opcode + 2 regs + count */
    };
    
    instructions[index++] = (Instruction) {
        OP_CreateRegExp, "CreateRegExp", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_IMM16, OPERAND_MEANING_STRING_ID}, /* Pattern string ID */
         {OPERAND_TYPE_IMM8, OPERAND_MEANING_NONE}}, /* Flags */
        5 /* opcode + reg + 2-byte string ID + flags */
    };
    
    /* Special instructions */
    instructions[index++] = (Instruction) {
        OP_SwitchImm, "SwitchImm", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Value to switch on */
         {OPERAND_TYPE_IMM32, OPERAND_MEANING_NONE}}, /* Jump table size */
        6 /* opcode + reg + 4-byte size + variable jump table */
    };
    
    instructions[index++] = (Instruction) {
        OP_Debugger, "Debugger", 
        {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}},
        1 /* opcode only */
    };
    
    /* TypedArrays and other modern features */
    instructions[index++] = (Instruction) {
        OP_TypeOf, "TypeOf", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Source register */
        3 /* opcode + 2 regs */
    };
    
    instructions[index++] = (Instruction) {
        OP_InstanceOf, "InstanceOf", 
        {{OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Destination register */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}, /* Object */
         {OPERAND_TYPE_REG8, OPERAND_MEANING_NONE}}, /* Constructor */
        4 /* opcode + 3 regs */
    };
    
    /* Update the actual count */
    if (out_count) *out_count = index;
    
    return instructions;
}

