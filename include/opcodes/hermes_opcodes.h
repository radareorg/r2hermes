#ifndef HERMES_DEC_HERMES_OPCODES_H
#define HERMES_DEC_HERMES_OPCODES_H

#include "../common.h"
#include "../parsers/hbc_bytecode_parser.h"

/* Hermes opcodes based on bytecode version 96 */
enum HermesOpcodes {
    /* Control flow */
    OP_Ret = 0x01,
    OP_RetUndefined = 0x02,
    OP_Jmp = 0x03,
    OP_JmpTrue = 0x04,
    OP_JmpFalse = 0x05,
    OP_JmpUndefined = 0x06,
    OP_JmpLong = 0x07,
    OP_Catch = 0x08,
    OP_Throw = 0x09,
    OP_ThrowIfEmpty = 0x0A,
    OP_JmpTrueLong = 0x0B,
    OP_JmpFalseLong = 0x0C,
    OP_JmpUndefinedLong = 0x0D,
    
    /* Calls */
    OP_Call = 0x10,
    OP_CallLong = 0x11,
    OP_Construct = 0x12,
    OP_ConstructLong = 0x13,
    OP_CallN = 0x14,
    OP_ConstructN = 0x15,
    OP_CallDirect = 0x16,
    OP_CallDirectLongIndex = 0x17,
    OP_CallBuiltin = 0x18,
    
    /* Load/Store */
    OP_LoadParam = 0x20,
    OP_LoadConstZero = 0x21,
    OP_LoadConstUndefined = 0x22,
    OP_LoadConstNull = 0x23,
    OP_LoadConstTrue = 0x24,
    OP_LoadConstFalse = 0x25,
    OP_LoadConstString = 0x26,
    OP_LoadConstStringLongIndex = 0x27,
    OP_LoadConstNumber = 0x28,
    OP_LoadConstBigInt = 0x29,
    OP_LoadConstEmpty = 0x2A,
    OP_LoadThis = 0x2B,
    
    /* Operations */
    OP_Add = 0x30,
    OP_Sub = 0x31,
    OP_Mul = 0x32,
    OP_Div = 0x33,
    OP_Mod = 0x34,
    OP_Not = 0x35,
    OP_BitNot = 0x36,
    OP_BitAnd = 0x37,
    OP_BitOr = 0x38,
    OP_BitXor = 0x39,
    OP_BitShl = 0x3A,
    OP_BitShr = 0x3B,
    OP_BitUshr = 0x3C,
    
    /* Comparisons */
    OP_Less = 0x40,
    OP_Greater = 0x41,
    OP_LessEq = 0x42,
    OP_GreaterEq = 0x43,
    OP_Eq = 0x44,
    OP_StrictEq = 0x45,
    OP_Neq = 0x46,
    OP_StrictNeq = 0x47,
    
    /* Object operations */
    OP_GetByVal = 0x50,
    OP_PutByVal = 0x51,
    OP_GetById = 0x52,
    OP_GetByIdLong = 0x53,
    OP_GetByIdShort = 0x54,
    OP_GetPNameList = 0x55,
    OP_GetNextPName = 0x56,
    OP_PutById = 0x57,
    OP_PutByIdLong = 0x58,
    OP_PutNewObjByVal = 0x59,
    OP_PutNewObjById = 0x5A,
    OP_PutNewObjByIdLong = 0x5B,
    OP_PutNewObjByIdShort = 0x5C,
    OP_PutOwnByVal = 0x5D,
    OP_PutOwnById = 0x5E,
    
    /* Creation/manipulation */
    OP_NewObject = 0x60,
    OP_NewObjectWithBuffer = 0x61,
    OP_NewObjectWithBufferLong = 0x62,
    OP_NewArray = 0x63,
    OP_NewArrayWithBuffer = 0x64,
    OP_NewArrayWithBufferLong = 0x65,
    OP_CreateRegExp = 0x66,
    OP_DelById = 0x67,
    OP_DelByVal = 0x68,
    OP_TryGetById = 0x69,
    
    /* Scope chain */
    OP_CreateEnvironment = 0x70,
    OP_CreateInnerEnvironment = 0x71,
    OP_EnvironmentCreate = 0x72,  /* Renamed to avoid duplicate */
    OP_PutToEnvironment = 0x73,
    OP_GetFromEnvironment = 0x74,
    
    /* Flow control */
    OP_SwitchImm = 0x80,
    OP_ResumeGenerator = 0x81,
    OP_Debugger = 0x82,
    OP_AsyncBreakCheck = 0x83,
    OP_ProfilePoint = 0x84,
    
    /* TypedArrays and other modern features */
    OP_CreateArrayWithStack = 0x90,
    OP_TypeOf = 0x91,
    OP_InstanceOf = 0x92,
    OP_IsIn = 0x93,
    OP_GetTemplateObject = 0x94,
    OP_ToNumber = 0x95,
    OP_ToNumeric = 0x96,
    OP_ToString = 0x97,
    OP_ToObject = 0x98,
    
    /* Generators/async */
    OP_StartGenerator = 0xA0,
    OP_ResumeGeneratorLong = 0xA1,  /* Renamed to avoid duplicate */
    OP_CompleteGenerator = 0xA2,
};

/* Define the instruction set for bytecode version 96 */
Instruction* get_instruction_set_v96(u32* out_count);

/* Helper functions */
bool is_jump_instruction(u8 opcode);
bool is_call_instruction(u8 opcode);

#endif /* HERMES_DEC_HERMES_OPCODES_H */


