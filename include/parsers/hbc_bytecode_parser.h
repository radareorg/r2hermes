#ifndef HERMES_DEC_HBC_BYTECODE_PARSER_H
#define HERMES_DEC_HBC_BYTECODE_PARSER_H

#include "../common.h"
#include "hbc_file_parser.h"

/* Operand type enum */
typedef enum {
	OPERAND_TYPE_NONE,
	OPERAND_TYPE_REG8,
	OPERAND_TYPE_REG32,
	OPERAND_TYPE_UINT8,
	OPERAND_TYPE_UINT16,
	OPERAND_TYPE_UINT32,
	OPERAND_TYPE_ADDR8,
	OPERAND_TYPE_ADDR32,
	OPERAND_TYPE_IMM32,
	OPERAND_TYPE_DOUBLE
} OperandType;

/* Operand meaning enum */
typedef enum {
	OPERAND_MEANING_NONE,
	OPERAND_MEANING_STRING_ID,
	OPERAND_MEANING_BIGINT_ID,
	OPERAND_MEANING_FUNCTION_ID,
	OPERAND_MEANING_BUILTIN_ID,
	OPERAND_MEANING_ARRAY_ID,
	OPERAND_MEANING_OBJ_KEY_ID,
	OPERAND_MEANING_OBJ_VAL_ID
} OperandMeaning;

/* Instruction operand */
typedef struct {
	OperandType operand_type;
	OperandMeaning operand_meaning;
} InstructionOperand;

/* Instruction definition */
typedef struct {
	u8 opcode;
	const char *name;
	InstructionOperand operands[6]; /* Up to 6 operands per instruction */
	u32 binary_size; /* Total size in bytes */
} Instruction;

/* Parsed instruction */
typedef struct {
    const Instruction* inst;
    u32 arg1;
    union {
        u32 arg2;
        double double_arg2;
    };
    u32 arg3;
    u32 arg4;
    u32 arg5;
    u32 arg6;
    u32* switch_jump_table;
    u32 switch_jump_table_size;
    u32 original_pos;
    u32 next_pos;
    u32 function_offset;
    HBCReader* hbc_reader;
} ParsedInstruction;

/* List of parsed instructions */
typedef struct {
	ParsedInstruction *instructions;
	u32 count;
	u32 capacity;
} ParsedInstructionList;

/* Function declarations */
Result parsed_instruction_list_init(ParsedInstructionList *list, u32 initial_capacity);
Result parsed_instruction_list_add(ParsedInstructionList *list, ParsedInstruction *instruction);
void parsed_instruction_list_free(ParsedInstructionList *list);

Result parse_instruction(HBCReader *reader, FunctionHeader *function_header,
	u32 offset, ParsedInstruction *out_instruction);
Result parse_function_bytecode(HBCReader *reader, u32 function_id,
	ParsedInstructionList *out_instructions);
Result instruction_to_string(ParsedInstruction *instruction, StringBuffer *out_string);

/* Bytecode version module getters */
BytecodeModule *get_bytecode_module(u32 bytecode_version);
const char **get_builtin_functions(BytecodeModule *module, u32 *out_count);

/* Opcode handlers (defined in version-specific modules) */
typedef Result(*OpcodeHandler)(HBCReader *reader, BufferReader *bytecode,
	ParsedInstruction *out_instruction);

/* Helpers to classify opcodes */
bool is_jump_instruction(u8 opcode);
bool is_call_instruction(u8 opcode);

#endif /* HERMES_DEC_HBC_BYTECODE_PARSER_H */
