/* radare2 - BSD - Copyright 2025-2026 - pancake */

#ifndef LIBHBC_BYTECODE_H
#define LIBHBC_BYTECODE_H

#include <hbc/common.h>
#include <hbc/opcodes.h>
#include <hbc/parser.h>

/* Parsed instruction */
typedef struct {
	const Instruction *inst;
	u8 opcode;
	u32 arg1;
	union {
		u32 arg2;
		double double_arg2;
	};
	u32 arg3;
	u32 arg4;
	u32 arg5;
	u32 arg6;
	u32 *switch_jump_table;
	u32 switch_jump_table_size;
	u32 original_pos;
	u32 next_pos;
	u32 function_offset;
	HBCReader *hbc_reader;
} ParsedInstruction;

/* List of parsed instructions */
typedef struct {
	ParsedInstruction *instructions;
	u32 count;
	u32 capacity;
} ParsedInstructionList;

/* Function declarations */
Result _hbc_parsed_instruction_list_init(ParsedInstructionList *list, u32 initial_capacity);
Result _hbc_parsed_instruction_list_add(ParsedInstructionList *list, ParsedInstruction *instruction);
void _hbc_parsed_instruction_list_free(ParsedInstructionList *list);

Result _hbc_parse_instruction(HBCReader *reader, FunctionHeader *function_header, u32 offset, ParsedInstruction *out_instruction);
Result _hbc_parse_function_bytecode(HBCReader *reader, u32 function_id, ParsedInstructionList *out_instructions, HBCISA isa);
Result _hbc_instruction_to_string(ParsedInstruction *instruction, StringBuffer *out_string);

/* Raw value of the i-th operand (0..5); 0 when the index is out of range. */
u32 hbc_operand_value(const ParsedInstruction *insn, int i);

/* True when operand `idx` (0..5) is a relative jump/branch address. */
bool _hbc_operand_is_addr(const Instruction *inst, int idx);

/* Absolute (function-relative) branch target of operand `op_index`.
 * Hermes offsets are relative to the start of the instruction. */
u32 _hbc_compute_target_address(const ParsedInstruction *insn, int op_index);

/* Bytecode version module getters */
BytecodeModule *_hbc_get_bytecode_module(u32 bytecode_version);
const char **_hbc_get_builtin_functions(BytecodeModule *module, u32 *out_count);

/* Opcode handlers (defined in version-specific modules) */
typedef Result(*OpcodeHandler)(HBCReader *reader, BufferReader *bytecode, ParsedInstruction *out_instruction);

/* Helpers to classify opcodes */
bool _hbc_is_jump_instruction(u8 opcode);
bool _hbc_is_call_instruction(u8 opcode);

#endif /* LIBHBC_BYTECODE_H */
