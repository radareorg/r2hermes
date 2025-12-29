#ifndef LIBHBC_DISASSEMBLER_H
#define LIBHBC_DISASSEMBLER_H

#include <hbc/common.h>
#include <hbc/parser.h>
#include <hbc/bytecode.h>
#include <hbc/hbc.h>

/* Disassembly options - defined in hbc.h */

/* Disassembler state */
typedef struct {
	HBCReader *reader; /* The HBC reader with parsed data */
	StringBuffer output; /* The output buffer */
	HBCDisOptions options; /* Disassembly options */
	u32 current_function_id; /* Function currently being disassembled */
} Disassembler;

/* Function declarations */
Result _hbc_disassembler_init(Disassembler *disassembler, HBCReader *reader, HBCDisOptions options);
void _hbc_disassembler_cleanup(Disassembler *disassembler);

Result _hbc_disassemble_file(const char *input_file, const char *output_file, HBCDisOptions options);
Result _hbc_disassemble_buffer(const u8 *buffer, size_t size, const char *output_file, HBCDisOptions options);
Result _hbc_disassemble_function(Disassembler *disassembler, u32 function_id);
Result _hbc_disassemble_all_functions(Disassembler *disassembler);

Result _hbc_output_disassembly(Disassembler *disassembler, const char *output_file);

/* r2 script generation function */
Result _hbc_generate_r2_script(const char *input_file, const char *output_file);

/* Utility functions */
Result _hbc_print_function_header(Disassembler *disassembler, FunctionHeader *function_header, u32 function_id);
Result _hbc_print_instruction(Disassembler *disassembler, ParsedInstruction *instruction);

#endif /* LIBHBC_DISASSEMBLER_H */
