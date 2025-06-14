#ifndef HERMES_DEC_HBC_DISASSEMBLER_H
#define HERMES_DEC_HBC_DISASSEMBLER_H

#include "../common.h"
#include "../parsers/hbc_file_parser.h"
#include "../parsers/hbc_bytecode_parser.h"

/* Disassembly options */
typedef struct {
    bool verbose;           /* Show detailed metadata */
    bool output_json;       /* Output in JSON format instead of text */
    bool show_bytecode;     /* Show raw bytecode bytes */
    bool show_debug_info;   /* Show debug information */
} DisassemblyOptions;

/* Disassembler state */
typedef struct {
    HBCReader* reader;      /* The HBC reader with parsed data */
    StringBuffer output;    /* The output buffer */
    DisassemblyOptions options; /* Disassembly options */
} Disassembler;

/* Function declarations */
Result disassembler_init(Disassembler* disassembler, HBCReader* reader, DisassemblyOptions options);
void disassembler_cleanup(Disassembler* disassembler);

Result disassemble_file(const char* input_file, const char* output_file, DisassemblyOptions options);
Result disassemble_buffer(const u8* buffer, size_t size, const char* output_file, DisassemblyOptions options);
Result disassemble_function(Disassembler* disassembler, u32 function_id);
Result disassemble_all_functions(Disassembler* disassembler);

Result output_disassembly(Disassembler* disassembler, const char* output_file);

/* Utility functions */
Result print_function_header(Disassembler* disassembler, FunctionHeader* function_header, u32 function_id);
Result print_instruction(Disassembler* disassembler, ParsedInstruction* instruction);

#endif /* HERMES_DEC_HBC_DISASSEMBLER_H */

