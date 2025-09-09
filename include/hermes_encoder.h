#ifndef HERMES_DEC_HERMES_ENCODER_H
#define HERMES_DEC_HERMES_ENCODER_H

#include "common.h"
#include "parsers/hbc_bytecode_parser.h"

/* Encoder context */
typedef struct {
    u32 bytecode_version;
    const Instruction* instruction_set;
    u32 instruction_count;
} HermesEncoder;

/* Encoded instruction representation */
typedef struct {
    u8 opcode;
    u32 size;  /* Total size in bytes */
    u32 arg1, arg2, arg3, arg4, arg5, arg6;
} EncodedInstruction;

/* Initialize encoder */
Result hermes_encoder_init(HermesEncoder* encoder, u32 bytecode_version);

/* Clean up encoder */
void hermes_encoder_cleanup(HermesEncoder* encoder);

/* Parse instruction from asm text */
Result hermes_encoder_parse_instruction(HermesEncoder* encoder, const char* asm_line,
                                       EncodedInstruction* out_instruction);

/* Encode instruction to bytecode */
Result hermes_encoder_encode_instruction(HermesEncoder* encoder, const EncodedInstruction* instruction,
                                        u8* out_buffer, size_t buffer_size, size_t* out_bytes_written);

/* Encode multiple instructions from asm text */
Result hermes_encoder_encode_instructions(HermesEncoder* encoder, const char* asm_text,
                                         u8* out_buffer, size_t buffer_size, size_t* out_bytes_written);

#endif /* HERMES_DEC_HERMES_ENCODER_H */

