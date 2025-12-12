#ifndef HBC_ENCODER_H
#define HBC_ENCODER_H

#include <hbc/common.h>
#include <hbc/parsers/hbc_bytecode_parser.h>

/* Encoder context */
typedef struct {
	u32 bytecode_version;
	const Instruction *instruction_set;
	u32 instruction_count;
} HBCEncoder;

/* Encoded instruction representation */
typedef struct {
	u8 opcode;
	u32 size; /* Total size in bytes */
	u64 arg1, arg2, arg3, arg4, arg5, arg6;
} HBCEncodedInstruction;

/* Initialize encoder */
Result hbc_encoder_init(HBCEncoder *encoder, u32 bytecode_version);

/* Clean up encoder */
void hbc_encoder_cleanup(HBCEncoder *encoder);

/* Parse instruction from asm text */
Result hbc_encoder_parse_instruction(HBCEncoder *encoder, const char *asm_line,
	HBCEncodedInstruction *out_instruction);

/* Encode instruction to bytecode */
Result hbc_encoder_encode_instruction(HBCEncoder *encoder, const HBCEncodedInstruction *instruction,
	u8 *out_buffer, size_t buffer_size, size_t *out_bytes_written);

/* Encode multiple instructions from asm text */
Result hbc_encoder_encode_instructions(HBCEncoder *encoder, const char *asm_text,
	u8 *out_buffer, size_t buffer_size, size_t *out_bytes_written);

#endif /* HBC_ENCODER_H */
