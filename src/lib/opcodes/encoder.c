#include <hbc/hermes_encoder.h>
#include <hbc/opcodes.h>
#include <hbc/bytecode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Cross-platform strcasecmp */
static int portable_strcasecmp(const char *s1, const char *s2) {
	while (*s1 && *s2) {
		unsigned char c1 = tolower ((unsigned char)*s1);
		unsigned char c2 = tolower ((unsigned char)*s2);
		if (c1 != c2) {
			return c1 - c2;
		}
		s1++;
		s2++;
	}
	return (unsigned char)*s1 - (unsigned char)*s2;
}

/* Initialize encoder */
Result hbc_encoder_init(HBCEncoder *encoder, u32 bytecode_version) {
	if (!encoder) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Encoder is NULL");
	}

	encoder->bytecode_version = bytecode_version;
	encoder->instruction_set = NULL;
	encoder->instruction_count = 0;

	/* Initialize instruction set */
	HBCISA isa = hbc_isa_getv (bytecode_version);
	encoder->instruction_set = isa.instructions;
	encoder->instruction_count = isa.count;
	if (!encoder->instruction_set) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION,
			"Failed to initialize instruction set");
	}

	return SUCCESS_RESULT ();
}

/* Clean up encoder */
void hbc_encoder_cleanup(HBCEncoder *encoder) {
	if (!encoder) {
		return;
	}

	/* Instruction set is managed globally, don't free it here */
	encoder->instruction_set = NULL;
	encoder->instruction_count = 0;
}

/* Find instruction by mnemonic */
static const Instruction *find_instruction_by_name(const char *mnemonic, const Instruction *instruction_set, u32 instruction_count, u8 *out_opcode) {
	if (!mnemonic || !instruction_set) {
		return NULL;
	}

	for (u32 i = 0; i < instruction_count; i++) {
		if (!instruction_set[i].name) {
			continue;
		}
		if (portable_strcasecmp (mnemonic, instruction_set[i].name) == 0) {
			if (out_opcode) {
				*out_opcode = (u8)i;
			}
			return &instruction_set[i];
		}
	}

	return NULL; /* Unknown */
}

/* Parse instruction line in asm format */
Result hbc_encoder_parse_instruction(HBCEncoder *encoder, const char *asm_line, HBCEncodedInstruction *out_instruction) {
	if (!encoder || !asm_line || !out_instruction) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	/* Initialize output */
	memset (out_instruction, 0, sizeof (HBCEncodedInstruction));

	/* Skip address prefix if present (format: "0xADDR: mnemonic ..." ) */
	const char *line = asm_line;
	if (line[0] == '0' && (line[1] == 'x' || line[1] == 'X')) {
		/* Skip address */
		while (*line && *line != ':') {
			line++;
		}
		if (*line == ':') {
			line++; /* Skip colon */
		}
		/* Skip whitespace */
		while (*line && isspace (*line)) {
			line++;
		}
	}

	/* Extract mnemonic */
	char mnemonic[64] = { 0 };
	size_t mnemonic_len = 0;
	while (*line && !isspace (*line) && mnemonic_len < sizeof (mnemonic) - 1) {
		mnemonic[mnemonic_len++] = *line++;
	}
	mnemonic[mnemonic_len] = '\0';

	if (mnemonic_len == 0) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "No mnemonic found");
	}

	/* Find instruction by mnemonic */
	u8 opcode = 0;
	const Instruction *inst = find_instruction_by_name (mnemonic, encoder->instruction_set, encoder->instruction_count, &opcode);
	if (!inst) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Unknown mnemonic");
	}

	out_instruction->opcode = opcode;
	out_instruction->size = inst->binary_size;

	/* Parse operands based on instruction definition */
	u64 operand_values[6] = { 0 };
	int operand_count = 0;

	/* Skip whitespace after mnemonic */
	while (*line && isspace (*line)) {
		line++;
	}

	/* Parse operands separated by commas */
	while (*line && operand_count < 6) {
		/* Skip whitespace */
		while (*line && isspace (*line)) {
			line++;
		}

		if (*line == '\0' || *line == '\n' || *line == '\r') {
			break;
		}

		/* Find end of operand (comma or end) */
		const char *operand_end = line;
		int paren_depth = 0;
		while (*operand_end && (*operand_end != ',' || paren_depth > 0)) {
			if (*operand_end == '(') {
				paren_depth++;
			} else if (*operand_end == ')') {
				paren_depth--;
			}
			operand_end++;
		}

		/* Extract operand string */
		size_t operand_len = operand_end - line;
		if (operand_len == 0) {
			break;
		}

		char operand_str[64] = { 0 };
		if (operand_len >= sizeof (operand_str)) {
			return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Operand too long");
		}
		memcpy (operand_str, line, operand_len);
		operand_str[operand_len] = '\0';

		/* Trim whitespace */
		char *trim_start = operand_str;
		while (*trim_start && isspace (*trim_start)) {
			trim_start++;
		}
		char *trim_end = trim_start + strlen (trim_start) - 1;
		while (trim_end > trim_start && isspace (*trim_end)) {
			*trim_end-- = '\0';
		}

		/* Parse operand based on expected type */
		if (operand_count < 6 && inst->operands[operand_count].operand_type != OPERAND_TYPE_NONE) {
			OperandType expected_type = inst->operands[operand_count].operand_type;
			char *endptr;
			bool parse_success = false;

			switch (expected_type) {
			case OPERAND_TYPE_REG8:
			case OPERAND_TYPE_REG32:
				/* Register: rN or RN */
				if (trim_start[0] == 'r' || trim_start[0] == 'R') {
					operand_values[operand_count] = (u32)strtoul (trim_start + 1, &endptr, 10);
					if (*endptr == '\0') {
						parse_success = true;
						/* Validate register range */
						if (expected_type == OPERAND_TYPE_REG8 && operand_values[operand_count] > 255) {
							return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Register number out of range for REG8");
						}
					}
				} else {
					/* Allow bare numbers for registers too */
					operand_values[operand_count] = (u32)strtoul (trim_start, &endptr, 10);
					if (*endptr == '\0') {
						parse_success = true;
						/* Validate register range */
						if (expected_type == OPERAND_TYPE_REG8 && operand_values[operand_count] > 255) {
							return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Register number out of range for REG8");
						}
					}
				}
				break;

			case OPERAND_TYPE_UINT8:
			case OPERAND_TYPE_UINT16:
			case OPERAND_TYPE_UINT32:
			case OPERAND_TYPE_IMM32:
			case OPERAND_TYPE_ADDR8:
			case OPERAND_TYPE_ADDR32:
				/* Immediate or address */
				if (trim_start[0] == '0' && (trim_start[1] == 'x' || trim_start[1] == 'X')) {
					/* Hex */
					operand_values[operand_count] = (u32)strtoul (trim_start, &endptr, 16);
					if (*endptr == '\0') {
						parse_success = true;
					}
				} else {
					/* Decimal */
					operand_values[operand_count] = (u32)strtoul (trim_start, &endptr, 10);
					if (*endptr == '\0') {
						parse_success = true;
					}
				}
				break;

			case OPERAND_TYPE_DOUBLE:
				/* Parse as double literal */
				{
					char *endptr_double;
					double dval = strtod (trim_start, &endptr_double);
					if (*endptr_double == '\0') {
						/* Convert double to IEEE 754 bits */
						u64 bits;
						memcpy (&bits, &dval, sizeof (double));
						operand_values[operand_count] = bits;
						parse_success = true;
					} else if (trim_start[0] == '0' && (trim_start[1] == 'x' || trim_start[1] == 'X')) {
						/* Allow hex for bit patterns */
						operand_values[operand_count] = (u64)strtoull (trim_start, &endptr_double, 16);
						if (*endptr_double == '\0') {
							parse_success = true;
						}
					}
				}
				break;

			default:
				/* Unknown type, try to parse as number */
				if (trim_start[0] == '0' && (trim_start[1] == 'x' || trim_start[1] == 'X')) {
					operand_values[operand_count] = (u32)strtoul (trim_start, &endptr, 16);
					if (*endptr == '\0') {
						parse_success = true;
					}
				} else {
					operand_values[operand_count] = (u32)strtoul (trim_start, &endptr, 10);
					if (*endptr == '\0') {
						parse_success = true;
					}
				}
				break;
			}

			if (!parse_success) {
				return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Invalid operand format");
			}

			operand_count++;
		}

		/* Move to next operand */
		line = operand_end;
		if (*line == ',') {
			line++;
		}
	}

	/* Count expected operands */
	int expected_operand_count = 0;
	for (int i = 0; i < 6; i++) {
		if (inst->operands[i].operand_type == OPERAND_TYPE_NONE) {
			break;
		}
		expected_operand_count++;
	}

	/* Validate operand count */
	if (operand_count != expected_operand_count) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Incorrect number of operands");
	}

	/* Store operand values */
	out_instruction->arg1 = operand_values[0];
	out_instruction->arg2 = operand_values[1];
	out_instruction->arg3 = operand_values[2];
	out_instruction->arg4 = operand_values[3];
	out_instruction->arg5 = operand_values[4];
	out_instruction->arg6 = operand_values[5];

	return SUCCESS_RESULT ();
}

/* Encode instruction to bytecode */
Result hbc_encoder_encode_instruction(HBCEncoder *encoder, const HBCEncodedInstruction *instruction, u8 *out_buffer, size_t buffer_size, size_t *out_bytes_written) {
	if (!encoder || !instruction || !out_buffer || !out_bytes_written) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	if (buffer_size < instruction->size) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer too small");
	}

	/* Find the instruction definition */
	if (instruction->opcode >= encoder->instruction_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Unknown instruction opcode");
	}

	const Instruction *inst = &encoder->instruction_set[instruction->opcode];
	if (!inst->name) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Unknown instruction opcode");
	}

	size_t offset = 0;
	u64 operand_values[6] = {
		instruction->arg1, instruction->arg2, instruction->arg3, instruction->arg4, instruction->arg5, instruction->arg6
	};

	/* Write opcode */
	out_buffer[offset++] = instruction->opcode;

	/* Write operands based on their types */
	for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
		OperandType type = inst->operands[i].operand_type;
		u32 value = operand_values[i];

		switch (type) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_UINT8:
		case OPERAND_TYPE_ADDR8:
			if (offset >= buffer_size) {
				return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
			}
			out_buffer[offset++] = (u8)value;
			break;

		case OPERAND_TYPE_UINT16:
			if (offset + 1 >= buffer_size) {
				return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
			}
			out_buffer[offset++] = (u8) (value & 0xFF);
			out_buffer[offset++] = (u8) ((value >> 8) & 0xFF);
			break;

		case OPERAND_TYPE_REG32:
		case OPERAND_TYPE_UINT32:
		case OPERAND_TYPE_ADDR32:
		case OPERAND_TYPE_IMM32:
			if (offset + 3 >= buffer_size) {
				return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
			}
			out_buffer[offset++] = (u8) (value & 0xFF);
			out_buffer[offset++] = (u8) ((value >> 8) & 0xFF);
			out_buffer[offset++] = (u8) ((value >> 16) & 0xFF);
			out_buffer[offset++] = (u8) ((value >> 24) & 0xFF);
			break;

		case OPERAND_TYPE_DOUBLE:
			/* For doubles, encode as IEEE 754 double (64-bit little-endian) */
			if (offset + 7 >= buffer_size) {
				return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
			}
			/* Value is already the 64-bit IEEE 754 bit pattern */
			u64 double_bits = value;
			for (int j = 0; j < 8; j++) {
				out_buffer[offset++] = (u8) (double_bits & 0xFF);
				double_bits >>= 8;
			}
			break;

		default:
			/* Unknown type - assume 8-bit */
			if (offset >= buffer_size) {
				return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
			}
			out_buffer[offset++] = (u8)value;
			break;
		}
	}

	*out_bytes_written = offset;
	return SUCCESS_RESULT ();
}

/* Encode multiple instructions */
Result hbc_encoder_encode_instructions(HBCEncoder *encoder, const char *asm_text, u8 *out_buffer, size_t buffer_size, size_t *out_bytes_written) {
	if (!encoder || !asm_text || !out_buffer || !out_bytes_written) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	size_t total_written = 0;
	const char *line_start = asm_text;

	while (*line_start) {
		/* Find end of line */
		const char *line_end = line_start;
		while (*line_end && *line_end != '\n' && *line_end != '\r') {
			line_end++;
		}

		/* Extract line */
		size_t line_len = line_end - line_start;
		if (line_len == 0) {
			line_start = line_end;
			if (*line_start) {
				line_start++;
			}
			continue;
		}

		char line[256] = { 0 };
		if (line_len >= sizeof (line)) {
			return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Line too long");
		}
		memcpy (line, line_start, line_len);
		line[line_len] = '\0';
		/* Trim trailing whitespace */
		char *end = line + line_len - 1;
		while (end >= line && isspace (*end)) {
			*end-- = '\0';
		}

		/* Skip empty lines or comments */
		const char *trim = line;
		while (*trim && isspace (*trim)) {
			trim++;
		}
		if (*trim == '\0' || *trim == '#') {
			line_start = line_end;
			if (*line_start) {
				line_start++;
			}
			continue;
		}

		/* Parse and encode instruction */
		HBCEncodedInstruction instruction;
		RETURN_IF_ERROR (hbc_encoder_parse_instruction (encoder, line, &instruction));

		if (total_written + instruction.size > buffer_size) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer too small for all instructions");
		}

		size_t bytes_written;
		RETURN_IF_ERROR (hbc_encoder_encode_instruction (encoder, &instruction, out_buffer + total_written, buffer_size - total_written, &bytes_written));

		total_written += bytes_written;

		/* Move to next line */
		line_start = line_end;
		if (*line_start) {
			line_start++;
		}
	}

	*out_bytes_written = total_written;
	return SUCCESS_RESULT ();
}
