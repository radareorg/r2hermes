#include "../../include/parsers/hbc_bytecode_parser.h"
#include "../../include/opcodes/hermes_opcodes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global instruction set definitions for different bytecode versions */
static Instruction *g_instruction_set_v96 = NULL;
static u32 g_instruction_set_v96_count = 0;

/* Initialize parsed instruction list */
Result parsed_instruction_list_init(ParsedInstructionList *list, u32 initial_capacity) {
	if (!list) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "List is NULL");
	}

	list->instructions = (ParsedInstruction *)malloc (initial_capacity * sizeof (ParsedInstruction));
	if (!list->instructions) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate instruction list");
	}

	list->count = 0;
	list->capacity = initial_capacity;

	return SUCCESS_RESULT ();
}

/* Add instruction to parsed instruction list */
Result parsed_instruction_list_add(ParsedInstructionList *list, ParsedInstruction *instruction) {
	if (!list || !instruction) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for parsed_instruction_list_add");
	}

	/* Resize list if needed */
	if (list->count >= list->capacity) {
		u32 new_capacity = list->capacity * 2;
		ParsedInstruction *new_instructions = (ParsedInstruction *)realloc (
			list->instructions, new_capacity * sizeof (ParsedInstruction));

		if (!new_instructions) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to resize instruction list");
		}

		list->instructions = new_instructions;
		list->capacity = new_capacity;
	}

	/* Copy instruction to list */
	memcpy (&list->instructions[list->count], instruction, sizeof (ParsedInstruction));
	list->count++;

	return SUCCESS_RESULT ();
}

/* Free parsed instruction list */
void parsed_instruction_list_free(ParsedInstructionList *list) {
	if (!list) {
		return;
	}

	if (list->instructions) {
		/* Free switch jump tables for any instructions that have them */
		for (u32 i = 0; i < list->count; i++) {
			if (list->instructions[i].switch_jump_table) {
				free (list->instructions[i].switch_jump_table);
			}
		}

		free (list->instructions);
	}

	list->instructions = NULL;
	list->count = 0;
	list->capacity = 0;
}

/* Initialize the instruction set for the given bytecode version */
static Result initialize_instruction_set(u32 bytecode_version) {
	/* Check bytecode version compatibility */
	if (bytecode_version < 72) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_FORMAT,
			"Bytecode version too old (< 72) - not supported");
	}

	if (bytecode_version > 96) {
		fprintf (stderr, "Warning: Bytecode version %u is newer than supported version (96).\n",
			bytecode_version);
		fprintf (stderr, "This may cause parsing errors. Proceed with caution.\n");
	}

	/* Initialize the instruction set for versions 92-96 */
	/* Based on Python implementation, version 94 uses the same opcodes as version 92 */
	if (!g_instruction_set_v96) {
		g_instruction_set_v96 = get_instruction_set_v96 (&g_instruction_set_v96_count);
		if (!g_instruction_set_v96) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to initialize instruction set");
		}
	}

	return SUCCESS_RESULT ();
}

/* Find instruction definition by opcode */
static const Instruction *find_instruction(u8 opcode, u32 bytecode_version) {
	u32 count;
	Instruction *instruction_set = NULL;

	/* Validate bytecode version */
	if (bytecode_version < 72) {
		fprintf (stderr, "Error: Bytecode version %u not supported (minimum supported: 72)\n", bytecode_version);
		return NULL;
	}

	/* Select the appropriate instruction set based on bytecode version */
	if (bytecode_version <= 96) {
		/* Based on Python implementation, version 94 also uses opcodes from version 92 */
		instruction_set = g_instruction_set_v96;
		count = g_instruction_set_v96_count;
		if (!instruction_set) {
			/* Lazy initialize if not done yet */
			instruction_set = get_instruction_set_v96 (&g_instruction_set_v96_count);
			g_instruction_set_v96 = instruction_set;
			count = g_instruction_set_v96_count;
		}

		if (bytecode_version == 94 || bytecode_version == 92) {
			fprintf (stderr, "Info: Using v96 opcodes for bytecode version %u (may require conversion)\n", bytecode_version);
			/* For version 94/92, we may need to convert opcode values... we can extend this in future */
		} else if (bytecode_version != 96 && bytecode_version != 95) {
			fprintf (stderr, "Warning: Using v96 opcodes for bytecode version %u (best match)\n", bytecode_version);
		}
	} else {
		/* For newer versions, use version 96 but warn */
		fprintf (stderr, "Warning: Using v96 opcodes for bytecode version %u\n", bytecode_version);
		instruction_set = g_instruction_set_v96;
		count = g_instruction_set_v96_count;
		if (!instruction_set) {
			instruction_set = get_instruction_set_v96 (&g_instruction_set_v96_count);
			g_instruction_set_v96 = instruction_set;
			count = g_instruction_set_v96_count;
		}
	}

	/* Fallback if count not initialized */
	if (instruction_set && count == 0) {
		count = 256; /* full table */
	}

	/* Direct lookup since instruction_set is indexed by opcode */
	if (opcode < count) {
		return &instruction_set[opcode];
	}

	fprintf (stderr, "Error: Unknown opcode 0x%02x for bytecode version %u (count=%u)\n", opcode, bytecode_version, count);
	return NULL;
}

/* This function is now deprecated as we're using the new approach directly in parse_function_bytecode */
Result parse_instruction(HBCReader *reader, FunctionHeader *function_header,
	u32 offset, ParsedInstruction *out_instruction) {
	if (!reader || !function_header || !out_instruction) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for parse_instruction");
	}

	/* Check if the offset is within the function's bytecode */
	if (offset >= function_header->bytecodeSizeInBytes) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Instruction offset out of bounds");
	}

	/* Check if bytecode is loaded */
	if (!function_header->bytecode) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Function bytecode is not loaded");
	}

	/* Initialize ALL instruction fields to zero for safety */
	memset (out_instruction, 0, sizeof (ParsedInstruction));
	out_instruction->original_pos = offset;
	out_instruction->function_offset = function_header->offset;
	out_instruction->hbc_reader = reader;
	out_instruction->arg1 = 0;
	out_instruction->arg2 = 0;
	out_instruction->arg3 = 0;
	out_instruction->arg4 = 0;
	out_instruction->arg5 = 0;
	out_instruction->arg6 = 0;
	out_instruction->switch_jump_table = NULL;
	out_instruction->switch_jump_table_size = 0;
	out_instruction->next_pos = offset; /* In case of early return */

	/* Create a buffer reader for the function bytecode */
	BufferReader bytecode_reader;
	Result init_result = buffer_reader_init_from_memory (&bytecode_reader,
		function_header->bytecode,
		function_header->bytecodeSizeInBytes);

	if (init_result.code != RESULT_SUCCESS) {
		return init_result;
	}

	/* Seek to the instruction offset with validation */
	if (offset >= bytecode_reader.size) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED,
			"Instruction offset beyond bytecode buffer size");
	}

	/* Seek to the instruction offset */
	Result seek_result = buffer_reader_seek (&bytecode_reader, offset);
	if (seek_result.code != RESULT_SUCCESS) {
		return seek_result;
	}

	/* Ensure we have at least one byte to read the opcode */
	if (bytecode_reader.position >= bytecode_reader.size) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "End of bytecode reached while parsing instruction");
	}

	/* Read opcode */
	u8 opcode;
	RETURN_IF_ERROR (buffer_reader_read_u8 (&bytecode_reader, &opcode));

	/* Initialize instruction set if needed */
	RETURN_IF_ERROR (initialize_instruction_set (reader->header.version));

	/* Find instruction definition */
	const Instruction *inst = find_instruction (opcode, reader->header.version);
	if (!inst) {
		/* Unknown opcode - fail explicitly instead of creating a placeholder */
		fprintf (stderr, "Error: Unknown opcode 0x%02x encountered at offset 0x%08x\n", opcode, offset);
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Unknown opcode encountered");
	}

	out_instruction->inst = inst;

	/* Parse operands based on instruction type */
	u32 operand_values[6] = { 0 };

	for (int i = 0; i < 6; i++) {
		if (inst->operands[i].operand_type == OPERAND_TYPE_NONE) {
			continue;
		}

		/* Read operand value based on type */
		switch (inst->operands[i].operand_type) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_UINT8:
		case OPERAND_TYPE_ADDR8:
			{
				u8 value;
				RETURN_IF_ERROR (buffer_reader_read_u8 (&bytecode_reader, &value));
				operand_values[i] = value;
				break;
			}

		case OPERAND_TYPE_UINT16:
			{
				u16 value;
				RETURN_IF_ERROR (buffer_reader_read_u16 (&bytecode_reader, &value));
				operand_values[i] = value;
				break;
			}

		case OPERAND_TYPE_REG32:
		case OPERAND_TYPE_UINT32:
		case OPERAND_TYPE_ADDR32:
			{
				u32 value;
				RETURN_IF_ERROR (buffer_reader_read_u32 (&bytecode_reader, &value));
				operand_values[i] = value;
				break;
			}

		default:
			break;
		}
	}

	/* Store operand values in instruction */
	out_instruction->arg1 = operand_values[0];
	out_instruction->arg2 = operand_values[1];
	out_instruction->arg3 = operand_values[2];
	out_instruction->arg4 = operand_values[3];
	out_instruction->arg5 = operand_values[4];
	out_instruction->arg6 = operand_values[5];

	/* Handle special cases for specific instructions */
	if (opcode == OP_SwitchImm) {
		/* SwitchImm has a jump table following the immediate operands */

		/* Match Python implementation's approach for SwitchImm handling */
		/* Check if arg4 and arg5 are both within reasonable ranges */
		if (out_instruction->arg4 > 1000 || out_instruction->arg5 > 1000) {
			fprintf (stderr, "Warning: Suspicious SwitchImm range values at offset 0x%08x: min=%u, max=%u\n",
				offset, out_instruction->arg4, out_instruction->arg5);
		}

		/* Validate jump table range - but be more tolerant like the Python version */
		if (out_instruction->arg4 > out_instruction->arg5) {
			fprintf (stderr, "Warning: Invalid jump table range - min (%u) > max (%u) at offset 0x%08x\n",
				out_instruction->arg4, out_instruction->arg5, offset);
			/* Set a reasonable default instead of failing */
			out_instruction->arg5 = out_instruction->arg4;
		}

		/* Calculate jump table size with safety limits */
		u32 jump_table_size = out_instruction->arg5 - out_instruction->arg4 + 1;

		/* Limit the jump table size to something reasonable */
		if (jump_table_size > 1000) {
			fprintf (stderr, "Warning: Limiting unreasonably large jump table size (%u) to 1000 at offset 0x%08x\n",
				jump_table_size, offset);
			jump_table_size = 1000;
			out_instruction->arg5 = out_instruction->arg4 + 999; /* Adjust max value */
		}

		/* Allocate jump table */
		out_instruction->switch_jump_table = (u32 *)malloc (jump_table_size * sizeof (u32));
		if (!out_instruction->switch_jump_table) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate switch jump table");
		}

		out_instruction->switch_jump_table_size = jump_table_size;

		/* Compute jump table file offset robustly (absolute or relative) */
		u32 base = out_instruction->arg2; /* encoded table pointer */
		u32 jump_table_offset = 0;
		size_t fsz = reader->file_buffer.size;
		bool jt_ok = false;
		/* Prefer absolute if it looks valid */
		if (base < fsz) {
			jump_table_offset = base;
			jt_ok = true;
		} else if ((u64)function_header->offset + (u64)base < (u64)fsz) {
			jump_table_offset = function_header->offset + base;
			jt_ok = true;
		} else if ((u64)function_header->offset + (u64)offset + (u64)base < (u64)fsz) {
			jump_table_offset = function_header->offset + offset + base;
			jt_ok = true;
		}

		/* Verify jump table offset is within file bounds */
		if (!jt_ok || jump_table_offset >= reader->file_buffer.size) {
			fprintf (stderr, "Warning: Jump table offset (0x%08x) is beyond file size\n", jump_table_offset);
			/* Initialize with dummy values instead of failing */
			for (u32 i = 0; i < jump_table_size; i++) {
				out_instruction->switch_jump_table[i] = offset;
			}
		} else {
			/* Save current position */
			size_t current_pos = reader->file_buffer.position;

			/* Try to seek to jump table in the file */
			Result seek_result = buffer_reader_seek (&reader->file_buffer, jump_table_offset);
			if (seek_result.code != RESULT_SUCCESS) {
				fprintf (stderr, "Warning: Failed to seek to jump table at offset 0x%08x\n", jump_table_offset);
				/* Initialize with dummy values */
				for (u32 i = 0; i < jump_table_size; i++) {
					out_instruction->switch_jump_table[i] = offset;
				}
			} else {
				/* Align to 4-byte boundary like Python's align_over_padding */
				size_t remainder = reader->file_buffer.position % 4;
				if (remainder != 0) {
					buffer_reader_seek (&reader->file_buffer,
						reader->file_buffer.position + (4 - remainder));
				}

				/* Read jump table entries with safety checks */
				for (u32 i = 0; i < jump_table_size; i++) {
					u32 jump_offset;
					if (reader->file_buffer.position + sizeof (u32) > reader->file_buffer.size) {
						/* Beyond file bounds, use current offset as fallback */
						fprintf (stderr, "Warning: Jump table entry %u is beyond file bounds\n", i);
						out_instruction->switch_jump_table[i] = offset;
					} else {
						Result read_result = buffer_reader_read_u32 (&reader->file_buffer, &jump_offset);
						if (read_result.code != RESULT_SUCCESS) {
							/* Read failed, use current offset as fallback */
							out_instruction->switch_jump_table[i] = offset;
						} else {
							/* Success - store the jump target like Python */
							out_instruction->switch_jump_table[i] = offset + jump_offset;
						}
					}
				}
			}

			/* Always attempt to restore original position */
			buffer_reader_seek (&reader->file_buffer, current_pos);
		}
	}

	/* Store next position */
	out_instruction->next_pos = bytecode_reader.position;

	return SUCCESS_RESULT ();
}

/* Parse all bytecode instructions in a function */
Result parse_function_bytecode(HBCReader *reader, u32 function_id,
	ParsedInstructionList *out_instructions) {
	if (!reader || !out_instructions) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT,
			"Invalid arguments for parse_function_bytecode");
	}

	/* Check function ID */
	if (function_id >= reader->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid function ID");
	}

	FunctionHeader *function_header = &reader->function_headers[function_id];

	/* Check if bytecode exists and has reasonable size */
	if (!function_header->bytecode) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function bytecode is NULL");
	}

	if (function_header->bytecodeSizeInBytes == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function has zero bytecode size");
	}

	/* Debug info to verify offsets */
	fprintf (stderr, "Function #%u bytecode: offset=0x%08x, size=%u\n",
		function_id, function_header->offset, function_header->bytecodeSizeInBytes);

	/* Initialize instruction list */
	RETURN_IF_ERROR (parsed_instruction_list_init (out_instructions, 32)); /* Start with space for 32 instructions */

	/* Create a fresh bytecode buffer similar to the Python BytesIO approach */
	BufferReader bytecode_buffer;
	Result result = buffer_reader_init_from_memory (&bytecode_buffer,
		function_header->bytecode,
		function_header->bytecodeSizeInBytes);

	if (result.code != RESULT_SUCCESS) {
		parsed_instruction_list_free (out_instructions);
		return result;
	}

	/* Parse instructions in a loop similar to Python's implementation */
	while (bytecode_buffer.position < bytecode_buffer.size) {
		/* Remember the original position */
		size_t original_pos = bytecode_buffer.position;

		/* Make sure we have at least one byte to read */
		if (bytecode_buffer.position >= bytecode_buffer.size) {
			break;
		}

		/* Read opcode */
		u8 opcode;
		result = buffer_reader_read_u8 (&bytecode_buffer, &opcode);
		if (result.code != RESULT_SUCCESS) {
			fprintf (stderr, "Error reading opcode at position %zu: %s\n",
				original_pos, result.error_message);
			parsed_instruction_list_free (out_instructions);
			return result;
		}

		/* Find instruction definition */
		const Instruction *inst = find_instruction (opcode, reader->header.version);
		if (!inst) {
			fprintf (stderr, "Error: Unknown opcode 0x%02x at offset 0x%08x\n", opcode, (u32)original_pos);
			parsed_instruction_list_free (out_instructions);
			return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Unknown opcode");
		}

		/* Create parsed instruction */
		ParsedInstruction instruction;
		memset (&instruction, 0, sizeof (ParsedInstruction));

		instruction.inst = inst;
		instruction.original_pos = original_pos;
		instruction.function_offset = function_header->offset;
		instruction.hbc_reader = reader;

		/* Set the expected next position based on instruction size */
		instruction.next_pos = original_pos + inst->binary_size;

		/* Parse operands from the buffer */
		u32 operand_values[6] = { 0 };
		bool parsing_failed = false;

		for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
			OperandType operand_type = inst->operands[i].operand_type;
			/* Pre-check remaining bytes to avoid tail overreads */
			size_t need = 0;
			switch (operand_type) {
			case OPERAND_TYPE_REG8:
			case OPERAND_TYPE_UINT8:
			case OPERAND_TYPE_ADDR8: need = 1; break;
			case OPERAND_TYPE_UINT16: need = 2; break;
			case OPERAND_TYPE_REG32:
			case OPERAND_TYPE_UINT32:
			case OPERAND_TYPE_IMM32:
			case OPERAND_TYPE_ADDR32: need = 4; break;
			case OPERAND_TYPE_DOUBLE: need = 8; break;
			default: need = 0; break;
			}
			if (need && (bytecode_buffer.position + need > bytecode_buffer.size)) {
				parsing_failed = true;
				break;
			}

			switch (operand_type) {
			case OPERAND_TYPE_REG8:
			case OPERAND_TYPE_UINT8:
			case OPERAND_TYPE_ADDR8:
				{
					u8 value;
					Result read_result = buffer_reader_read_u8 (&bytecode_buffer, &value);
					if (read_result.code != RESULT_SUCCESS) {
						parsing_failed = true;
						break;
					}
					operand_values[i] = value;
					break;
				}

			case OPERAND_TYPE_UINT16:
				{
					u16 value;
					Result read_result = buffer_reader_read_u16 (&bytecode_buffer, &value);
					if (read_result.code != RESULT_SUCCESS) {
						parsing_failed = true;
						break;
					}
					operand_values[i] = value;
					break;
				}

			case OPERAND_TYPE_REG32:
			case OPERAND_TYPE_UINT32:
			case OPERAND_TYPE_IMM32:
			case OPERAND_TYPE_ADDR32:
				{
					u32 value;
					Result read_result = buffer_reader_read_u32 (&bytecode_buffer, &value);
					if (read_result.code != RESULT_SUCCESS) {
						parsing_failed = true;
						break;
					}
					operand_values[i] = value;
					break;
				}
			case OPERAND_TYPE_DOUBLE:
				{
					double value;
					Result read_result = buffer_reader_read_u64 (&bytecode_buffer, (u64 *)&value);
					if (read_result.code != RESULT_SUCCESS) {
						parsing_failed = true;
						break;
					}
					instruction.double_arg2 = value;
					break;
				}

			default:
				break;
			}

			if (parsing_failed) {
				break;
			}
		}

		if (parsing_failed) {
			/* Truncated at tail; end cleanly without error spam */
			break;
		}

		/* Store operand values */
		instruction.arg1 = operand_values[0];
		instruction.arg2 = operand_values[1];
		instruction.arg3 = operand_values[2];
		instruction.arg4 = operand_values[3];
		instruction.arg5 = operand_values[4];
		instruction.arg6 = operand_values[5];

		/* Handle special cases like SwitchImm */
		if (opcode == OP_SwitchImm) {
			/* Process jump table similarly to Python implementation but with stronger guards */
			/* Interpret min/max as signed to avoid unsigned wrap issues */
			int32_t min_s = (int32_t)instruction.arg4;
			int32_t max_s = (int32_t)instruction.arg5;

			/* Heuristic: if values look implausibly large, treat as suspicious */
			bool suspicious_range = (min_s < -100000 || min_s > 100000 || max_s < -100000 || max_s > 100000);
			if (min_s > max_s) {
				fprintf (stderr, "Warning: Invalid jump table range - min (%u) > max (%u) at offset 0x%08x (Function #%u)\n",
					instruction.arg4, instruction.arg5, (u32)original_pos, function_id);
				/* Clamp to a single entry to keep parsing moving */
				max_s = min_s;
			}

			u32 jump_table_size = (u32) ((int64_t)max_s - (int64_t)min_s + 1);
			if (jump_table_size > 1000) {
				fprintf (stderr, "Warning: Limiting large jump table size (%u) to 1000 at offset 0x%08x (Function #%u)\n", jump_table_size, (u32)original_pos, function_id);
				jump_table_size = 1000;
			}

			/* Allocate table even if suspicious; we'll fill defaults if we can't resolve */
			instruction.switch_jump_table = (u32 *)malloc (jump_table_size * sizeof (u32));
			if (!instruction.switch_jump_table) {
				parsed_instruction_list_free (out_instructions);
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate jump table");
			}
			instruction.switch_jump_table_size = jump_table_size;

			/* Resolve jump table base pointer. The Python impl uses func_off + instr_off + arg2 first. */
			u32 base = instruction.arg2;
			size_t fsz = reader->file_buffer.size;
			u32 candidates[3];
			candidates[0] = function_header->offset + (u32)original_pos + base; /* instruction-relative */
			candidates[1] = function_header->offset + base; /* function-relative */
			candidates[2] = base; /* absolute */
			size_t func_start = function_header->offset;
			size_t func_end = func_start + function_header->bytecodeSizeInBytes;

			/* Save file position */
			size_t saved_pos = reader->file_buffer.position;
			bool read_ok = false;

			for (int ci = 0; ci < 3 && !read_ok; ci++) {
				u32 jt_off = candidates[ci];
				if (jt_off >= fsz) {
					continue;
				}

				/* Seek and align to 4 bytes */
				Result seek_result = buffer_reader_seek (&reader->file_buffer, jt_off);
				if (seek_result.code != RESULT_SUCCESS) {
					continue;
				}
				size_t rem = reader->file_buffer.position % 4;
				if (rem != 0) {
					if (reader->file_buffer.position + (4 - rem) > fsz) {
						continue;
					}
					buffer_reader_seek (&reader->file_buffer, reader->file_buffer.position + (4 - rem));
				}

				/* Validate that the whole table fits */
				size_t table_end = reader->file_buffer.position + (size_t)jump_table_size * sizeof (u32);
				if (table_end > fsz) {
					continue;
				}
				/* Also require the table to lie within the function's bytecode region */
				if (! (reader->file_buffer.position >= func_start && table_end <= func_end)) {
					continue;
				}

				/* If the range looked totally implausible, skip trying to read and leave defaults */
				if (suspicious_range) {
					break;
				}

				/* Read entries */
				bool fail = false;
				for (u32 i = 0; i < jump_table_size; i++) {
					u32 rel;
					Result rr = buffer_reader_read_u32 (&reader->file_buffer, &rel);
					if (rr.code != RESULT_SUCCESS) {
						fail = true;
						break;
					}
					instruction.switch_jump_table[i] = (u32)original_pos + rel;
				}
				if (!fail) {
					read_ok = true;
				}
			}

			/* Restore file position */
			buffer_reader_seek (&reader->file_buffer, saved_pos);

			if (!read_ok) {
				/* Fill with safe defaults */
				for (u32 i = 0; i < jump_table_size; i++) {
					instruction.switch_jump_table[i] = (u32)original_pos;
				}
			}
		}

		/* Add instruction to list */
		result = parsed_instruction_list_add (out_instructions, &instruction);
		if (result.code != RESULT_SUCCESS) {
			parsed_instruction_list_free (out_instructions);
			return result;
		}
	}

	return SUCCESS_RESULT ();
}

/* Convert instruction to string */
Result instruction_to_string(ParsedInstruction *instruction, StringBuffer *out_string) {
	if (!instruction || !out_string || !instruction->inst) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT,
			"Invalid arguments for instruction_to_string");
	}

	/* Format offset */
	char offset_str[16];
	snprintf (offset_str, sizeof (offset_str), "%08x", instruction->function_offset + instruction->original_pos);

	/* Add address */
	RETURN_IF_ERROR (string_buffer_append (out_string, offset_str));
	RETURN_IF_ERROR (string_buffer_append (out_string, ": <"));
	RETURN_IF_ERROR (string_buffer_append (out_string, instruction->inst->name));
	RETURN_IF_ERROR (string_buffer_append (out_string, ">: <"));

	/* Get operands */
	bool first = true;
	for (int i = 0; i < 6; i++) {
		if (instruction->inst->operands[i].operand_type == OPERAND_TYPE_NONE) {
			continue;
		}

		if (!first) {
			RETURN_IF_ERROR (string_buffer_append (out_string, ", "));
		}
		first = false;

		/* Get operand value */
		u32 value;
		switch (i) {
		case 0: value = instruction->arg1; break;
		case 1: value = instruction->arg2; break;
		case 2: value = instruction->arg3; break;
		case 3: value = instruction->arg4; break;
		case 4: value = instruction->arg5; break;
		case 5: value = instruction->arg6; break;
		default: value = 0;
		}

		/* Get operand name */
		const char *operand_name;
		if (instruction->inst->operands[i].operand_meaning != OPERAND_MEANING_NONE) {
			switch (instruction->inst->operands[i].operand_meaning) {
			case OPERAND_MEANING_STRING_ID:
				operand_name = "string_id";
				break;
			case OPERAND_MEANING_BIGINT_ID:
				operand_name = "bigint_id";
				break;
			case OPERAND_MEANING_FUNCTION_ID:
				operand_name = "function_id";
				break;
			case OPERAND_MEANING_BUILTIN_ID:
				operand_name = "builtin_id";
				break;
			case OPERAND_MEANING_ARRAY_ID:
				operand_name = "array_id";
				break;
			case OPERAND_MEANING_OBJ_KEY_ID:
				operand_name = "obj_key_id";
				break;
			case OPERAND_MEANING_OBJ_VAL_ID:
				operand_name = "obj_val_id";
				break;
			default:
				operand_name = "unknown";
				break;
			}
		} else {
			switch (instruction->inst->operands[i].operand_type) {
			case OPERAND_TYPE_REG8:
				operand_name = "Reg8";
				break;
			case OPERAND_TYPE_REG32:
				operand_name = "Reg32";
				break;
			case OPERAND_TYPE_UINT8:
				operand_name = "UInt8";
				break;
			case OPERAND_TYPE_UINT16:
				operand_name = "UInt16";
				break;
			case OPERAND_TYPE_UINT32:
				operand_name = "UInt32";
				break;
			case OPERAND_TYPE_ADDR8:
				operand_name = "Addr8";
				break;
			case OPERAND_TYPE_ADDR32:
				operand_name = "Addr32";
				break;
			case OPERAND_TYPE_IMM32:
				operand_name = "Imm32";
				break;
			case OPERAND_TYPE_DOUBLE:
				operand_name = "Double";
				break;
			default:
				operand_name = "Unknown";
				break;
			}
		}

		/* Print operand name and value */
		RETURN_IF_ERROR (string_buffer_append (out_string, operand_name));
		RETURN_IF_ERROR (string_buffer_append (out_string, ": "));

		/* Format value based on operand type */
		char value_str[32];
		snprintf (value_str, sizeof (value_str), "%u", value);
		RETURN_IF_ERROR (string_buffer_append (out_string, value_str));
	}

	/* Close operands bracket */
	RETURN_IF_ERROR (string_buffer_append (out_string, ">"));

	/* Add comments for special operands */
	HBCReader *reader = instruction->hbc_reader;
	if (reader) {
		for (int i = 0; i < 6; i++) {
			OperandMeaning operand_meaning = instruction->inst->operands[i].operand_meaning;
			if (operand_meaning == OPERAND_MEANING_NONE) {
				continue;
			}

			u32 value;
			switch (i) {
			case 0: value = instruction->arg1; break;
			case 1: value = instruction->arg2; break;
			case 2: value = instruction->arg3; break;
			case 3: value = instruction->arg4; break;
			case 4: value = instruction->arg5; break;
			case 5: value = instruction->arg6; break;
			default: value = 0;
			}

			switch (operand_meaning) {
			case OPERAND_MEANING_STRING_ID:
				if (value < reader->header.stringCount) {
					RETURN_IF_ERROR (string_buffer_append (out_string, "  # String: \""));
					RETURN_IF_ERROR (string_buffer_append (out_string, reader->strings[value]));
					RETURN_IF_ERROR (string_buffer_append (out_string, "\" ("));
					RETURN_IF_ERROR (string_buffer_append (out_string, string_kind_to_string (reader->string_kinds[value])));
					RETURN_IF_ERROR (string_buffer_append (out_string, ")"));
				}
				break;

			case OPERAND_MEANING_BIGINT_ID:
				if (value < reader->bigint_count) {
					RETURN_IF_ERROR (string_buffer_append (out_string, "  # BigInt: "));
					char bigint_str[32];
					snprintf (bigint_str, sizeof (bigint_str), "%lld", (long long)reader->bigint_values[value]);
					RETURN_IF_ERROR (string_buffer_append (out_string, bigint_str));
				}
				break;

			case OPERAND_MEANING_FUNCTION_ID:
				if (value < reader->header.functionCount) {
					FunctionHeader *func = &reader->function_headers[value];
					const char *func_name = "unknown";
					if (func->functionName < reader->header.stringCount) {
						func_name = reader->strings[func->functionName];
					}

					char func_info[256];
					snprintf (func_info, sizeof (func_info),
						"  # Function: [#%u %s of %u bytes]: %u params @ offset 0x%08x",
						value, func_name, func->bytecodeSizeInBytes,
						func->paramCount, func->offset);
					RETURN_IF_ERROR (string_buffer_append (out_string, func_info));
				}
				break;

			case OPERAND_MEANING_BUILTIN_ID:
				/* Add support for builtin functions when available */
				RETURN_IF_ERROR (string_buffer_append (out_string, "  # Built-in function: "));
				char builtin_id_str[16];
				snprintf (builtin_id_str, sizeof (builtin_id_str), "#%u", value);
				RETURN_IF_ERROR (string_buffer_append (out_string, builtin_id_str));
				break;

			default:
				break;
			}
		}

		/* Add comments for address operands */
		for (int i = 0; i < 6; i++) {
			OperandType operand_type = instruction->inst->operands[i].operand_type;
			if (operand_type != OPERAND_TYPE_ADDR8 && operand_type != OPERAND_TYPE_ADDR32) {
				continue;
			}

			u32 value;
			switch (i) {
			case 0: value = instruction->arg1; break;
			case 1: value = instruction->arg2; break;
			case 2: value = instruction->arg3; break;
			case 3: value = instruction->arg4; break;
			case 4: value = instruction->arg5; break;
			case 5: value = instruction->arg6; break;
			default: value = 0;
			}

			/* For addresses, calculate absolute target address */
			u32 absolute_address = instruction->function_offset + instruction->original_pos + value;

			char addr_comment[32];
			snprintf (addr_comment, sizeof (addr_comment), "  # Address: %08x", absolute_address);
			RETURN_IF_ERROR (string_buffer_append (out_string, addr_comment));
		}

		/* Add jump table for switch instructions */
		if (strcmp (instruction->inst->name, "SwitchImm") == 0 &&
			instruction->switch_jump_table && instruction->switch_jump_table_size > 0) {

			RETURN_IF_ERROR (string_buffer_append (out_string, "  # Jump table: ["));

			for (u32 i = 0; i < instruction->switch_jump_table_size; i++) {
				if (i > 0) {
					RETURN_IF_ERROR (string_buffer_append (out_string, ", "));
				}

				char table_entry[16];
				snprintf (table_entry, sizeof (table_entry), "%08x", instruction->function_offset + instruction->switch_jump_table[i]);
				RETURN_IF_ERROR (string_buffer_append (out_string, table_entry));
			}

			RETURN_IF_ERROR (string_buffer_append (out_string, "]"));
		}
	}

	return SUCCESS_RESULT ();
}

/* Helper function - check if an opcode is a jump instruction */
bool is_jump_instruction(u8 opcode) {
	switch (opcode) {
	case OP_Jmp: /* 142 */
	case OP_JmpLong: /* 143 */
	case OP_JmpTrue: /* 144 */
	case OP_JmpTrueLong: /* 145 */
	case OP_JmpFalse: /* 146 */
	case OP_JmpFalseLong: /* 147 */
	case OP_JmpUndefined: /* 148 */
	case OP_JmpUndefinedLong: /* 149 */
	case OP_SaveGenerator: /* 150 */
	case OP_SaveGeneratorLong: /* 151 */
	case OP_JLess: /* 152 */
	case OP_JLessLong: /* 153 */
	case OP_JNotLess: /* 154 */
	case OP_JNotLessLong: /* 155 */
	case OP_JLessN: /* 156 */
	case OP_JLessNLong: /* 157 */
	case OP_JNotLessN: /* 158 */
	case OP_JNotLessNLong: /* 159 */
	case OP_JLessEqual: /* 160 */
	case OP_JLessEqualLong: /* 161 */
	case OP_JNotLessEqual: /* 162 */
	case OP_JNotLessEqualLong: /* 163 */
	case OP_JLessEqualN: /* 164 */
	case OP_JLessEqualNLong: /* 165 */
	case OP_JNotLessEqualN: /* 166 */
	case OP_JNotLessEqualNLong: /* 167 */
	case OP_JGreater: /* 168 */
	case OP_JGreaterLong: /* 169 */
	case OP_JNotGreater: /* 170 */
	case OP_JNotGreaterLong: /* 171 */
	case OP_JGreaterN: /* 172 */
	case OP_JGreaterNLong: /* 173 */
	case OP_JNotGreaterN: /* 174 */
	case OP_JNotGreaterNLong: /* 175 */
	case OP_JGreaterEqual: /* 176 */
	case OP_JGreaterEqualLong: /* 177 */
	case OP_JNotGreaterEqual: /* 178 */
	case OP_JNotGreaterEqualLong: /* 179 */
	case OP_JGreaterEqualN: /* 180 */
	case OP_JGreaterEqualNLong: /* 181 */
	case OP_JNotGreaterEqualN: /* 182 */
	case OP_JNotGreaterEqualNLong: /* 183 */
	case OP_JEqual: /* 184 */
	case OP_JEqualLong: /* 185 */
	case OP_JNotEqual: /* 186 */
	case OP_JNotEqualLong: /* 187 */
	case OP_JStrictEqual: /* 188 */
	case OP_JStrictEqualLong: /* 189 */
	case OP_JStrictNotEqual: /* 190 */
	case OP_JStrictNotEqualLong: /* 191 */
		return true;
	default:
		return false;
	}
}

/* Helper function - check if an opcode is a call instruction */
bool is_call_instruction(u8 opcode) {
	switch (opcode) {
	case OP_Call: /* 79 */
	case OP_Construct: /* 80 */
	case OP_Call1: /* 81 */
	case OP_CallDirect: /* 82 */
	case OP_Call2: /* 83 */
	case OP_Call3: /* 84 */
	case OP_Call4: /* 85 */
	case OP_CallLong: /* 86 */
	case OP_ConstructLong: /* 87 */
	case OP_CallDirectLongIndex: /* 88 */
	case OP_CallBuiltin: /* 89 */
	case OP_CallBuiltinLong: /* 90 */
		return true;
	default:
		return false;
	}
}
