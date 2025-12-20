#include <hbc/disasm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Initialize disassembler */
Result disassembler_init(Disassembler *disassembler, HBCReader *reader, HBCDisassemblyOptions options) {
	if (!disassembler || !reader) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for disassembler_init");
	}

	disassembler->reader = reader;
	disassembler->options = options;
	if (options.asm_syntax) {
		fprintf (stderr, "[disassembler] asm_syntax=1\n");
	}
	disassembler->current_function_id = 0;

	return string_buffer_init (&disassembler->output, 8192);
}

/* Clean up disassembler */
void disassembler_cleanup(Disassembler *disassembler) {
	if (disassembler) {
		string_buffer_free (&disassembler->output);
	}
}

/* Print function header */
Result print_function_header(Disassembler *disassembler, FunctionHeader *function_header, u32 function_id) {
	if (!disassembler || !function_header) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for print_function_header");
	}

	HBCReader *reader = disassembler->reader;
	StringBuffer *output = &disassembler->output;
	bool verbose = disassembler->options.verbose;

	/* Get function name with validation */
	const char *function_name = "unknown";
	if (function_header->functionName < reader->header.stringCount &&
		reader->strings && reader->strings[function_header->functionName]) {
		function_name = reader->strings[function_header->functionName];
	} else if (function_header->functionName >= reader->header.stringCount) {
		fprintf (stderr, "Warning: Function #%u has invalid name index %u (max %u)\n", function_id, function_header->functionName, reader->header.stringCount);
	}

	if (verbose) {
		/* Basic function information */
		RETURN_IF_ERROR (string_buffer_append (output, "=> [Function #"));
		RETURN_IF_ERROR (string_buffer_append_int (output, function_id));
		RETURN_IF_ERROR (string_buffer_append (output, " \""));
		RETURN_IF_ERROR (string_buffer_append (output, function_name));
		RETURN_IF_ERROR (string_buffer_append (output, "\" of "));
		RETURN_IF_ERROR (string_buffer_append_int (output, function_header->bytecodeSizeInBytes));
		RETURN_IF_ERROR (string_buffer_append (output, " bytes]: "));
		RETURN_IF_ERROR (string_buffer_append_int (output, function_header->paramCount));
		RETURN_IF_ERROR (string_buffer_append (output, " params, frame size="));
		RETURN_IF_ERROR (string_buffer_append_int (output, function_header->frameSize));
		RETURN_IF_ERROR (string_buffer_append (output, ", env size="));
		RETURN_IF_ERROR (string_buffer_append_int (output, function_header->environmentSize));
	}

	/* Verbose information */
	if (verbose) {
		RETURN_IF_ERROR (string_buffer_append (output, ", read index sz="));
		RETURN_IF_ERROR (string_buffer_append_int (output, function_header->highestReadCacheIndex));
		RETURN_IF_ERROR (string_buffer_append (output, ", write index sz="));
		RETURN_IF_ERROR (string_buffer_append_int (output, function_header->highestWriteCacheIndex));
		RETURN_IF_ERROR (string_buffer_append (output, ", strict="));
		RETURN_IF_ERROR (string_buffer_append (output, function_header->strictMode? "true": "false"));
		RETURN_IF_ERROR (string_buffer_append (output, ", exc handler="));
		RETURN_IF_ERROR (string_buffer_append (output, function_header->hasExceptionHandler? "true": "false"));
		RETURN_IF_ERROR (string_buffer_append (output, ", debug info="));
		RETURN_IF_ERROR (string_buffer_append (output, function_header->hasDebugInfo? "true": "false"));
	}

	/* Offset information */
	RETURN_IF_ERROR (string_buffer_append (output, " @ offset 0x"));
	char hex_offset[16];
	snprintf (hex_offset, sizeof (hex_offset), "%08x", function_header->offset);
	RETURN_IF_ERROR (string_buffer_append (output, hex_offset));

	/* Exception handler information */
	if (function_header->hasExceptionHandler && disassembler->options.show_debug_info) {
		RETURN_IF_ERROR (string_buffer_append (output, "\n  [Exception handlers:"));

		ExceptionHandlerList *exc_handlers = &reader->function_id_to_exc_handlers[function_id];
		for (u32 i = 0; i < exc_handlers->count; i++) {
			ExceptionHandlerInfo *handler = &exc_handlers->handlers[i];

			char hex_start[16], hex_end[16], hex_target[16];
			snprintf (hex_start, sizeof (hex_start), "%x", handler->start);
			snprintf (hex_end, sizeof (hex_end), "%x", handler->end);
			snprintf (hex_target, sizeof (hex_target), "%x", handler->target);

			RETURN_IF_ERROR (string_buffer_append (output, " [start=0x"));
			RETURN_IF_ERROR (string_buffer_append (output, hex_start));
			RETURN_IF_ERROR (string_buffer_append (output, ", end=0x"));
			RETURN_IF_ERROR (string_buffer_append (output, hex_end));
			RETURN_IF_ERROR (string_buffer_append (output, ", target=0x"));
			RETURN_IF_ERROR (string_buffer_append (output, hex_target));
			RETURN_IF_ERROR (string_buffer_append (output, "]"));
		}

		RETURN_IF_ERROR (string_buffer_append (output, " ]"));
	}

	/* Debug information */
	if (function_header->hasDebugInfo && disassembler->options.show_debug_info) {
		DebugOffsets *debug_offsets = &reader->function_id_to_debug_offsets[function_id];

		RETURN_IF_ERROR (string_buffer_append (output, "\n  [Debug offsets: "));
		RETURN_IF_ERROR (string_buffer_append (output, "source_locs=0x"));

		char hex_source_loc[16], hex_scope_desc[16];
		snprintf (hex_source_loc, sizeof (hex_source_loc), "%x", debug_offsets->source_locations);
		snprintf (hex_scope_desc, sizeof (hex_scope_desc), "%x", debug_offsets->scope_desc_data);

		RETURN_IF_ERROR (string_buffer_append (output, hex_source_loc));
		RETURN_IF_ERROR (string_buffer_append (output, ", scope_desc_data=0x"));
		RETURN_IF_ERROR (string_buffer_append (output, hex_scope_desc));
		RETURN_IF_ERROR (string_buffer_append (output, "]"));
	}

	/* End the function header */
	RETURN_IF_ERROR (string_buffer_append (output, "\n\n"));

	return SUCCESS_RESULT ();
}

/* Print a single instruction */
/* Helpers for asm-syntax formatting */
static void to_snake_lower(const char *in, char *out, size_t outsz) {
	size_t j = 0;
	for (size_t i = 0; in && in[i] && j + 1 < outsz; i++) {
		char c = in[i];
		if (c >= 'A' && c <= 'Z') {
			if (i != 0 && out[j - 1] != '_') {
				if (j + 1 < outsz) {
					out[j++] = '_';
				}
			}
			c = (char) (c - 'A' + 'a');
		}
		out[j++] = c;
	}
	if (outsz > 0) {
		out[j < outsz? j: outsz - 1] = '\0';
	}
}

static Result format_operand_asm(Disassembler *d, ParsedInstruction *ins, int idx, StringBuffer *out) {
	OperandType t = ins->inst->operands[idx].operand_type;
	OperandMeaning m = ins->inst->operands[idx].operand_meaning;
	u32 v = 0;
	switch (idx) {
	case 0: v = ins->arg1; break;
	case 1: v = ins->arg2; break;
	case 2: v = ins->arg3; break;
	case 3: v = ins->arg4; break;
	case 4: v = ins->arg5; break;
	case 5: v = ins->arg6; break;
	}

	HBCReader *r = d->reader;
	FunctionHeader *fh = &r->function_headers[d->current_function_id];

	char buf[64];
	if (t == OPERAND_TYPE_REG8 || t == OPERAND_TYPE_REG32) {
		snprintf (buf, sizeof (buf), "r%u", v);
		return string_buffer_append (out, buf);
	}

	if (m == OPERAND_MEANING_FUNCTION_ID) {
		if (v < r->header.functionCount) {
			u32 off = r->function_headers[v].offset;
			snprintf (buf, sizeof (buf), "0x%x", off);
			return string_buffer_append (out, buf);
		}
		snprintf (buf, sizeof (buf), "%u", v);
		return string_buffer_append (out, buf);
	}

	if (m == OPERAND_MEANING_STRING_ID) {
		u32 off = 0;
		if (v < r->header.stringCount && r->small_string_table) {
			if (r->small_string_table[v].length == 0xFF && r->overflow_string_table) {
				u32 oi = r->small_string_table[v].offset;
				off = r->overflow_string_table[oi].offset;
			} else {
				off = r->small_string_table[v].offset;
			}
		}
		u32 abs = r->string_storage_file_offset + off;
		snprintf (buf, sizeof (buf), "0x%x", abs);
		return string_buffer_append (out, buf);
	}

	if (t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32) {
		/* Convert relative address to file-absolute */
		u32 file_abs = fh->offset + ins->original_pos + v;
		snprintf (buf, sizeof (buf), "0x%x", file_abs);
		return string_buffer_append (out, buf);
	}

	if (t == OPERAND_TYPE_DOUBLE) {
		double double_val = ins->double_arg2;

		snprintf (buf, sizeof (buf), "%.6f", double_val);
		return string_buffer_append (out, buf);
	}

	/* Default: decimal immediate */
	snprintf (buf, sizeof (buf), "%u", v);
	return string_buffer_append (out, buf);
}

static Result print_instruction_asm(Disassembler *disassembler, ParsedInstruction *instruction) {
	StringBuffer *out = &disassembler->output;
	/* Prefix with absolute file address of the instruction */
	HBCReader *r = disassembler->reader;
	FunctionHeader *fh = &r->function_headers[disassembler->current_function_id];
	char abuf[32];
	snprintf (abuf, sizeof (abuf), "0x%08x: ", fh->offset + instruction->original_pos);
	RETURN_IF_ERROR (string_buffer_append (out, abuf));
	/* mnemonic */
	char mnem[64];
	to_snake_lower (instruction->inst->name, mnem, sizeof (mnem));
	RETURN_IF_ERROR (string_buffer_append (out, mnem));

	bool first = true;
	for (int i = 0; i < 6; i++) {
		if (instruction->inst->operands[i].operand_type == OPERAND_TYPE_NONE) {
			continue;
		}
		RETURN_IF_ERROR (string_buffer_append (out, first? " ": ", "));
		first = false;
		RETURN_IF_ERROR (format_operand_asm (disassembler, instruction, i, out));
	}
	RETURN_IF_ERROR (string_buffer_append (out, "\n"));
	return SUCCESS_RESULT ();
}

Result print_instruction(Disassembler *disassembler, ParsedInstruction *instruction) {
	if (!disassembler || !instruction || !instruction->inst) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for print_instruction");
	}

	/* Force asm path to ensure consistent output as requested */
	if (disassembler->options.asm_syntax) {
		return print_instruction_asm (disassembler, instruction);
	}
	StringBuffer *output = &disassembler->output;
	HBCReader *reader = disassembler->reader;
	FunctionHeader *fh = &reader->function_headers[disassembler->current_function_id];

	/* Print instruction address */
	char hex_addr[16];
	snprintf (hex_addr, sizeof (hex_addr), "%08x", fh->offset + instruction->original_pos);
	RETURN_IF_ERROR (string_buffer_append (output, "==> "));
	RETURN_IF_ERROR (string_buffer_append (output, hex_addr));
	RETURN_IF_ERROR (string_buffer_append (output, ">: <"));
	RETURN_IF_ERROR (string_buffer_append (output, instruction->inst->name));
	RETURN_IF_ERROR (string_buffer_append (output, ">: <"));

	/* Print operands */
	bool first = true;
	for (int i = 0; i < 6; i++) {
		OperandType operand_type = instruction->inst->operands[i].operand_type;
		if (operand_type == OPERAND_TYPE_NONE) {
			continue;
		}

		if (!first) {
			RETURN_IF_ERROR (string_buffer_append (output, ", "));
		}
		first = false;

		/* Get operand name */
		const char *operand_name = "Unknown";
		switch (instruction->inst->operands[i].operand_meaning) {
		case OPERAND_MEANING_NONE:
			switch (operand_type) {
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
				break;
			default:
				operand_name = "Unknown";
				break;
			}
			break;
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
		}

		/* Print operand name and value */
		RETURN_IF_ERROR (string_buffer_append (output, operand_name));
		RETURN_IF_ERROR (string_buffer_append (output, ": "));

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

		/* Print operand value */
		if (instruction->inst->operands[i].operand_type != OPERAND_TYPE_DOUBLE) {
			RETURN_IF_ERROR (string_buffer_append_int (output, value));
		} else {
			double double_val = instruction->double_arg2;

			char value_str[32];
			snprintf (value_str, sizeof (value_str), "%.6f", double_val);
			RETURN_IF_ERROR (string_buffer_append (output, value_str));
		}
	}

	RETURN_IF_ERROR (string_buffer_append (output, ">"));

	/* Add comments for special operands */

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
			if (value < reader->header.stringCount &&
				reader->strings && reader->strings[value]) {
				RETURN_IF_ERROR (string_buffer_append (output, "  # String: \""));
				RETURN_IF_ERROR (string_buffer_append (output, reader->strings[value]));
				RETURN_IF_ERROR (string_buffer_append (output, "\" ("));
				if (value < reader->header.stringCount && reader->string_kinds) {
					RETURN_IF_ERROR (string_buffer_append (output, string_kind_to_string (reader->string_kinds[value])));
				} else {
					RETURN_IF_ERROR (string_buffer_append (output, "Unknown"));
				}
				RETURN_IF_ERROR (string_buffer_append (output, ")"));
			}
			break;

		case OPERAND_MEANING_BIGINT_ID:
			if (value < reader->bigint_count) {
				RETURN_IF_ERROR (string_buffer_append (output, "  # BigInt: "));
				RETURN_IF_ERROR (string_buffer_append_int (output, reader->bigint_values[value]));
			}
			break;

		case OPERAND_MEANING_FUNCTION_ID:
			if (value < reader->header.functionCount && reader->function_headers) {
				FunctionHeader *func = &reader->function_headers[value];
				const char *func_name = "unknown";
				if (func->functionName < reader->header.stringCount &&
					reader->strings && reader->strings[func->functionName]) {
					func_name = reader->strings[func->functionName];
				}

				RETURN_IF_ERROR (string_buffer_append (output, "  # Function: [#"));
				RETURN_IF_ERROR (string_buffer_append_int (output, value));
				RETURN_IF_ERROR (string_buffer_append (output, " "));
				RETURN_IF_ERROR (string_buffer_append (output, func_name));
				RETURN_IF_ERROR (string_buffer_append (output, " of "));
				RETURN_IF_ERROR (string_buffer_append_int (output, func->bytecodeSizeInBytes));
				RETURN_IF_ERROR (string_buffer_append (output, " bytes]: "));
				RETURN_IF_ERROR (string_buffer_append_int (output, func->paramCount));
				RETURN_IF_ERROR (string_buffer_append (output, " params @ offset 0x"));

				char hex_offset[16];
				snprintf (hex_offset, sizeof (hex_offset), "%08x", func->offset);
				RETURN_IF_ERROR (string_buffer_append (output, hex_offset));
			}
			break;

		case OPERAND_MEANING_BUILTIN_ID:
			/* We'll implement this later when we have builtin function tables */
			break;

		default:
			break;
		}
	}

	/* Add address comments for address operands */
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

		RETURN_IF_ERROR (string_buffer_append (output, "  # Address: "));

		char hex_addr[16];
		snprintf (hex_addr, sizeof (hex_addr), "%08x", fh->offset + instruction->original_pos + value);
		RETURN_IF_ERROR (string_buffer_append (output, hex_addr));
	}

	/* Add jump table comment for switch instructions */
	if (strcmp (instruction->inst->name, "SwitchImm") == 0) {
		if (instruction->switch_jump_table && instruction->switch_jump_table_size > 0) {
			RETURN_IF_ERROR (string_buffer_append (output, "  # Jump table: ["));

			for (u32 i = 0; i < instruction->switch_jump_table_size; i++) {
				if (i > 0) {
					RETURN_IF_ERROR (string_buffer_append (output, ", "));
				}

				char hex_addr[16];
				snprintf (hex_addr, sizeof (hex_addr), "%08x", fh->offset + instruction->switch_jump_table[i]);
				RETURN_IF_ERROR (string_buffer_append (output, hex_addr));
			}

			RETURN_IF_ERROR (string_buffer_append (output, "]"));
		}
	}

	/* End the instruction */
	RETURN_IF_ERROR (string_buffer_append (output, "\n"));

	return SUCCESS_RESULT ();
}

/* Disassemble a single function */
Result disassemble_function(Disassembler *disassembler, u32 function_id) {
	if (!disassembler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Disassembler is NULL");
	}

	HBCReader *reader = disassembler->reader;

	if (function_id >= reader->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid function ID");
	}

	/* Print function header */
	FunctionHeader *function_header = &reader->function_headers[function_id];
	disassembler->current_function_id = function_id;
	RETURN_IF_ERROR (print_function_header (disassembler, function_header, function_id));

	/* Print bytecode listing header */
	if (disassembler->options.asm_syntax) {
		RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "Bytecode listing (asm):\n\n"));
	} else {
		RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "Bytecode listing:\n\n"));
	}

	/* Debug mode - always show function offset info */
	const char *debug_func_name = "unknown";
	if (function_header->functionName < reader->header.stringCount &&
		reader->strings && reader->strings[function_header->functionName]) {
		debug_func_name = reader->strings[function_header->functionName];
	}

	fprintf (stderr, "Function #%u: name=%s, offset=0x%08x, size=%u\n", function_id, debug_func_name, function_header->offset, function_header->bytecodeSizeInBytes);

	/* Only try to fetch bytecode if we don't have it yet but have valid size & offset */
	if (function_header->bytecodeSizeInBytes > 0 && !function_header->bytecode) {
		/* Skip functions with suspicious sizes */
		if (function_header->bytecodeSizeInBytes > 1024 * 1024) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output,
				"[Skipping function with unreasonably large bytecode size]\n"));
			return SUCCESS_RESULT ();
		}

		/* Skip functions with offset 0 (likely invalid) */
		if (function_header->offset == 0) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output,
				"[No bytecode available for this function (invalid offset)]\n"));
			return SUCCESS_RESULT ();
		}

		/* Verify offset is within file bounds */
		if (function_header->offset >= reader->file_buffer.size) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output,
				"[Bytecode offset beyond file size]\n"));
			return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Bytecode offset beyond file size");
		}

		/* Verify we can read the full bytecode from the file */
		if (function_header->offset + function_header->bytecodeSizeInBytes > reader->file_buffer.size) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output,
				"[Bytecode extends beyond file size, truncating]\n"));
			function_header->bytecodeSizeInBytes = reader->file_buffer.size - function_header->offset;
		}

		/* Allocate bytecode buffer */
		function_header->bytecode = (u8 *)malloc (function_header->bytecodeSizeInBytes);
		if (!function_header->bytecode) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "[Memory allocation failed for bytecode]\n"));
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate bytecode buffer");
		}

		/* Save current position */
		size_t saved_pos = reader->file_buffer.position;

		/* Seek to bytecode offset */
		Result seek_result = buffer_reader_seek (&reader->file_buffer, function_header->offset);
		if (seek_result.code != RESULT_SUCCESS) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "[Failed to seek to bytecode location]\n"));
			free (function_header->bytecode);
			function_header->bytecode = NULL;
			return seek_result;
		}

		/* Read bytecode data */
		Result read_result = buffer_reader_read_bytes (&reader->file_buffer,
			function_header->bytecode,
			function_header->bytecodeSizeInBytes);

		/* Restore original position */
		buffer_reader_seek (&reader->file_buffer, saved_pos);

		if (read_result.code != RESULT_SUCCESS) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "[Failed to read bytecode data]\n"));
			free (function_header->bytecode);
			function_header->bytecode = NULL;
			return read_result;
		}

		/* Verify the first byte looks like a valid opcode */
		if (function_header->bytecodeSizeInBytes > 0) {
			u8 first_opcode = function_header->bytecode[0];
			if (first_opcode == 0 || first_opcode > 0xA2) { // Using known opcode range
				RETURN_IF_ERROR (string_buffer_append (&disassembler->output,
					"[Warning: First byte doesn't look like a valid opcode]\n"));
			}
		}
	}

	/* Parse the bytecode */
	ParsedInstructionList instructions;
	HBCISA isa = hbc_isa_getv (reader->header.version);
	Result result = parse_function_bytecode (reader, function_id, &instructions, isa);

	if (result.code != RESULT_SUCCESS) {
		/* Handle parsing error - Print more debug info */
		char debug_info[512];
		snprintf (debug_info, sizeof (debug_info), "[Error parsing bytecode for function #%u: %s - Offset: %u, Size: %u]\n", function_id, result.error_message[0] != '\0'? result.error_message: "Unknown error", function_header->offset, function_header->bytecodeSizeInBytes);

		RETURN_IF_ERROR (string_buffer_append (&disassembler->output, debug_info));

		/* Skip this function but continue with others */
		return SUCCESS_RESULT ();
	} else {
		/* Print raw bytecode if requested */
		if (disassembler->options.show_bytecode) {
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "Raw bytecode: "));
			for (u32 i = 0; i < function_header->bytecodeSizeInBytes; i++) {
				char hex[8];
				snprintf (hex, sizeof (hex), "%02x ", function_header->bytecode[i]);
				RETURN_IF_ERROR (string_buffer_append (&disassembler->output, hex));

				/* Line break every 16 bytes */
				if ((i + 1) % 16 == 0 && i + 1 < function_header->bytecodeSizeInBytes) {
					RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "\n               "));
				}
			}
			RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "\n\n"));
		}

		/* Print instructions */
		for (u32 i = 0; i < instructions.count; i++) {
			ParsedInstruction *instruction = &instructions.instructions[i];
			if (disassembler->options.asm_syntax) {
				RETURN_IF_ERROR (print_instruction_asm (disassembler, instruction));
			} else {
				RETURN_IF_ERROR (print_instruction (disassembler, instruction));
			}
		}

		/* Free instruction list */
		parsed_instruction_list_free (&instructions);
	}

	/* End the function disassembly */
	RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "\n\n"));
	RETURN_IF_ERROR (string_buffer_append (&disassembler->output, "===============\n\n"));

	return SUCCESS_RESULT ();
}

/* Disassemble all functions */
Result disassemble_all_functions(Disassembler *disassembler) {
	if (!disassembler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Disassembler is NULL");
	}

	HBCReader *reader = disassembler->reader;

	/* Try to disassemble global function (index 0) first, since Python does this */
	if (reader->header.functionCount > 0) {
		Result result = disassemble_function (disassembler, 0);
		if (result.code != RESULT_SUCCESS) {
			fprintf (stderr, "Warning: Failed to disassemble global function: %s\n", result.error_message[0] != '\0'? result.error_message: "Unknown error");
		}
	}

	/* Disassemble each remaining function, ignoring errors */
	for (u32 i = 1; i < reader->header.functionCount; i++) {
		Result result = disassemble_function (disassembler, i);
		if (result.code != RESULT_SUCCESS) {
			/* Just log and continue with next function */
			fprintf (stderr, "Warning: Failed to disassemble function #%u: %s\n", i, result.error_message[0] != '\0'? result.error_message: "Unknown error");
		}
	}

	return SUCCESS_RESULT ();
}

/* Output disassembly to file or stdout */
Result output_disassembly(Disassembler *disassembler, const char *output_file) {
	if (!disassembler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Disassembler is NULL");
	}

	FILE *out = stdout;

	/* Open output file if specified */
	if (output_file) {
		out = fopen (output_file, "w");
		if (!out) {
			return ERROR_RESULT (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file");
		}
	}

	/* Write the output */
	fputs (disassembler->output.data, out);

	/* Close the file if we opened it */
	if (output_file) {
		fclose (out);
		printf ("\n[+] Disassembly output wrote to \"%s\"\n\n", output_file);
	}

	return SUCCESS_RESULT ();
}

/* Disassemble a file */
Result disassemble_file(const char *input_file, const char *output_file, HBCDisassemblyOptions options) {
	if (!input_file) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Input file is NULL");
	}

	/* Initialize HBC reader */
	HBCReader reader;
	Result result = hbc_reader_init (&reader);
	if (result.code != RESULT_SUCCESS) {
		return result;
	}

	/* Read the whole file */
	result = hbc_reader_read_whole_file (&reader, input_file);
	if (result.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&reader);
		return result;
	}

	/* Initialize disassembler */
	Disassembler disassembler;
	result = disassembler_init (&disassembler, &reader, options);
	if (result.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&reader);
		return result;
	}

	/* Disassemble all functions */
	result = disassemble_all_functions (&disassembler);
	if (result.code != RESULT_SUCCESS) {
		disassembler_cleanup (&disassembler);
		hbc_reader_cleanup (&reader);
		return result;
	}

	/* Output the disassembly */
	result = output_disassembly (&disassembler, output_file);

	/* Clean up */
	disassembler_cleanup (&disassembler);
	hbc_reader_cleanup (&reader);

	return result;
}

/* Disassemble a buffer */
Result disassemble_buffer(const u8 *buffer, size_t size, const char *output_file, HBCDisassemblyOptions options) {
	if (!buffer || size == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid buffer");
	}

	/* Initialize HBC reader */
	HBCReader reader;
	Result result = hbc_reader_init (&reader);
	if (result.code != RESULT_SUCCESS) {
		return result;
	}

	/* Initialize buffer reader */
	result = buffer_reader_init_from_memory (&reader.file_buffer, buffer, size);
	if (result.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&reader);
		return result;
	}

	/* Read header */
	result = hbc_reader_read_header (&reader);
	if (result.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&reader);
		return result;
	}

	/* Continue parsing the file */
	/*(This is a simplified version - we should call all the individual read_ functions) */

	/* Initialize disassembler */
	Disassembler disassembler;
	result = disassembler_init (&disassembler, &reader, options);
	if (result.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&reader);
		return result;
	}

	/* Disassemble all functions */
	result = disassemble_all_functions (&disassembler);
	if (result.code != RESULT_SUCCESS) {
		disassembler_cleanup (&disassembler);
		hbc_reader_cleanup (&reader);
		return result;
	}

	/* Output the disassembly */
	result = output_disassembly (&disassembler, output_file);

	/* Clean up */
	disassembler_cleanup (&disassembler);
	hbc_reader_cleanup (&reader);

	return result;
}
