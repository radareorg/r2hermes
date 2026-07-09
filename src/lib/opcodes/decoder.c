/* radare2 - BSD - Copyright 2025-2026 - pancake */

#include <hbc/disasm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Initialize disassembler */
Result _hbc_disassembler_init(Disassembler *disassembler, HBCReader *reader, HBCDisOptions options) {
	if (!disassembler || !reader) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for _hbc_disassembler_init");
	}

	disassembler->reader = reader;
	disassembler->options = options;
	if (options.asm_syntax) {
		fprintf (stderr, "[disassembler] asm_syntax=1\n");
	}
	disassembler->current_function_id = 0;

	r_strbuf_init (&disassembler->output);
	return SUCCESS_RESULT ();
}

/* Clean up disassembler */
void _hbc_disassembler_cleanup(Disassembler *disassembler) {
	if (disassembler) {
		r_strbuf_fini (&disassembler->output);
	}
}

/* Print function header */
Result _hbc_print_function_header(Disassembler *disassembler, FunctionHeader *function_header, u32 function_id) {
	if (!disassembler || !function_header) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for _hbc_print_function_header");
	}

	HBCReader *reader = disassembler->reader;
	RStrBuf *output = &disassembler->output;
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
		RETURN_IF_ERROR (r_strbuf_appendf (output,
			"=> [Function #%u \"%s\" of %u bytes]: %u params, frame size=%u, env size=%u",
			function_id,
			function_name,
			function_header->bytecodeSizeInBytes,
			function_header->paramCount,
			function_header->frameSize,
			function_header->environmentSize));
	}

	/* Verbose information */
	if (verbose) {
		RETURN_IF_ERROR (r_strbuf_appendf (output,
			", read index sz=%u, write index sz=%u, strict=%s, exc handler=%s, debug info=%s",
			function_header->highestReadCacheIndex,
			function_header->highestWriteCacheIndex,
			function_header->strictMode? "true": "false",
			function_header->hasExceptionHandler? "true": "false",
			function_header->hasDebugInfo? "true": "false"));
	}

	/* Offset information */
	RETURN_IF_ERROR (r_strbuf_appendf (output, " @ offset 0x%08x", function_header->offset));

	/* Exception handler information */
	if (function_header->hasExceptionHandler && disassembler->options.show_debug_info) {
		RETURN_IF_ERROR (r_strbuf_append (output, "\n  [Exception handlers:"));

		ExceptionHandlerList *exc_handlers = &reader->function_id_to_exc_handlers[function_id];
		for (u32 i = 0; i < exc_handlers->count; i++) {
			ExceptionHandlerInfo *handler = &exc_handlers->handlers[i];

			RETURN_IF_ERROR (r_strbuf_appendf (output,
				" [start=0x%x, end=0x%x, target=0x%x]",
				handler->start,
				handler->end,
				handler->target));
		}

		RETURN_IF_ERROR (r_strbuf_append (output, " ]"));
	}

	/* Debug information */
	if (function_header->hasDebugInfo && disassembler->options.show_debug_info) {
		DebugOffsets *debug_offsets = &reader->function_id_to_debug_offsets[function_id];

		RETURN_IF_ERROR (r_strbuf_appendf (output,
			"\n  [Debug offsets: source_locs=0x%x, scope_desc_data=0x%x]",
			debug_offsets->source_locations,
			debug_offsets->scope_desc_data));
	}

	/* End the function header */
	RETURN_IF_ERROR (r_strbuf_append (output, "\n\n"));

	return SUCCESS_RESULT ();
}

/* Print a single instruction */
/* Helpers for asm-syntax formatting */

static Result format_operand_asm(Disassembler *d, ParsedInstruction *ins, int idx, RStrBuf *out) {
	OperandType t = ins->inst->operands[idx].operand_type;
	OperandMeaning m = ins->inst->operands[idx].operand_meaning;
	u32 v = hbc_operand_value (ins, idx);

	HBCReader *r = d->reader;
	FunctionHeader *fh = &r->function_headers[d->current_function_id];

	if (t == OPERAND_TYPE_REG8 || t == OPERAND_TYPE_REG32) {
		return HBC_TO_RESULT (r_strbuf_appendf (out, "r%u", v));
	}

	if (m == OPERAND_MEANING_FUNCTION_ID) {
		if (v < r->header.functionCount) {
			u32 off = r->function_headers[v].offset;
			return HBC_TO_RESULT (r_strbuf_appendf (out, "0x%x", off));
		}
		return HBC_TO_RESULT (r_strbuf_appendf (out, "%u", v));
	}

	if (m == OPERAND_MEANING_STRING_ID) {
		u32 off = 0;
		if (v < r->header.stringCount && r->small_string_table) {
			if (r->small_string_table[v].length == 0xFF && r->overflow_string_table) {
				u32 oi = r->small_string_table[v].offset;
				/* Bounds check: ensure oi is within overflow_string_table bounds */
				if (oi < r->header.overflowStringCount) {
					off = r->overflow_string_table[oi].offset;
				} else {
					/* Fallback: use original offset if overflow index is invalid */
					off = r->small_string_table[v].offset;
				}
			} else {
				off = r->small_string_table[v].offset;
			}
		}
		u32 abs = r->string_storage_file_offset + off;
		return HBC_TO_RESULT (r_strbuf_appendf (out, "0x%x", abs));
	}

	if (t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32) {
		/* Convert relative address to file-absolute */
		u32 file_abs = fh->offset + ins->original_pos + v;
		return HBC_TO_RESULT (r_strbuf_appendf (out, "0x%x", file_abs));
	}

	if (t == OPERAND_TYPE_DOUBLE) {
		double double_val = ins->double_arg2;

		return HBC_TO_RESULT (r_strbuf_appendf (out, "%.6f", double_val));
	}

	/* Default: decimal immediate */
	return HBC_TO_RESULT (r_strbuf_appendf (out, "%u", v));
}

static Result print_instruction_asm(Disassembler *disassembler, ParsedInstruction *instruction) {
	RStrBuf *out = &disassembler->output;
	/* Prefix with absolute file address of the instruction */
	HBCReader *r = disassembler->reader;
	FunctionHeader *fh = &r->function_headers[disassembler->current_function_id];
	RETURN_IF_ERROR (r_strbuf_appendf (out, "0x%08x: ", fh->offset + instruction->original_pos));
	/* mnemonic — tables are already snake_case */
	RETURN_IF_ERROR (r_strbuf_append (out, instruction->inst->name));

	bool first = true;
	for (int i = 0; i < 6; i++) {
		if (instruction->inst->operands[i].operand_type == OPERAND_TYPE_NONE) {
			continue;
		}
		RETURN_IF_ERROR (r_strbuf_append (out, first? " ": ", "));
		first = false;
		RETURN_IF_ERROR (format_operand_asm (disassembler, instruction, i, out));
	}
	RETURN_IF_ERROR (r_strbuf_append (out, "\n"));
	return SUCCESS_RESULT ();
}

Result _hbc_print_instruction(Disassembler *disassembler, ParsedInstruction *instruction) {
	if (!disassembler || !instruction || !instruction->inst) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for _hbc_print_instruction");
	}

	/* Force asm path to ensure consistent output as requested */
	if (disassembler->options.asm_syntax) {
		return print_instruction_asm (disassembler, instruction);
	}
	RStrBuf *output = &disassembler->output;
	HBCReader *reader = disassembler->reader;
	FunctionHeader *fh = &reader->function_headers[disassembler->current_function_id];

	/* Print instruction address */
	RETURN_IF_ERROR (r_strbuf_appendf (output, "==> %08x>: <", fh->offset + instruction->original_pos));
	RETURN_IF_ERROR (r_strbuf_append (output, instruction->inst->name));
	RETURN_IF_ERROR (r_strbuf_append (output, ">: <"));

	/* Print operands */
	bool first = true;
	for (int i = 0; i < 6; i++) {
		OperandType operand_type = instruction->inst->operands[i].operand_type;
		if (operand_type == OPERAND_TYPE_NONE) {
			continue;
		}

		if (!first) {
			RETURN_IF_ERROR (r_strbuf_append (output, ", "));
		}
		first = false;

		/* Print operand name and value */
		const char *operand_name = hbc_operand_name (&instruction->inst->operands[i]);
		RETURN_IF_ERROR (r_strbuf_append (output, operand_name));
		RETURN_IF_ERROR (r_strbuf_append (output, ": "));

		/* Get operand value */
		u32 value = hbc_operand_value (instruction, i);

		/* Print operand value */
		if (instruction->inst->operands[i].operand_type != OPERAND_TYPE_DOUBLE) {
			RETURN_IF_ERROR (r_strbuf_appendf (output, "%u", value));
		} else {
			double double_val = instruction->double_arg2;

			RETURN_IF_ERROR (r_strbuf_appendf (output, "%.6f", double_val));
		}
	}

	RETURN_IF_ERROR (r_strbuf_append (output, ">"));

	/* Add comments for special operands */

	for (int i = 0; i < 6; i++) {
		OperandMeaning operand_meaning = instruction->inst->operands[i].operand_meaning;
		if (operand_meaning == OPERAND_MEANING_NONE) {
			continue;
		}

		u32 value = hbc_operand_value (instruction, i);

		switch (operand_meaning) {
		case OPERAND_MEANING_STRING_ID:
			if (value < reader->header.stringCount &&
				reader->strings && reader->strings[value]) {
				RETURN_IF_ERROR (r_strbuf_append (output, "  # String: \""));
				RETURN_IF_ERROR (r_strbuf_append (output, reader->strings[value]));
				RETURN_IF_ERROR (r_strbuf_append (output, "\" ("));
				if (value < reader->header.stringCount && reader->string_kinds) {
					RETURN_IF_ERROR (r_strbuf_append (output, _hbc_string_kind_to_string (reader->string_kinds[value])));
				} else {
					RETURN_IF_ERROR (r_strbuf_append (output, "Unknown"));
				}
				RETURN_IF_ERROR (r_strbuf_append (output, ")"));
			}
			break;

		case OPERAND_MEANING_BIGINT_ID:
			if (value < reader->bigint_count) {
				RETURN_IF_ERROR (r_strbuf_append (output, "  # BigInt: "));
				RETURN_IF_ERROR (r_strbuf_appendf (output, "%lld", (long long)reader->bigint_values[value]));
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

				RETURN_IF_ERROR (r_strbuf_appendf (output,
					"  # Function: [#%u %s of %u bytes]: %u params @ offset 0x%08x",
					value,
					func_name,
					func->bytecodeSizeInBytes,
					func->paramCount,
					func->offset));
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

		u32 value = hbc_operand_value (instruction, i);

		RETURN_IF_ERROR (r_strbuf_appendf (output, "  # Address: %08x", fh->offset + instruction->original_pos + value));
	}

	/* Add jump table comment for switch instructions */
	if (strcmp (instruction->inst->name, "SwitchImm") == 0) {
		if (instruction->switch_jump_table && instruction->switch_jump_table_size > 0) {
			RETURN_IF_ERROR (r_strbuf_append (output, "  # Jump table: ["));

			for (u32 i = 0; i < instruction->switch_jump_table_size; i++) {
				if (i > 0) {
					RETURN_IF_ERROR (r_strbuf_append (output, ", "));
				}

				RETURN_IF_ERROR (r_strbuf_appendf (output, "%08x", fh->offset + instruction->switch_jump_table[i]));
			}

			RETURN_IF_ERROR (r_strbuf_append (output, "]"));
		}
	}

	/* End the instruction */
	RETURN_IF_ERROR (r_strbuf_append (output, "\n"));

	return SUCCESS_RESULT ();
}

/* Disassemble a single function */
Result _hbc_disassemble_function(Disassembler *disassembler, u32 function_id) {
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
	RETURN_IF_ERROR (_hbc_print_function_header (disassembler, function_header, function_id));

	/* Print bytecode listing header */
	if (disassembler->options.asm_syntax) {
		RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "Bytecode listing (asm):\n\n"));
	} else {
		RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "Bytecode listing:\n\n"));
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
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output,
				"[Skipping function with unreasonably large bytecode size]\n"));
			return SUCCESS_RESULT ();
		}

		/* Skip functions with offset 0 (likely invalid) */
		if (function_header->offset == 0) {
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output,
				"[No bytecode available for this function (invalid offset)]\n"));
			return SUCCESS_RESULT ();
		}

		/* Verify offset is within file bounds */
		if (function_header->offset >= r_buf_size (reader->file_buffer)) {
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output,
				"[Bytecode offset beyond file size]\n"));
			return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Bytecode offset beyond file size");
		}

		/* Verify we can read the full bytecode from the file */
		if (function_header->bytecodeSizeInBytes > r_buf_size (reader->file_buffer) - function_header->offset) {
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output,
				"[Bytecode extends beyond file size, truncating]\n"));
			function_header->bytecodeSizeInBytes = r_buf_size (reader->file_buffer) - function_header->offset;
		}

		/* Allocate bytecode buffer */
		function_header->bytecode = (u8 *)malloc (function_header->bytecodeSizeInBytes);
		if (!function_header->bytecode) {
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "[Memory allocation failed for bytecode]\n"));
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate bytecode buffer");
		}

		/* Read bytecode data */
		bool read_ok = (u32)r_buf_read_at (reader->file_buffer,
				function_header->offset,
				function_header->bytecode,
				function_header->bytecodeSizeInBytes) == function_header->bytecodeSizeInBytes;

		if (!read_ok) {
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "[Failed to read bytecode data]\n"));
			free (function_header->bytecode);
			function_header->bytecode = NULL;
			return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Failed to read bytecode data");
		}

		/* Verify the first byte looks like a valid opcode */
		if (function_header->bytecodeSizeInBytes > 0) {
			u8 first_opcode = function_header->bytecode[0];
			if (first_opcode == 0 || first_opcode > 0xA2) { // Using known opcode range
				RETURN_IF_ERROR (r_strbuf_append (&disassembler->output,
					"[Warning: First byte doesn't look like a valid opcode]\n"));
			}
		}
	}

	/* Parse the bytecode */
	ParsedInstructionList instructions;
	HBCISA isa = hbc_isa_getv (reader->header.version);
	Result result = _hbc_parse_function_bytecode (reader, function_id, &instructions, isa);

	if (result.code != RESULT_SUCCESS) {
		/* Handle parsing error - Print more debug info */
		RETURN_IF_ERROR (r_strbuf_appendf (&disassembler->output,
			"[Error parsing bytecode for function #%u: %s - Offset: %u, Size: %u]\n",
			function_id,
			result.error_message[0] != '\0'? result.error_message: "Unknown error",
			function_header->offset,
			function_header->bytecodeSizeInBytes));

		/* Skip this function but continue with others */
		return SUCCESS_RESULT ();
	} else {
		/* Print raw bytecode if requested */
		if (disassembler->options.show_bytecode) {
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "Raw bytecode: "));
			for (u32 i = 0; i < function_header->bytecodeSizeInBytes; i++) {
				RETURN_IF_ERROR (r_strbuf_appendf (&disassembler->output, "%02x ", function_header->bytecode[i]));

				/* Line break every 16 bytes */
				if ((i + 1) % 16 == 0 && i + 1 < function_header->bytecodeSizeInBytes) {
					RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "\n               "));
				}
			}
			RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "\n\n"));
		}

		/* Print instructions */
		for (u32 i = 0; i < instructions.count; i++) {
			ParsedInstruction *instruction = &instructions.instructions[i];
			if (disassembler->options.asm_syntax) {
				RETURN_IF_ERROR (print_instruction_asm (disassembler, instruction));
			} else {
				RETURN_IF_ERROR (_hbc_print_instruction (disassembler, instruction));
			}
		}

		/* Free instruction list */
		_hbc_parsed_instruction_list_free (&instructions);
	}

	/* End the function disassembly */
	RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "\n\n"));
	RETURN_IF_ERROR (r_strbuf_append (&disassembler->output, "===============\n\n"));

	return SUCCESS_RESULT ();
}

/* Disassemble all functions */
Result _hbc_disassemble_all_functions(Disassembler *disassembler) {
	if (!disassembler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Disassembler is NULL");
	}

	HBCReader *reader = disassembler->reader;

	/* Try to disassemble global function (index 0) first, since Python does this */
	if (reader->header.functionCount > 0) {
		Result result = _hbc_disassemble_function (disassembler, 0);
		if (result.code != RESULT_SUCCESS) {
			fprintf (stderr, "Warning: Failed to disassemble global function: %s\n", result.error_message[0] != '\0'? result.error_message: "Unknown error");
		}
	}

	/* Disassemble each remaining function, ignoring errors */
	for (u32 i = 1; i < reader->header.functionCount; i++) {
		Result result = _hbc_disassemble_function (disassembler, i);
		if (result.code != RESULT_SUCCESS) {
			/* Just log and continue with next function */
			fprintf (stderr, "Warning: Failed to disassemble function #%u: %s\n", i, result.error_message[0] != '\0'? result.error_message: "Unknown error");
		}
	}

	return SUCCESS_RESULT ();
}

/* Output disassembly to file or stdout */
Result _hbc_output_disassembly(Disassembler *disassembler, const char *output_file) {
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
	fputs (R_STRBUF_SAFEGET (&disassembler->output), out);

	/* Close the file if we opened it */
	if (output_file) {
		fclose (out);
		printf ("\n[+] Disassembly output wrote to \"%s\"\n\n", output_file);
	}

	return SUCCESS_RESULT ();
}

/* Disassemble a file */
Result _hbc_disassemble_file(const char *input_file, const char *output_file, HBCDisOptions options) {
	if (!input_file) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Input file is NULL");
	}

	/* Initialize HBC reader */
	HBCReader reader;
	RETURN_IF_ERROR (_hbc_reader_init (&reader));

	/* Read the whole file */
	Result result = _hbc_reader_read_whole_file (&reader, input_file);
	if (result.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&reader);
		return result;
	}

	/* Initialize disassembler */
	Disassembler disassembler;
	result = _hbc_disassembler_init (&disassembler, &reader, options);
	if (result.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&reader);
		return result;
	}

	/* Disassemble all functions */
	result = _hbc_disassemble_all_functions (&disassembler);
	if (result.code != RESULT_SUCCESS) {
		_hbc_disassembler_cleanup (&disassembler);
		_hbc_reader_cleanup (&reader);
		return result;
	}

	/* Output the disassembly */
	result = _hbc_output_disassembly (&disassembler, output_file);

	/* Clean up */
	_hbc_disassembler_cleanup (&disassembler);
	_hbc_reader_cleanup (&reader);

	return result;
}

/* Disassemble a buffer */
Result _hbc_disassemble_buffer(const u8 *buffer, size_t size, const char *output_file, HBCDisOptions options) {
	if (!buffer || size == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid buffer");
	}

	/* Initialize HBC reader */
	HBCReader reader;
	RETURN_IF_ERROR (_hbc_reader_init (&reader));

	reader.file_buffer = r_buf_new_with_bytes (buffer, size);
	if (!reader.file_buffer) {
		_hbc_reader_cleanup (&reader);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate buffer");
	}

	/* Read header */
	Result result = _hbc_reader_read_header (&reader);
	if (result.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&reader);
		return result;
	}

	/* Continue parsing the file */
	/*(This is a simplified version - we should call all the individual read_ functions) */

	/* Initialize disassembler */
	Disassembler disassembler;
	result = _hbc_disassembler_init (&disassembler, &reader, options);
	if (result.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&reader);
		return result;
	}

	/* Disassemble all functions */
	result = _hbc_disassemble_all_functions (&disassembler);
	if (result.code != RESULT_SUCCESS) {
		_hbc_disassembler_cleanup (&disassembler);
		_hbc_reader_cleanup (&reader);
		return result;
	}

	/* Output the disassembly */
	result = _hbc_output_disassembly (&disassembler, output_file);

	/* Clean up */
	_hbc_disassembler_cleanup (&disassembler);
	_hbc_reader_cleanup (&reader);

	return result;
}
