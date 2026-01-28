#include <hbc/hbc.h>
#include <hbc/common.h>
#include <hbc/disasm.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/decompilation/literals.h>
#include <hbc/hermes_encoder.h>
#include <hbc/parser.h>
#include <hbc/bytecode.h>
#include "hbc_internal.h"
#include <hbc/opcodes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================================
 * HBC - Direct File Access API Implementation
 * ============================================================================ */

Result hbc_open(const char *path, HBC **out) {
	if (!path || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_open");
	}

	HBC *hbc = (HBC *)calloc (1, sizeof (HBC));
	if (!hbc) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HBC");
	}

	Result res = _hbc_reader_init (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hbc);
		return res;
	}

	res = _hbc_reader_read_whole_file (&hbc->reader, path);
	if (res.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&hbc->reader);
		free (hbc);
		return res;
	}

	*out = hbc;
	return SUCCESS_RESULT ();
}

Result hbc_open_from_memory(const u8 *data, size_t size, HBC **out) {
	if (!data || size == 0 || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_open_from_memory");
	}

	HBC *hbc = (HBC *)calloc (1, sizeof (HBC));
	if (!hbc) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HBC");
	}

	Result res = _hbc_reader_init (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hbc);
		return res;
	}

	res = _hbc_buffer_reader_init_from_memory (&hbc->reader.file_buffer, data, size);
	if (res.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&hbc->reader);
		free (hbc);
		return res;
	}

	/* Parse header and all sections */
	res = _hbc_reader_read_header (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_functions_robust (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_string_kinds (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_identifier_hashes (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_string_tables (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_arrays (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_bigints (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_regexp (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_cjs_modules (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	res = _hbc_reader_read_function_sources (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	(void)_hbc_reader_read_debug_info;

	*out = hbc;
	return SUCCESS_RESULT ();
}

void hbc_close(HBC *hbc) {
	if (!hbc) {
		return;
	}
	_hbc_reader_cleanup (&hbc->reader);
	free (hbc);
}

u32 hbc_function_count(HBC *hbc) {
	if (!hbc) {
		return 0;
	}
	return hbc->reader.header.functionCount;
}

u32 hbc_string_count(HBC *hbc) {
	if (!hbc) {
		return 0;
	}
	return hbc->reader.header.stringCount;
}

Result hbc_get_header(HBC *hbc, HBCHeader *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_get_header");
	}
	HBCHeader *h = &hbc->reader.header;
	out->magic = h->magic;
	out->version = h->version;
	memcpy (out->sourceHash, h->sourceHash, sizeof (out->sourceHash));
	out->fileLength = h->fileLength;
	out->globalCodeIndex = h->globalCodeIndex;
	out->functionCount = h->functionCount;
	out->stringKindCount = h->stringKindCount;
	out->identifierCount = h->identifierCount;
	out->stringCount = h->stringCount;
	out->overflowStringCount = h->overflowStringCount;
	out->stringStorageSize = h->stringStorageSize;
	out->bigIntCount = h->bigIntCount;
	out->bigIntStorageSize = h->bigIntStorageSize;
	out->regExpCount = h->regExpCount;
	out->regExpStorageSize = h->regExpStorageSize;
	out->arrayBufferSize = h->arrayBufferSize;
	out->objKeyBufferSize = h->objKeyBufferSize;
	out->objValueBufferSize = h->objValueBufferSize;
	out->segmentID = h->segmentID;
	out->cjsModuleCount = h->cjsModuleCount;
	out->functionSourceCount = h->functionSourceCount;
	out->debugInfoOffset = h->debugInfoOffset;
	out->staticBuiltins = h->staticBuiltins;
	out->cjsModulesStaticallyResolved = h->cjsModulesStaticallyResolved;
	out->hasAsync = h->hasAsync;
	return SUCCESS_RESULT ();
}

Result hbc_get_function_info(HBC *hbc, u32 function_id, HBCFunc *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (function_id >= hbc->reader.header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
	}
	const FunctionHeader *fh = &hbc->reader.function_headers[function_id];
	/* Get function name from string table */
	const char *name = NULL;
	if (fh->functionName < hbc->reader.header.stringCount) {
		name = hbc->reader.strings[fh->functionName];
	}
	out->name = name;
	out->offset = fh->offset;
	out->size = fh->bytecodeSizeInBytes;
	out->param_count = fh->paramCount;
	return SUCCESS_RESULT ();
}

Result hbc_get_string(HBC *hbc, u32 index, const char **out_str) {
	if (!hbc || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (index >= hbc->reader.header.stringCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "String ID out of range");
	}
	*out_str = hbc->reader.strings[index];
	return SUCCESS_RESULT ();
}

Result hbc_get_string_meta(HBC *hbc, u32 index, HBCStringMeta *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	HBCReader *r = &hbc->reader;
	if (index >= r->header.stringCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "String ID out of range");
	}

	u32 is_utf16 = r->small_string_table[index].isUTF16;
	u32 length = r->small_string_table[index].length;
	u32 off = r->small_string_table[index].offset;

	if (length == 0xFF) {
		u32 oi = off;
		/* Bounds check: ensure oi is within overflow_string_table bounds */
		if (oi >= r->header.overflowStringCount) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Overflow string index out of bounds");
		}
		/* Additional safety check: ensure overflow_string_table exists */
		if (!r->overflow_string_table) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Overflow string table not allocated");
		}
		off = r->overflow_string_table[oi].offset;
		length = r->overflow_string_table[oi].length;
	}

	out->isUTF16 = is_utf16 != 0;
	out->offset = r->string_storage_file_offset + off;
	out->length = length;
	out->kind = (HBCStringKind)r->string_kinds[index];
	return SUCCESS_RESULT ();
}

Result hbc_get_string_tables(HBC *hbc, HBCStrs *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	out->string_count = hbc->reader.header.stringCount;
	out->small_string_table = hbc->reader.small_string_table;
	out->overflow_string_table = hbc->reader.overflow_string_table;
	out->string_storage_offset = hbc->reader.string_storage_file_offset;
	return SUCCESS_RESULT ();
}

Result hbc_get_function_source(HBC *hbc, u32 function_id, const char **out_src) {
	if (!hbc || !out_src) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (function_id >= hbc->reader.header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
	}
	*out_src = NULL;
	if (hbc->reader.function_sources && function_id < hbc->reader.header.functionSourceCount) {
		u32 string_id = hbc->reader.function_sources[function_id].string_id;
		if (string_id < hbc->reader.header.stringCount) {
			*out_src = hbc->reader.strings[string_id];
		}
	}
	return SUCCESS_RESULT ();
}

Result hbc_get_function_bytecode(HBC *hbc, u32 function_id, const u8 **out_ptr, u32 *out_size) {
	if (!hbc || !out_ptr || !out_size) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (function_id >= hbc->reader.header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
	}
	const FunctionHeader *fh = &hbc->reader.function_headers[function_id];
	*out_ptr = hbc->reader.file_buffer.data + fh->offset;
	*out_size = fh->bytecodeSizeInBytes;
	return SUCCESS_RESULT ();
}

/* ============================================================================
 * HBC Decompilation API (Primary Public Interface)
 * ============================================================================ */

Result hbc_decomp_fn(
	HBC *hbc,
	u32 function_id,
	HBCDecompOptions options,
	char **out_str) {
	if (!hbc || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	StringBuffer sb;
	Result res = _hbc_string_buffer_init (&sb, 16 * 1024);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	res = _hbc_decompile_function_with_state (hbc, function_id, options, &sb);
	if (res.code != RESULT_SUCCESS) {
		_hbc_string_buffer_free (&sb);
		return res;
	}

	*out_str = sb.data;
	return SUCCESS_RESULT ();
}

Result hbc_decomp_all(
	HBC *hbc,
	HBCDecompOptions options,
	char **out_str) {
	if (!hbc || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	StringBuffer sb;
	Result res = _hbc_string_buffer_init (&sb, 32 * 1024);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	res = _hbc_decompile_all_with_state (hbc, options, &sb);
	if (res.code != RESULT_SUCCESS) {
		_hbc_string_buffer_free (&sb);
		return res;
	}

	*out_str = sb.data;
	return SUCCESS_RESULT ();
}

Result hbc_disasm_fn(
	HBC *hbc,
	u32 function_id,
	HBCDisOptions options,
	char **out_str) {
	(void)function_id;
	(void)options;

	if (!hbc || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Disassembly via state not yet implemented");
}

Result hbc_disasm_all(
	HBC *hbc,
	HBCDisOptions options,
	char **out_str) {
	(void)options;

	if (!hbc || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Disassembly via state not yet implemented");
}

Result hbc_all_funcs(
	HBC *hbc,
	HBCFuncArray *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	u32 count = hbc_function_count (hbc);
	if (count == 0) {
		out->functions = NULL;
		out->count = 0;
		return SUCCESS_RESULT ();
	}

	out->functions = (HBCFunc *)malloc (count * sizeof (HBCFunc));
	if (!out->functions) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function array");
	}

	for (u32 i = 0; i < count; i++) {
		Result res = hbc_get_function_info (hbc, i, &out->functions[i]);
		if (res.code != RESULT_SUCCESS) {
			free (out->functions);
			out->functions = NULL;
			out->count = 0;
			return res;
		}
	}

	out->count = count;
	return SUCCESS_RESULT ();
}

void hbc_free_funcs(HBCFuncArray *arr) {
	if (arr) {
		free (arr->functions);
		arr->functions = NULL;
		arr->count = 0;
	}
}

Result hbc_decode_fn(
	HBC *hbc,
	u32 function_id,
	HBCInsns *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	const u8 *bytecode = NULL;
	u32 bytecode_size = 0;
	Result res = hbc_get_function_bytecode (hbc, function_id, &bytecode, &bytecode_size);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	HBCStrs string_tables = { 0 };
	res = hbc_get_string_tables (hbc, &string_tables);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	out->instructions = NULL;
	out->count = 0;
	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Instruction decoding via state not yet implemented");
}

/* Single-instruction decode functions */

Result hbc_dec(const HBCDecodeCtx *ctx, HBCInsnInfo *out) {
	if (!ctx || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid context");
	}

	u32 bytecode_version = ctx->bytecode_version;
	if (bytecode_version == 0) {
		bytecode_version = 96;
		hbc_debug_printf ("Warning: bytecode version not specified, defaulting to %u\n", bytecode_version);
	}

	return hbc_dec_insn (
		ctx->bytes,
		ctx->len,
		bytecode_version,
		ctx->pc,
		ctx->asm_syntax,
		ctx->resolve_string_ids,
		ctx->string_tables,
		ctx->hbc,
		out);
}

Result hbc_dec_insn(
	const u8 *bytes,
	size_t len,
	u32 bytecode_version,
	u64 pc,
	bool asm_syntax,
	bool resolve_string_ids,
	const HBCStrs *string_ctx,
	HBC *hbc,
	HBCInsnInfo *out) {

	if (!bytes || !out || len == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	/* Get the ISA for this bytecode version */
	HBCISA isa = hbc_isa_getv (bytecode_version);
	if (!isa.instructions || isa.count == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid bytecode version");
	}

	/* Read opcode */
	u8 opcode = bytes[0];

	/* Find instruction definition */
	const Instruction *inst = NULL;
	for (u32 i = 0; i < isa.count; i++) {
		if (i == opcode) {
			inst = &isa.instructions[i];
			break;
		}
	}

	if (!inst || !inst->name) {
		out->text = strdup ("unk");
		out->size = 1;
		out->opcode = opcode;
		out->is_jump = false;
		out->is_call = false;
		out->jump_target = 0;
		return SUCCESS_RESULT ();
	}

	/* Parse operands */
	u32 operand_values[6] = { 0 };
	size_t pos = 1; /* Start after opcode */

	for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
		OperandType operand_type = inst->operands[i].operand_type;

		/* Check if we have enough bytes */
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

		if (pos + need > len) {
			break;
		}

		/* Read operand value */
		switch (operand_type) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_UINT8:
		case OPERAND_TYPE_ADDR8:
			operand_values[i] = bytes[pos];
			pos += 1;
			break;
		case OPERAND_TYPE_UINT16:
			operand_values[i] = bytes[pos] | (bytes[pos + 1] << 8);
			pos += 2;
			break;
		case OPERAND_TYPE_REG32:
		case OPERAND_TYPE_UINT32:
		case OPERAND_TYPE_IMM32:
		case OPERAND_TYPE_ADDR32:
			operand_values[i] = bytes[pos] | (bytes[pos + 1] << 8) |
				(bytes[pos + 2] << 16) | (bytes[pos + 3] << 24);
			pos += 4;
			break;
		case OPERAND_TYPE_DOUBLE:
			/* Skip for now */
			pos += 8;
			break;
		default:
			break;
		}
	}

	/* Format output string */
	char buf[512];
	char mnemonic[128];
	int offset = 0;

	/* Convert instruction name to snake_case */
	hbc_camel_to_snake (inst->name, mnemonic, sizeof (mnemonic));

	if (asm_syntax) {
		/* ASM syntax: mnemonic operand1, operand2, ... */
		offset = snprintf (buf, sizeof (buf), "%s", mnemonic);

		bool first = true;
		for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
			if (first) {
				offset += snprintf (buf + offset, sizeof (buf) - offset, " ");
				first = false;
			} else {
				offset += snprintf (buf + offset, sizeof (buf) - offset, ", ");
			}

			OperandType operand_type = inst->operands[i].operand_type;
			OperandMeaning operand_meaning = inst->operands[i].operand_meaning;
			u32 val = operand_values[i];

			if (operand_type == OPERAND_TYPE_REG8 || operand_type == OPERAND_TYPE_REG32) {
				offset += snprintf (buf + offset, sizeof (buf) - offset, "r%u", val);
			} else if (operand_meaning == OPERAND_MEANING_STRING_ID) {
				/* For string IDs, output the string storage offset (not the ID)
				 * so r2 can replace it with flags */
				if (resolve_string_ids && string_ctx && string_ctx->string_storage_offset != 0) {
					u32 str_offset = 0;
					bool found = false;

					/* Cast to proper types for access */
					const StringTableEntry *small_table = (const StringTableEntry *)string_ctx->small_string_table;
					const OffsetLengthPair *overflow_table = (const OffsetLengthPair *)string_ctx->overflow_string_table;

					/* Look up string storage offset from string tables */
					if (val < string_ctx->string_count && small_table) {
						if (small_table[val].length == 0xFF && overflow_table) {
							/* Overflow string */
							u32 overflow_idx = small_table[val].offset;
							str_offset = overflow_table[overflow_idx].offset;
							found = true;
						} else {
							str_offset = small_table[val].offset;
							found = true;
						}
					}

					if (found) {
						/* Output the file-absolute string offset in hex - r2 will replace this with the string flag */
						u32 file_offset = string_ctx->string_storage_offset + str_offset;
						offset += snprintf (buf + offset, sizeof (buf) - offset, "0x%x", file_offset);
					} else {
						/* Fallback: just show the ID */
						offset += snprintf (buf + offset, sizeof (buf) - offset, "0x%x", val);
					}
				} else {
					/* No string tables available, just show the ID */
					offset += snprintf (buf + offset, sizeof (buf) - offset, "0x%x", val);
				}
			} else {
				offset += snprintf (buf + offset, sizeof (buf) - offset, "%u", val);
			}
		}
	} else {
		/* Default syntax */
		offset = snprintf (buf, sizeof (buf), "%s", mnemonic);

		for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
			offset += snprintf (buf + offset, sizeof (buf) - offset, " %u", operand_values[i]);
		}
	}

	char *final_text = NULL;
	if (hbc && (opcode == OP_NewObjectWithBuffer || opcode == OP_NewObjectWithBufferLong ||
	            opcode == OP_NewArrayWithBuffer || opcode == OP_NewArrayWithBufferLong)) {
		HBCReader *reader = &hbc->reader;
		StringBuffer sb;
		if (_hbc_string_buffer_init (&sb, 256).code == RESULT_SUCCESS) {
			Result fmt_res = { .code = RESULT_ERROR_PARSING_FAILED };
			if (opcode == OP_NewObjectWithBuffer || opcode == OP_NewObjectWithBufferLong) {
				u32 key_count = operand_values[1];
				u32 value_count = operand_values[2];
				u32 keys_id = operand_values[3];
				u32 values_id = operand_values[4];
				fmt_res = _hbc_format_object_literal (reader, key_count, value_count, keys_id, values_id,
				                                      &sb, LITERALS_PRETTY_NEVER, true);
			} else {
				u32 value_count = operand_values[2];
				u32 array_id = operand_values[3];
				fmt_res = _hbc_format_array_literal (reader, value_count, array_id,
				                                     &sb, LITERALS_PRETTY_NEVER, true);
			}
			if (fmt_res.code == RESULT_SUCCESS && sb.data && sb.data[0]) {
				size_t buf_len = strlen (buf);
				size_t sb_len = strlen (sb.data);
				final_text = (char *)malloc (buf_len + 4 + sb_len + 1);
				if (final_text) {
					memcpy (final_text, buf, buf_len);
					memcpy (final_text + buf_len, "  ; ", 4);
					memcpy (final_text + buf_len + 4, sb.data, sb_len + 1);
				}
			}
			_hbc_string_buffer_free (&sb);
		}
	}

	out->text = final_text ? final_text : strdup (buf);
	out->size = (u32)pos;
	out->opcode = opcode;

	/* Detect jumps and calls (using snake_case mnemonic) */
	out->is_jump = (strncmp (mnemonic, "jmp", 3) == 0) || (strncmp (mnemonic, "j", 1) == 0 && mnemonic[1] >= 'a' && mnemonic[1] <= 'z');
	out->is_call = (strncmp (mnemonic, "call", 4) == 0) || (strcmp (mnemonic, "construct") == 0);
	out->jump_target = 0;

	if (!out->is_jump && !strncmp (mnemonic, "save_generator", strlen ("save_generator"))) {
		out->is_jump = true;
	}
	if (out->is_jump && operand_values[0] != 0) {
		/* Calculate jump target (relative offset) */
		out->jump_target = pc + (i32)operand_values[0];
	}

	return SUCCESS_RESULT ();
}

/* Encoding functions */

Result hbc_enc(
	const char *asm_line,
	u32 bytecode_version,
	HBCEncBuf *out) {

	if (!asm_line || !out || !out->buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	if (bytecode_version == 0) {
		bytecode_version = 96;
	}

	HBCEncoder encoder;
	RETURN_IF_ERROR (hbc_encoder_init (&encoder, bytecode_version));

	HBCEncodedInstruction instruction;
	Result res = hbc_encoder_parse_instruction (&encoder, asm_line, &instruction);
	if (res.code != RESULT_SUCCESS) {
		hbc_encoder_cleanup (&encoder);
		return res;
	}

	size_t bytes_written = 0;
	res = hbc_encoder_encode_instruction (&encoder, &instruction, out->buffer, out->buffer_size, &bytes_written);
	hbc_encoder_cleanup (&encoder);

	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	out->bytes_written = bytes_written;
	return SUCCESS_RESULT ();
}

Result hbc_enc_multi(
	const char *asm_text,
	u32 bytecode_version,
	HBCEncBuf *out) {

	if (!asm_text || !out || !out->buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	if (bytecode_version == 0) {
		bytecode_version = 96;
	}

	HBCEncoder encoder;
	RETURN_IF_ERROR (hbc_encoder_init (&encoder, bytecode_version));

	size_t bytes_written = 0;
	Result res = hbc_encoder_encode_instructions (&encoder, asm_text, out->buffer, out->buffer_size, &bytes_written);
	hbc_encoder_cleanup (&encoder);

	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	out->bytes_written = bytes_written;
	return SUCCESS_RESULT ();
}

void hbc_free_insns(HBCInsn *insns, u32 count) {
	if (!insns || count == 0) {
		return;
	}
	for (u32 i = 0; i < count; i++) {
		free ((void *)insns[i].mnemonic);
		free (insns[i].text);
	}
	free (insns);
}
