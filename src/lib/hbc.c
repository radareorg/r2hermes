#include <hbc/hbc.h>
#include <hbc/common.h>
#include <hbc/disasm.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/hermes_encoder.h>
#include <hbc/parser.h>
#include <hbc/bytecode.h>
#include "hbc_internal.h"
#include "hbc_internal_legacy.h"
#include <hbc/opcodes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================================
 * HBCSTATE - Direct File Access API Implementation
 * ============================================================================ */

Result hbc_open(const char *path, HBCState **out) {
	if (!path || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_open");
	}

	HBCState *hd = (HBCState *)calloc (1, sizeof (HBCState));
	if (!hd) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HBC");
	}

	Result res = _hbc_reader_init (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hd);
		return res;
	}

	res = _hbc_reader_read_whole_file (&hd->reader, path);
	if (res.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&hd->reader);
		free (hd);
		return res;
	}

	*out = hd;
	return SUCCESS_RESULT ();
}

Result hbc_open_from_memory(const u8 *data, size_t size, HBCState **out) {
	if (!data || size == 0 || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_open_from_memory");
	}

	HBCState *hd = (HBCState *)calloc (1, sizeof (HBCState));
	if (!hd) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HBC");
	}

	Result res = _hbc_reader_init (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hd);
		return res;
	}

	res = _hbc_buffer_reader_init_from_memory (&hd->reader.file_buffer, data, size);
	if (res.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&hd->reader);
		free (hd);
		return res;
	}

	/* Parse header and all sections */
	res = _hbc_reader_read_header (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_functions_robust (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_string_kinds (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_identifier_hashes (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_string_tables (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_arrays (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_bigints (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_regexp (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_cjs_modules (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = _hbc_reader_read_function_sources (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	(void)_hbc_reader_read_debug_info;

	*out = hd;
	return SUCCESS_RESULT ();
}

void hbc_close(HBCState *hd) {
	if (!hd) {
		return;
	}
	_hbc_reader_cleanup (&hd->reader);
	free (hd);
}

u32 hbc_function_count(HBCState *hd) {
	if (!hd) {
		return 0;
	}
	return hd->reader.header.functionCount;
}

u32 hbc_string_count(HBCState *hd) {
	if (!hd) {
		return 0;
	}
	return hd->reader.header.stringCount;
}

Result hbc_get_header(HBCState *hd, HBCHeader *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_get_header");
	}
	HBCHeader *h = &hd->reader.header;
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

Result hbc_get_function_info(HBCState *hd, u32 function_id, HBCFunc *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (function_id >= hd->reader.header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
	}
	const FunctionHeader *fh = &hd->reader.function_headers[function_id];
	/* Get function name from string table */
	const char *name = NULL;
	if (fh->functionName < hd->reader.header.stringCount) {
		name = hd->reader.strings[fh->functionName];
	}
	out->name = name;
	out->offset = fh->offset;
	out->size = fh->bytecodeSizeInBytes;
	out->param_count = fh->paramCount;
	return SUCCESS_RESULT ();
}

Result hbc_get_string(HBCState *hd, u32 index, const char **out_str) {
	if (!hd || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (index >= hd->reader.header.stringCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "String ID out of range");
	}
	*out_str = hd->reader.strings[index];
	return SUCCESS_RESULT ();
}

Result hbc_get_string_meta(HBCState *hd, u32 index, HBCStringMeta *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	HBCReader *r = &hd->reader;
	if (index >= r->header.stringCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "String ID out of range");
	}

	u32 is_utf16 = r->small_string_table[index].isUTF16;
	u32 length = r->small_string_table[index].length;
	u32 off = r->small_string_table[index].offset;

	if (length == 0xFF) {
		u32 oi = off;
		off = r->overflow_string_table[oi].offset;
		length = r->overflow_string_table[oi].length;
	}

	out->isUTF16 = is_utf16 != 0;
	out->offset = r->string_storage_file_offset + off;
	out->length = length;
	out->kind = (HBCStringKind)r->string_kinds[index];
	return SUCCESS_RESULT ();
}

Result hbc_get_string_tables(HBCState *hd, HBCStrs *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	out->string_count = hd->reader.header.stringCount;
	out->small_string_table = hd->reader.small_string_table;
	out->overflow_string_table = hd->reader.overflow_string_table;
	out->string_storage_offset = hd->reader.string_storage_file_offset;
	return SUCCESS_RESULT ();
}

Result hbc_get_function_source(HBCState *hd, u32 function_id, const char **out_src) {
	if (!hd || !out_src) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (function_id >= hd->reader.header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
	}
	*out_src = NULL;
	if (hd->reader.function_sources && function_id < hd->reader.header.functionSourceCount) {
		u32 string_id = hd->reader.function_sources[function_id].string_id;
		if (string_id < hd->reader.header.stringCount) {
			*out_src = hd->reader.strings[string_id];
		}
	}
	return SUCCESS_RESULT ();
}

Result hbc_get_function_bytecode(HBCState *hd, u32 function_id, const u8 **out_ptr, u32 *out_size) {
	if (!hd || !out_ptr || !out_size) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	if (function_id >= hd->reader.header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
	}
	const FunctionHeader *fh = &hd->reader.function_headers[function_id];
	*out_ptr = hd->reader.file_buffer.data + fh->offset;
	*out_size = fh->bytecodeSizeInBytes;
	return SUCCESS_RESULT ();
}

/* ============================================================================
 * CLI Convenience Functions
 * ============================================================================ */

Result hbc_decompile_file(const char *input_file, const char *output_file) {
	return _hbc_decompile_file (input_file, output_file);
}

/* ============================================================================
 * HBC Decompilation API (Primary Public Interface)
 * ============================================================================ */

Result hbc_decomp_fn(
	HBC *provider,
	u32 function_id,
	HBCDecompOptions options,
	char **out_str) {
	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	StringBuffer sb;
	Result res = _hbc_string_buffer_init (&sb, 16 * 1024);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	res = _hbc_decompile_function_with_provider (provider, function_id, options, &sb);
	if (res.code != RESULT_SUCCESS) {
		_hbc_string_buffer_free (&sb);
		return res;
	}

	 *out_str = sb.data; /* Transfer ownership to caller */
	return SUCCESS_RESULT ();
}

Result hbc_decomp_all(
	HBC *provider,
	HBCDecompOptions options,
	char **out_str) {
	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	StringBuffer sb;
	Result res = _hbc_string_buffer_init (&sb, 32 * 1024);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	res = _hbc_decompile_all_with_provider (provider, options, &sb);
	if (res.code != RESULT_SUCCESS) {
		_hbc_string_buffer_free (&sb);
		return res;
	}

	 *out_str = sb.data; /* Transfer ownership to caller */
	return SUCCESS_RESULT ();
}

Result hbc_disasm_fn(
	HBC *provider,
	u32 function_id,
	HBCDisOptions options,
	char **out_str) {
	(void)function_id;
	(void)options;

	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Disassembly via provider not yet implemented");
}

Result hbc_disasm_all(
	HBC *provider,
	HBCDisOptions options,
	char **out_str) {
	(void)options;

	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Disassembly via provider not yet implemented");
}

Result hbc_all_funcs(
	HBC *provider,
	HBCFuncArray *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	u32 count = 0;
	Result res = hbc_func_count (provider, &count);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

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
		res = hbc_func_info (provider, i, &out->functions[i]);
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
	HBC *provider,
	u32 function_id,
	HBCInsns *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	const u8 *bytecode = NULL;
	u32 bytecode_size = 0;
	Result res = hbc_bytecode (provider, function_id, &bytecode, &bytecode_size);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	HBCStrs string_tables = { 0 };
	res = hbc_str_tbl (provider, &string_tables);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	out->instructions = NULL;
	out->count = 0;
	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Instruction decoding via provider not yet implemented");
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
						/* Append full virtual address as comment */
						u32 str_addr = 0x10000000 + file_offset;
						offset += snprintf (buf + offset, sizeof (buf) - offset, "  ; 0x%x", str_addr);
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

	out->text = strdup (buf);
	out->size = (u32)pos;
	out->opcode = opcode;

	/* Detect jumps and calls (using snake_case mnemonic) */
	out->is_jump = (strncmp (mnemonic, "jmp", 3) == 0) || (strncmp (mnemonic, "j", 1) == 0 && mnemonic[1] >= 'a' && mnemonic[1] <= 'z');
	out->is_call = (strncmp (mnemonic, "call", 4) == 0) || (strcmp (mnemonic, "construct") == 0);
	out->jump_target = 0;

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
