#include <hbc/hbc.h>
#include <hbc/common.h>
#include <hbc/disasm.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/decompilation/literals.h>
#include <hbc/literals.h>
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
	res = _hbc_reader_read_debug_info (&hbc->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}

	*out = hbc;
	return SUCCESS_RESULT ();
}

void hbc_close(HBC *hbc) {
	if (!hbc) {
		return;
	}
	hbc_literals_reset (hbc);
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
	*out = hbc->reader.header;
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
	if (hbc->reader.function_sources) {
		for (u32 i = 0; i < hbc->reader.header.functionSourceCount; i++) {
			if (hbc->reader.function_sources[i].function_id != function_id) {
				continue;
			}
			u32 string_id = hbc->reader.function_sources[i].string_id;
			if (string_id < hbc->reader.header.stringCount) {
				*out_src = hbc->reader.strings[string_id];
			}
			break;
		}
	}
	return SUCCESS_RESULT ();
}

static bool read_sleb128(const u8 *data, size_t size, size_t *pos, int64_t *out) {
	uint64_t result = 0;
	unsigned shift = 0;
	u8 byte = 0;

	do {
		if (*pos >= size || shift > 63) {
			return false;
		}
		byte = data[(*pos)++];
		if (shift == 63 && (byte & 0x7e)) {
			return false;
		}
		result |= ((uint64_t)(byte & 0x7f)) << shift;
		shift += 7;
	} while (byte & 0x80);

	if ((shift < 64) && (byte & 0x40)) {
		result |= (~0ULL) << shift;
	}
	*out = (int64_t)result;
	return true;
}

static const char *debug_filename_at(HBCReader *reader, u32 index) {
	const u32 count = reader->debug_info_header.filename_count;
	if (index >= count || !reader->debug_string_table || !reader->debug_string_storage) {
		return NULL;
	}
	if (!reader->debug_filenames) {
		reader->debug_filenames = (char **)calloc (count, sizeof (char *));
		if (!reader->debug_filenames) {
			return NULL;
		}
	}
	if (!reader->debug_filenames[index]) {
		const OffsetLengthPair *entry = &reader->debug_string_table[index];
		const size_t storage_size = reader->debug_string_storage_size;
		if ((size_t)entry->offset > storage_size || (size_t)entry->length > storage_size - entry->offset) {
			return NULL;
		}
		char *filename = (char *)malloc ((size_t)entry->length + 1);
		if (!filename) {
			return NULL;
		}
		memcpy (filename, reader->debug_string_storage + entry->offset, entry->length);
		filename[entry->length] = '\0';
		reader->debug_filenames[index] = filename;
	}
	return reader->debug_filenames[index];
}

static const char *debug_filename_for_source_offset(HBCReader *reader, u32 source_offset) {
	const DebugFileRegion *best = NULL;
	for (u32 i = 0; i < reader->debug_file_region_count; i++) {
		const DebugFileRegion *region = &reader->debug_file_regions[i];
		if (region->from_address <= source_offset && (!best || region->from_address >= best->from_address)) {
			best = region;
		}
	}
	return best? debug_filename_at (reader, best->filename_id): NULL;
}

static Result append_source_line(HBCSourceLineArray *arr, u32 *cap, const HBCSourceLine *line) {
	if (arr->count >= *cap) {
		u32 next = *cap? (*cap * 2): 64;
		HBCSourceLine *lines = (HBCSourceLine *)realloc (arr->lines, (size_t)next * sizeof (HBCSourceLine));
		if (!lines) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate source lines");
		}
		arr->lines = lines;
		*cap = next;
	}
	arr->lines[arr->count++] = *line;
	return SUCCESS_RESULT ();
}

#define PARSE_FAIL(msg) do { res = ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, msg); goto fail; } while (0)

Result hbc_get_source_lines(HBC *hbc, HBCSourceLineArray *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	memset (out, 0, sizeof (*out));
	HBCReader *reader = &hbc->reader;
	const u8 *data = reader->sources_data_storage;
	const size_t size = reader->sources_data_storage_size;
	if (!data || !size) {
		return SUCCESS_RESULT ();
	}

	Result res = SUCCESS_RESULT ();
	u32 cap = 0;
	size_t pos = 0;
	while (pos < size) {
		const size_t source_offset = pos;
		int64_t function_id = 0, line = 0, column = 0;
		if (source_offset > UINT32_MAX
				|| !read_sleb128 (data, size, &pos, &function_id)
				|| !read_sleb128 (data, size, &pos, &line)
				|| !read_sleb128 (data, size, &pos, &column)) {
			PARSE_FAIL ("Invalid source location header");
		}
		if (function_id < 0 || function_id >= (int64_t)reader->header.functionCount
				|| line < 0 || line > UINT32_MAX || column < 0 || column > UINT32_MAX) {
			PARSE_FAIL ("Source location header out of range");
		}

		HBCFunc fi = { 0 };
		(void)hbc_get_function_info (hbc, (u32)function_id, &fi);
		HBCSourceLine sl = {
			.function_id = (u32)function_id,
			.address = fi.offset,
			.line = (u32)line,
			.column = (u32)column,
			.filename = debug_filename_for_source_offset (reader, (u32)source_offset)
		};
		res = append_source_line (out, &cap, &sl);
		if (res.code != RESULT_SUCCESS) {
			goto fail;
		}

		int64_t address = 0, statement = 0;
		for (;;) {
			int64_t adelta = 0;
			if (!read_sleb128 (data, size, &pos, &adelta)) {
				PARSE_FAIL ("Invalid source location address delta");
			}
			if (adelta == -1) {
				break;
			}
			int64_t ldelta = 0, cdelta = 0, scope = 0, env = 0, sdelta = 0;
			if (adelta < 0
					|| !read_sleb128 (data, size, &pos, &ldelta)
					|| !read_sleb128 (data, size, &pos, &cdelta)
					|| !read_sleb128 (data, size, &pos, &scope)
					|| !read_sleb128 (data, size, &pos, &env)) {
				PARSE_FAIL ("Invalid source location entry");
			}
			if ((ldelta & 1) && !read_sleb128 (data, size, &pos, &sdelta)) {
				PARSE_FAIL ("Invalid source location statement delta");
			}
			ldelta = (ldelta - (ldelta & 1)) / 2;
			address += adelta;
			line += ldelta;
			column += cdelta;
			statement += sdelta;
			if (address < 0 || address > UINT32_MAX || (uint64_t)fi.offset + (uint64_t)address > UINT32_MAX
					|| line < 0 || line > UINT32_MAX || column < 0 || column > UINT32_MAX
					|| statement < 0 || statement > UINT32_MAX) {
				PARSE_FAIL ("Source location entry out of range");
			}
			sl.address = fi.offset + (u32)address;
			sl.function_address = (u32)address;
			sl.line = (u32)line;
			sl.column = (u32)column;
			sl.statement = (u32)statement;
			res = append_source_line (out, &cap, &sl);
			if (res.code != RESULT_SUCCESS) {
				goto fail;
			}
		}
	}
	return SUCCESS_RESULT ();
fail:
	hbc_free_source_lines (out);
	return res;
}

#undef PARSE_FAIL

void hbc_free_source_lines(HBCSourceLineArray *arr) {
	if (!arr) {
		return;
	}
	free (arr->lines);
	memset (arr, 0, sizeof (*arr));
}

bool hbc_has_source_lines(HBC *hbc) {
	return hbc && hbc->reader.sources_data_storage && hbc->reader.sources_data_storage_size > 0;
}

Result hbc_get_debug_info(HBC *hbc, HBCDebugInfo *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	memset (out, 0, sizeof (*out));
	HBCReader *reader = &hbc->reader;
	out->has_debug_info = reader->header.debugInfoOffset != 0;
	if (!out->has_debug_info) {
		return SUCCESS_RESULT ();
	}
	out->filename_count = reader->debug_info_header.filename_count;
	out->filename_storage_size = reader->debug_info_header.filename_storage_size;
	out->file_region_count = reader->debug_info_header.file_region_count;
	out->source_locations_size = (u32)reader->sources_data_storage_size;
	out->scope_desc_data_size = (u32)reader->scope_desc_data_storage_size;
	out->textified_data_size = (u32)reader->textified_data_storage_size;
	out->string_table_size = (u32)reader->string_table_storage_size;
	out->debug_data_size = reader->debug_info_header.debug_data_size;
	if (reader->function_headers) {
		for (u32 i = 0; i < reader->header.functionCount; i++) {
			if (reader->function_headers[i].hasDebugInfo) {
				out->functions_with_debug_info++;
			}
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

/* Single-instruction decode functions */

static char *build_literal_comment(HBCReader *reader, const char *mnemonic, const u32 *ovs, const char *base_text) {
	const bool is_obj = mnemonic && !strncmp (mnemonic, "new_object_with_buffer", strlen ("new_object_with_buffer"));
	StringBuffer sb;
	if (_hbc_string_buffer_init (&sb, 256).code != RESULT_SUCCESS) {
		return NULL;
	}
	Result fmt_res;
	if (is_obj) {
		const u32 key_count = ovs[1];
		const u32 value_count = ovs[2];
		const u32 keys_id = ovs[3];
		const u32 values_id = ovs[4];
		fmt_res = _hbc_format_object_literal (reader, key_count, value_count, keys_id, values_id, &sb, LITERALS_PRETTY_NEVER, true);
	} else {
		const u32 value_count = ovs[2];
		const u32 array_id = ovs[3];
		fmt_res = _hbc_format_array_literal (reader, value_count, array_id, &sb, LITERALS_PRETTY_NEVER, true);
	}
	char *result = NULL;
	if (fmt_res.code == RESULT_SUCCESS && sb.length > 0) {
		size_t base_len = strlen (base_text);
		result = (char *)malloc (base_len + 4 + sb.length + 1);
		if (result) {
			memcpy (result, base_text, base_len);
			memcpy (result + base_len, "  ; ", 4);
			memcpy (result + base_len + 4, sb.data, sb.length + 1);
		}
	}
	_hbc_string_buffer_free (&sb);
	return result;
}

Result hbc_dec(const HBCDecodeCtx *ctx, HBCInsnInfo *out) {
	if (!ctx || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid context");
	}

	u32 bytecode_version = ctx->bytecode_version;
	if (bytecode_version == 0) {
		bytecode_version = 96;
		hbc_debug_printf ("Warning: bytecode version not specified, defaulting to %u\n", bytecode_version);
	}

	if (!ctx->bytes || !out || ctx->len == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	/* Get the ISA for this bytecode version */
	HBCISA isa = hbc_isa_getv (bytecode_version);
	if (!isa.instructions || isa.count == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid bytecode version");
	}

	/* Read opcode */
	u8 opcode = ctx->bytes[0];

	/* Get instruction definition */
	const Instruction *inst = (opcode < isa.count)? &isa.instructions[opcode]: NULL;
	if (!inst || !inst->name) {
		out->text = strdup ("unk");
		out->size = 1;
		out->opcode = opcode;
		out->canonical_opcode = HBC_CANONICAL_OPCODE_UNKNOWN;
		out->mnemonic = NULL;
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

		if (pos + need > ctx->len) {
			break;
		}

		/* Read operand value */
		switch (operand_type) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_UINT8:
			operand_values[i] = ctx->bytes[pos];
			pos += 1;
			break;
		case OPERAND_TYPE_ADDR8:
			operand_values[i] = (u32) (i32) (i8)ctx->bytes[pos];
			pos += 1;
			break;
		case OPERAND_TYPE_UINT16:
			operand_values[i] = (u32)ctx->bytes[pos] | ((u32)ctx->bytes[pos + 1] << 8);
			pos += 2;
			break;
		case OPERAND_TYPE_REG32:
		case OPERAND_TYPE_UINT32:
		case OPERAND_TYPE_IMM32:
		case OPERAND_TYPE_ADDR32:
			operand_values[i] = (u32)ctx->bytes[pos] | ((u32)ctx->bytes[pos + 1] << 8) |
				((u32)ctx->bytes[pos + 2] << 16) | ((u32)ctx->bytes[pos + 3] << 24);
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

	/* Tables are already snake_case */
	snprintf (mnemonic, sizeof (mnemonic), "%s", inst->name);

	if (ctx->asm_syntax) {
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
				if (ctx->resolve_string_ids && ctx->string_tables && ctx->string_tables->string_storage_offset != 0) {
					u32 str_offset = 0;
					bool found = false;

					/* Cast to proper types for access */
					const StringTableEntry *small_table = (const StringTableEntry *)ctx->string_tables->small_string_table;
					const OffsetLengthPair *overflow_table = (const OffsetLengthPair *)ctx->string_tables->overflow_string_table;

					/* Look up string storage offset from string tables */
					if (val < ctx->string_tables->string_count && small_table) {
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
						u32 file_offset = ctx->string_tables->string_storage_offset + str_offset;
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

	if (ctx->build_objects && ctx->hbc) {
		const bool is_literal_op = !strncmp (mnemonic, "new_object_with_buffer", strlen ("new_object_with_buffer")) ||
			!strncmp (mnemonic, "new_array_with_buffer", strlen ("new_array_with_buffer"));
		if (is_literal_op) {
			char *with_comment = build_literal_comment (&ctx->hbc->reader, mnemonic, operand_values, buf);
			out->text = with_comment? with_comment: strdup (buf);
		} else {
			out->text = strdup (buf);
		}
	} else {
		out->text = strdup (buf);
	}
	out->size = (u32)pos;
	out->opcode = opcode;
	out->canonical_opcode = hbc_canonical_opcode_from_name (mnemonic);
	out->mnemonic = inst->name;

	/* Detect jumps and calls (using snake_case mnemonic) */
	out->is_jump = (strncmp (mnemonic, "jmp", 3) == 0) || (strncmp (mnemonic, "j", 1) == 0 && mnemonic[1] >= 'a' && mnemonic[1] <= 'z');
	out->is_call = (strncmp (mnemonic, "call", 4) == 0) || (strcmp (mnemonic, "construct") == 0);
	out->jump_target = 0;

	if (!out->is_jump && !strncmp (mnemonic, "save_generator", strlen ("save_generator"))) {
		out->is_jump = true;
	}
	if (out->is_jump && operand_values[0] != 0) {
		/* Calculate jump target (relative offset) */
		out->jump_target = ctx->pc + (i32)operand_values[0];
	}

	return SUCCESS_RESULT ();
}

typedef struct {
	const char *name;    /* exact match, else match prefix */
	const char *prefix;
	const char *kind;
	const char *module;  /* NULL for exports */
	HBCBindingType type;
} BindingHint;

static const BindingHint g_hints[] = {
	{ "NativeModules",          NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "TurboModuleRegistry",    NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "__turboModuleProxy",     NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "requireNativeComponent", NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "codegenNativeComponent", NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "NativeEventEmitter",     NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "RCTDeviceEventEmitter",  NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "HermesInternal",         NULL,     "native", "react-native", HBC_BINDING_IMPORT },
	{ "require",                NULL,     "js",     "react-native", HBC_BINDING_IMPORT },
	{ "metroRequire",           NULL,     "js",     "react-native", HBC_BINDING_IMPORT },
	{ "__r",                    NULL,     "js",     "react-native", HBC_BINDING_IMPORT },
	{ "importScripts",          NULL,     "js",     "react-native", HBC_BINDING_IMPORT },
	{ "global",                 NULL,     "global", "react-native", HBC_BINDING_IMPORT },
	{ "globalThis",             NULL,     "global", "react-native", HBC_BINDING_IMPORT },
	{ "exports",                NULL,     "module", NULL,           HBC_BINDING_EXPORT },
	{ "module",                 NULL,     "module", NULL,           HBC_BINDING_EXPORT },
	{ "__esModule",             NULL,     "module", NULL,           HBC_BINDING_EXPORT },
	{ "default",                NULL,     "module", NULL,           HBC_BINDING_EXPORT },
	{ NULL,                     "RCT",    "native", "react-native", HBC_BINDING_IMPORT },
	{ NULL,                     "Native", "native", "react-native", HBC_BINDING_IMPORT },
};
#define HINTS_N (sizeof (g_hints) / sizeof (g_hints[0]))

static bool str_eq(const char *a, const char *b) {
	if (a == b) {
		return true;
	}
	return a && b && !strcmp (a, b);
}

static bool is_export_marker(const char *s) {
	return !strcmp (s, "exports") || !strcmp (s, "module");
}

static bool is_export_store(const char *name) {
	return strstr (name, "put") && strstr (name, "by_id");
}

static Result binding_add(HBCBindings *out, HBCBindingType type, const char *kind,
	const char *name, const char *module, u32 function_id, u32 offset, u32 string_id) {
	for (u32 i = 0; i < out->count; i++) {
		HBCBinding *b = &out->bindings[i];
		if (b->type == type && !strcmp (b->kind, kind)
				&& !strcmp (b->name, name) && str_eq (b->module, module)) {
			return SUCCESS_RESULT ();
		}
	}
	HBCBinding *nb = realloc (out->bindings, (out->count + 1) * sizeof (HBCBinding));
	if (!nb) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	out->bindings = nb;
	HBCBinding *b = &nb[out->count++];
	*b = (HBCBinding){
		.type = type, .kind = kind, .name = strdup (name),
		.module = module? strdup (module): NULL,
		.function_id = function_id, .offset = offset, .string_id = string_id,
	};
	if (!b->name || (module && !b->module)) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	return SUCCESS_RESULT ();
}

static size_t decode_operands(const Instruction *inst, const u8 *bytes, size_t len,
	u32 values[6]) {
	size_t pos = 1;
	memset (values, 0, 6 * sizeof (u32));
	for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
		OperandType t = inst->operands[i].operand_type;
		size_t need;
		switch (t) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_UINT8:
			need = 1;
			if (pos + need > len) { return 0; }
			values[i] = bytes[pos];
			break;
		case OPERAND_TYPE_ADDR8:
			need = 1;
			if (pos + need > len) { return 0; }
			values[i] = (u32)(i32)(i8)bytes[pos];
			break;
		case OPERAND_TYPE_UINT16:
			need = 2;
			if (pos + need > len) { return 0; }
			values[i] = (u32)bytes[pos] | ((u32)bytes[pos + 1] << 8);
			break;
		case OPERAND_TYPE_REG32:
		case OPERAND_TYPE_UINT32:
		case OPERAND_TYPE_IMM32:
		case OPERAND_TYPE_ADDR32:
			need = 4;
			if (pos + need > len) { return 0; }
			values[i] = (u32)bytes[pos] | ((u32)bytes[pos + 1] << 8)
				| ((u32)bytes[pos + 2] << 16) | ((u32)bytes[pos + 3] << 24);
			break;
		case OPERAND_TYPE_DOUBLE:
			need = 8;
			if (pos + need > len) { return 0; }
			break;
		default:
			return 0;
		}
		pos += need;
	}
	return pos;
}

static Result scan_hint_matches(HBCBindings *out, const char *s, u32 fid, u32 off, u32 sid) {
	for (size_t h = 0; h < HINTS_N; h++) {
		const BindingHint *hint = &g_hints[h];
		bool match = hint->name? !strcmp (s, hint->name):
			!strncmp (s, hint->prefix, strlen (hint->prefix));
		if (!match) {
			continue;
		}
		RETURN_IF_ERROR (binding_add (out, hint->type, hint->kind, s,
			hint->module, fid, off, sid));
	}
	return SUCCESS_RESULT ();
}

static bool function_has_export_marker(HBCReader *r, const u8 *code, u32 size, HBCISA isa) {
	for (u32 pc = 0; pc < size; ) {
		u8 op = code[pc];
		const Instruction *inst = (op < isa.count)? &isa.instructions[op]: NULL;
		if (!inst || !inst->name || !inst->binary_size) {
			break;
		}
		u32 values[6];
		if (!decode_operands (inst, code + pc, size - pc, values)) {
			break;
		}
		for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
			if (inst->operands[i].operand_meaning == OPERAND_MEANING_STRING_ID) {
				u32 sid = values[i];
				const char *s = (sid < r->header.stringCount && r->strings)? r->strings[sid]: NULL;
				if (s && is_export_marker (s)) {
					return true;
				}
			}
		}
		pc += inst->binary_size;
	}
	return false;
}

Result hbc_scan_bindings(HBC *hbc, HBCBindings *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	memset (out, 0, sizeof (*out));
	HBCReader *r = &hbc->reader;
	HBCISA isa = hbc_isa_getv (r->header.version);
	if (!isa.instructions) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "no isa for version");
	}
	if (r->header.cjsModuleCount > 0 && r->header.version >= 77 && r->cjs_modules) {
		for (u32 i = 0; i < r->header.cjsModuleCount; i++) {
			u32 sid = r->cjs_modules[i].symbol_id;
			const char *name = (sid < r->header.stringCount && r->strings)? r->strings[sid]: NULL;
			if (name && *name) {
				RETURN_IF_ERROR (binding_add (out, HBC_BINDING_IMPORT,
					"cjs", name, "commonjs", 0, r->cjs_modules[i].offset, sid));
			}
		}
	}
	for (u32 fid = 0; fid < r->header.functionCount; fid++) {
		const u8 *code = NULL;
		u32 size = 0;
		if (hbc_get_function_bytecode (hbc, fid, &code, &size).code != RESULT_SUCCESS
				|| !code || !size) {
			continue;
		}
		HBCFunc fi = { 0 };
		(void)hbc_get_function_info (hbc, fid, &fi);
		bool has_export_marker = function_has_export_marker (r, code, size, isa);
		for (u32 pc = 0; pc < size; ) {
			u8 op = code[pc];
			const Instruction *inst = (op < isa.count)? &isa.instructions[op]: NULL;
			if (!inst || !inst->name || !inst->binary_size) {
				break;
			}
			u32 values[6];
			if (!decode_operands (inst, code + pc, size - pc, values)) {
				break;
			}
			for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
				if (inst->operands[i].operand_meaning != OPERAND_MEANING_STRING_ID) {
					continue;
				}
				u32 sid = values[i];
				const char *s = (sid < r->header.stringCount && r->strings)? r->strings[sid]: NULL;
				if (!s || !*s) {
					continue;
				}
				RETURN_IF_ERROR (scan_hint_matches (out, s, fid, fi.offset + pc, sid));
				if (has_export_marker && is_export_store (inst->name) && !is_export_marker (s)) {
					RETURN_IF_ERROR (binding_add (out, HBC_BINDING_EXPORT,
						"module", s, NULL, fid, fi.offset + pc, sid));
				}
			}
			pc += inst->binary_size;
		}
	}
	return SUCCESS_RESULT ();
}

void hbc_free_bindings(HBCBindings *bindings) {
	if (!bindings || !bindings->bindings) {
		return;
	}
	for (u32 i = 0; i < bindings->count; i++) {
		free (bindings->bindings[i].name);
		free (bindings->bindings[i].module);
	}
	free (bindings->bindings);
	bindings->bindings = NULL;
	bindings->count = 0;
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
