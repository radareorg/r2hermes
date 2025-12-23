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
 * INTERNAL LEGACY API - HBCState Implementation (For Data Providers Only)
 * ============================================================================ */

Result hbc_open(const char *path, HBCState **out) {
	if (!path || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_open");
	}

	HBCState *hd = (HBCState *)calloc (1, sizeof (HBCState));
	if (!hd) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HBC");
	}

	Result res = hbc_reader_init (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hd);
		return res;
	}

	res = hbc_reader_read_whole_file (&hd->reader, path);
	if (res.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&hd->reader);
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

	Result res = hbc_reader_init (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hd);
		return res;
	}

	res = buffer_reader_init_from_memory (&hd->reader.file_buffer, data, size);
	if (res.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&hd->reader);
		free (hd);
		return res;
	}

	/* Parse header and all sections */
	res = hbc_reader_read_header (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_functions_robust (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_string_kinds (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_identifier_hashes (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_string_tables (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_arrays (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_bigints (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_regexp (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_cjs_modules (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_function_sources (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	(void)hbc_reader_read_debug_info;

	*out = hd;
	return SUCCESS_RESULT ();
}

void hbc_close(HBCState *hd) {
	if (!hd) {
		return;
	}
	hbc_reader_cleanup (&hd->reader);
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

Result hbc_get_function_info(HBCState *hd, u32 function_id, HBCFunctionInfo *out) {
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
	out->kind = r->string_kinds[index];
	return SUCCESS_RESULT ();
}

Result hbc_get_string_tables(HBCState *hd, HBCStringTables *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	out->string_count = hd->reader.header.stringCount;
	out->small_string_table = hd->reader.small_string_table;
	out->overflow_string_table = hd->reader.overflow_string_table;
	out->string_storage_offset = 0;
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
	return decompile_file (input_file, output_file);
}

/* ============================================================================
 * HBCDataProvider Decompilation API (Primary Public Interface)
 * ============================================================================ */

Result hbc_data_provider_decompile_function(
	HBCDataProvider *provider,
	u32 function_id,
	HBCDecompileOptions options,
	char **out_str) {
	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	StringBuffer sb;
	Result res = string_buffer_init (&sb, 16 * 1024);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	res = decompile_function_with_provider (provider, function_id, options, &sb);
	if (res.code != RESULT_SUCCESS) {
		string_buffer_free (&sb);
		return res;
	}

	*out_str = sb.data; /* Transfer ownership to caller */
	return SUCCESS_RESULT ();
}

Result hbc_data_provider_decompile_all(
	HBCDataProvider *provider,
	HBCDecompileOptions options,
	char **out_str) {
	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	StringBuffer sb;
	Result res = string_buffer_init (&sb, 32 * 1024);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	res = decompile_all_with_provider (provider, options, &sb);
	if (res.code != RESULT_SUCCESS) {
		string_buffer_free (&sb);
		return res;
	}

	*out_str = sb.data; /* Transfer ownership to caller */
	return SUCCESS_RESULT ();
}

Result hbc_data_provider_disassemble_function(
	HBCDataProvider *provider,
	u32 function_id,
	HBCDisassemblyOptions options,
	char **out_str) {
	(void)function_id;
	(void)options;
	
	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Disassembly via provider not yet implemented");
}

Result hbc_data_provider_disassemble_all(
	HBCDataProvider *provider,
	HBCDisassemblyOptions options,
	char **out_str) {
	(void)options;
	
	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Disassembly via provider not yet implemented");
}

Result hbc_data_provider_get_all_functions(
	HBCDataProvider *provider,
	HBCFunctionArray *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	u32 count = 0;
	Result res = hbc_data_provider_get_function_count (provider, &count);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	if (count == 0) {
		out->functions = NULL;
		out->count = 0;
		return SUCCESS_RESULT ();
	}

	out->functions = (HBCFunctionInfo *)malloc (count * sizeof (HBCFunctionInfo));
	if (!out->functions) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function array");
	}

	for (u32 i = 0; i < count; i++) {
		res = hbc_data_provider_get_function_info (provider, i, &out->functions[i]);
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

void hbc_free_function_array(HBCFunctionArray *arr) {
	if (arr) {
		free (arr->functions);
		arr->functions = NULL;
		arr->count = 0;
	}
}

Result hbc_data_provider_decode_function_instructions(
	HBCDataProvider *provider,
	u32 function_id,
	HBCDecodedInstructions *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	const u8 *bytecode = NULL;
	u32 bytecode_size = 0;
	Result res = hbc_data_provider_get_bytecode (provider, function_id, &bytecode, &bytecode_size);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	HBCStringTables string_tables = { 0 };
	res = hbc_data_provider_get_string_tables (provider, &string_tables);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	out->instructions = NULL;
	out->count = 0;
	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Instruction decoding via provider not yet implemented");
}

/* Single-instruction decode functions (unchanged) */

Result hbc_decode(const HBCDecodeContext *ctx, HBCSingleInstructionInfo *out) {
	if (!ctx || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid context");
	}

	u32 bytecode_version = ctx->bytecode_version;
	if (bytecode_version == 0) {
		bytecode_version = 96;
		hbc_debug_printf ("Warning: bytecode version not specified, defaulting to %u\n", bytecode_version);
	}

	return hbc_decode_single_instruction (
		ctx->bytes,
		ctx->len,
		bytecode_version,
		ctx->pc,
		ctx->asm_syntax,
		ctx->resolve_string_ids,
		ctx->string_tables,
		out);
}

Result hbc_decode_single_instruction(
	const u8 *bytes,
	size_t len,
	u32 bytecode_version,
	u64 pc,
	bool asm_syntax,
	bool resolve_string_ids,
	const HBCStringTables *string_ctx,
	HBCSingleInstructionInfo *out) {
	
	HBCDecodeContext ctx = {
		.bytes = bytes,
		.len = len,
		.pc = pc,
		.bytecode_version = bytecode_version,
		.asm_syntax = asm_syntax,
		.resolve_string_ids = resolve_string_ids,
		.string_tables = string_ctx
	};
	return hbc_decode (&ctx, out);
}

/* Encoding functions (unchanged) */

Result hbc_encode_instruction(
	const char *asm_line,
	u32 bytecode_version,
	HBCEncodeBuffer *out) {
	
	if (!asm_line || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	if (bytecode_version == 0) {
		bytecode_version = 96;
	}

	/* Placeholder: real implementation would parse asm_line and encode */
	(void)bytecode_version;

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Encoding not yet implemented");
}

Result hbc_encode_instructions(
	const char *asm_text,
	u32 bytecode_version,
	HBCEncodeBuffer *out) {
	
	if (!asm_text || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	if (bytecode_version == 0) {
		bytecode_version = 96;
	}

	/* Placeholder: real implementation would parse multiple instructions */
	(void)bytecode_version;

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Encoding not yet implemented");
}

void hbc_free_instructions(HBCInstruction *insns, u32 count) {
	if (!insns || count == 0) {
		return;
	}
	for (u32 i = 0; i < count; i++) {
		free ((void *)insns[i].mnemonic);
		free (insns[i].text);
	}
	free (insns);
}
