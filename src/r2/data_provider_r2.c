/* radare2 - LGPL - Copyright 2025 - pancake */
/* R2DataProvider: Read HBC data from r2 RBinFile without separate file I/O */

#include <r_bin.h>
#include <hbc/hbc.h>
#include <hbc/data_provider.h>
#include <hbc/common.h>
#include <hbc/parser.h>
#include <stdlib.h>
#include <string.h>

/**
 * R2DataProvider reads from an r2 RBinFile without opening a separate file.
 * Data is already parsed and cached by r2's bin_hbc plugin.
 */
struct R2DataProvider {
	RBinFile *bf; /* r2 binary file handle (not owned) */
	RBin *bin; /* r2 bin handle (not owned) */
	void *buf; /* r2 buffer for binary data (not owned) */

	HBCHeader cached_header; /* Cache to avoid re-parsing */
	bool header_loaded;

	/* String tables cache */
	HBCStringTables cached_string_tables;
	bool string_tables_loaded;

	/* Temporary buffer for bytecode reads */
	ut8 *tmp_read_buffer;
	size_t tmp_buffer_size;
};

/**
 * Create a data provider from an r2 RBinFile.
 * Reads data via r2's RBuffer API (no separate file opens).
 * Returns NULL if bf is NULL or invalid.
 */
HBCDataProvider *hbc_data_provider_from_rbinfile(RBinFile *bf) {
	if (!bf || !bf->buf) {
		return NULL;
	}
	/* Note: bf->rbin might be NULL in some r2 versions, but we only strictly need bf->buf for data reads */

	struct R2DataProvider *rp = (struct R2DataProvider *)malloc (sizeof (*rp));
	if (!rp) {
		return NULL;
	}

	memset (rp, 0, sizeof (*rp));
	rp->bf = bf;
	rp->bin = bf->rbin;
	rp->buf = bf->buf;
	rp->header_loaded = false;
	rp->string_tables_loaded = false;
	rp->tmp_read_buffer = NULL;
	rp->tmp_buffer_size = 0;

	return (HBCDataProvider *)rp;
}

/**
 * Wrapper for hbc_data_provider_from_rbinfile with shorter name (new API).
 */
HBC *hbc_new_r2(RBinFile *bf) {
	return (HBC *)hbc_data_provider_from_rbinfile (bf);
}

/**
 * Parse HBC header from RBuffer at offset 0.
 * Header format is well-defined in the HBC spec.
 */
static Result parse_header_from_buffer(void *buf, HBCHeader *out) {
	if (!buf || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	ut8 header_buf[256];
	if (r_buf_read_at (buf, 0, header_buf, 256) < 32) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_DATA, "Cannot read header");
	}

	/* Parse header fields at known offsets */
	/* Offset 0: magic (8 bytes, little-endian) */
	memcpy (&out->magic, header_buf + 0, 8);
	out->version = r_read_le32 (header_buf + 8);
	memcpy (out->sourceHash, header_buf + 12, 20);
	out->fileLength = r_read_le32 (header_buf + 32);
	out->globalCodeIndex = r_read_le32 (header_buf + 36);
	out->functionCount = r_read_le32 (header_buf + 40);
	out->stringKindCount = r_read_le32 (header_buf + 44);
	out->identifierCount = r_read_le32 (header_buf + 48);
	out->stringCount = r_read_le32 (header_buf + 52);
	out->overflowStringCount = r_read_le32 (header_buf + 56);
	out->stringStorageSize = r_read_le32 (header_buf + 60);
	out->bigIntCount = r_read_le32 (header_buf + 64);
	out->bigIntStorageSize = r_read_le32 (header_buf + 68);
	out->regExpCount = r_read_le32 (header_buf + 72);
	out->regExpStorageSize = r_read_le32 (header_buf + 76);
	out->arrayBufferSize = r_read_le32 (header_buf + 80);
	out->objKeyBufferSize = r_read_le32 (header_buf + 84);
	out->objValueBufferSize = r_read_le32 (header_buf + 88);
	out->segmentID = r_read_le32 (header_buf + 92);
	out->cjsModuleCount = r_read_le32 (header_buf + 96);
	out->functionSourceCount = r_read_le32 (header_buf + 100);
	out->debugInfoOffset = r_read_le32 (header_buf + 104);
	out->staticBuiltins = (header_buf[108] & 0x01) != 0;
	out->cjsModulesStaticallyResolved = (header_buf[108] & 0x02) != 0;
	out->hasAsync = (header_buf[108] & 0x04) != 0;

	return SUCCESS_RESULT ();
}

/**
 * Get the HBC file header.
 * Caches the header on first call to avoid re-parsing.
 */
Result hbc_data_provider_get_header(HBCDataProvider *provider, struct HBCHeader *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Return cached header on subsequent calls */
	if (rp->header_loaded) {
		memcpy (out, &rp->cached_header, sizeof (HBCHeader));
		return SUCCESS_RESULT ();
	}

	/* Parse header on first call */
	Result res = parse_header_from_buffer (rp->buf, &rp->cached_header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	rp->header_loaded = true;
	memcpy (out, &rp->cached_header, sizeof (HBCHeader));
	return SUCCESS_RESULT ();
}

/**
 * Get the total number of functions in the binary.
 */
Result hbc_data_provider_get_function_count(
	HBCDataProvider *provider,
	u32 *out_count) {

	if (!provider || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	/* Get header first */
	HBCHeader header;
	Result res = hbc_data_provider_get_header (provider, (struct HBCHeader *)&header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	*out_count = header.functionCount;
	return SUCCESS_RESULT ();
}

/**
 * Get metadata for a specific function.
 * Function data is pre-parsed by bin_hbc.c and stored in RBinFile->bo->symbols.
 */
Result hbc_data_provider_get_function_info(
	HBCDataProvider *provider,
	u32 function_id,
	struct HBCFunctionInfo *out) {

	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* RBinFile->bo has a list of RBinSymbol entries from bin_hbc.c::symbols () */
	if (!rp->bf || !rp->bf->bo) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No binary object in file");
	}

	RBinObject *bo = (RBinObject *)rp->bf->bo;
	if (!bo->symbols) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No symbols in binary");
	}

	/* Iterate symbols to find function with matching ordinal */
	if (bo->symbols) {
		RListIter *iter;
		RBinSymbol *sym;
		r_list_foreach (bo->symbols, iter, sym) {
			if (sym && sym->ordinal == function_id) {
				/* Found the function */
				out->name = sym->name? (const char *)sym->name: "unknown";
				out->offset = sym->paddr;
				out->size = sym->size;
				out->param_count = 0;
				return SUCCESS_RESULT ();
			}
		}
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "Function not found");
}

/**
 * Get the total number of strings in the binary.
 */
Result hbc_data_provider_get_string_count(
	HBCDataProvider *provider,
	u32 *out_count) {

	if (!provider || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	/* Get header to get string count */
	HBCHeader header;
	Result res = hbc_data_provider_get_header (provider, (struct HBCHeader *)&header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	*out_count = header.stringCount;
	return SUCCESS_RESULT ();
}

/**
 * Get a string by index.
 * String data is pre-parsed by bin_hbc.c and stored in RBinFile->bo->strings.
 */
Result hbc_data_provider_get_string(
	HBCDataProvider *provider,
	u32 string_id,
	const char **out_str) {

	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Strings are in rp->bf->bo->strings (RBinString list) */
	if (!rp->bf || !rp->bf->bo) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No binary object");
	}

	RBinObject *bo = (RBinObject *)rp->bf->bo;
	if (!bo->strings) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No strings");
	}

	/* Iterate strings to find one with matching ordinal */
	if (bo->strings) {
		RListIter *iter;
		RBinString *str;
		r_list_foreach (bo->strings, iter, str) {
			if (str && str->ordinal == string_id) {
				*out_str = str->string;
				return SUCCESS_RESULT ();
			}
		}
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "String not found");
}

/**
 * Get metadata for a string (offset, length, kind).
 */
Result hbc_data_provider_get_string_meta(HBCDataProvider *provider, u32 string_id, struct HBCStringMeta *out) {

	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	if (!rp->bf || !rp->bf->bo) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No binary object");
	}

	RBinObject *bo = (RBinObject *)rp->bf->bo;
	if (!bo->strings) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No strings");
	}

	/* Iterate strings to find metadata */
	if (bo->strings) {
		RListIter *iter;
		RBinString *str;
		r_list_foreach (bo->strings, iter, str) {
			if (str && str->ordinal == string_id) {
				out->offset = str->paddr;
				out->length = str->length;
				out->isUTF16 = false; /* r2 stores UTF8 strings */
				out->kind = HERMES_STRING_KIND_STRING;
				return SUCCESS_RESULT ();
			}
		}
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "String not found");
}

/**
 * Get the raw bytecode bytes for a function.
 */
Result hbc_data_provider_get_bytecode(
	HBCDataProvider *provider,
	u32 function_id,
	const u8 **out_ptr,
	u32 *out_size) {

	if (!provider || !out_ptr || !out_size) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Get function info to find bytecode location */
	struct HBCFunctionInfo info;
	Result res = hbc_data_provider_get_function_info (provider, function_id, &info);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	/* Allocate or reallocate temporary buffer for bytecode */
	if (!rp->tmp_read_buffer || rp->tmp_buffer_size < info.size) {
		ut8 *new_buf = (ut8 *)realloc (rp->tmp_read_buffer, info.size);
		if (!new_buf) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
		}
		rp->tmp_read_buffer = new_buf;
		rp->tmp_buffer_size = info.size;
	}

	/* Read bytecode from buffer at function offset */
	int bytes_read = r_buf_read_at (rp->buf, info.offset, rp->tmp_read_buffer, info.size);
	if (bytes_read != (int)info.size) {
		return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read bytecode");
	}

	*out_ptr = rp->tmp_read_buffer;
	*out_size = info.size;
	return SUCCESS_RESULT ();
}

/**
 * Parse and cache string tables from the binary.
 */
static Result parse_string_tables(struct R2DataProvider *rp) {
	if (!rp || !rp->buf) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	/* Get header first */
	if (!rp->header_loaded) {
		Result res = parse_header_from_buffer (rp->buf, &rp->cached_header);
		if (res.code != RESULT_SUCCESS) {
			return res;
		}
		rp->header_loaded = true;
	}

	HBCHeader *h = &rp->cached_header;

	/* Calculate string table offset (after function headers) */
	ut64 string_kind_offset = 112 + (h->functionCount * 32); /* Header is 112 bytes, each function header is 32 bytes */

	/* Read string kind table */
	ut8 *string_kinds = (ut8 *)malloc (h->stringKindCount);
	if (!string_kinds) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}
	if (r_buf_read_at (rp->buf, string_kind_offset, string_kinds, h->stringKindCount) != (int)h->stringKindCount) {
		free (string_kinds);
		return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read string kinds");
	}

	/* Read identifier hash table (after string kinds) */
	ut64 identifier_offset = string_kind_offset + h->stringKindCount;
	/* Skip identifier hashes for now */

	/* Align to 4-byte boundary after identifier hashes */
	ut64 small_table_offset = identifier_offset + (h->identifierCount * 4);
	small_table_offset = (small_table_offset + 3) & ~3; /* Align to 4 bytes */

	/* Read and parse small string table entries (each entry is a packed 32-bit value) */
	StringTableEntry *small_table = (StringTableEntry *)calloc (h->stringCount, sizeof (StringTableEntry));
	if (!small_table) {
		free (string_kinds);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}

	for (u32 i = 0; i < h->stringCount; i++) {
		ut8 entry_bytes[4];
		if (r_buf_read_at (rp->buf, small_table_offset + (i * 4), entry_bytes, 4) != 4) {
			free (string_kinds);
			free (small_table);
			return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read small string table entry");
		}

		/* Parse packed 32-bit entry (little-endian) */
		u32 entry = entry_bytes[0] | (entry_bytes[1] << 8) | (entry_bytes[2] << 16) | (entry_bytes[3] << 24);

		/* Parse the entry based on version */
		if (h->version >= 56) {
			small_table[i].isUTF16 = entry & 0x1;
			small_table[i].offset = (entry >> 1) & 0x7FFFFF; /* 23 bits */
			small_table[i].length = (entry >> 24) & 0xFF; /* 8 bits */
			small_table[i].isIdentifier = 0;
		} else {
			small_table[i].isUTF16 = entry & 0x1;
			small_table[i].isIdentifier = (entry >> 1) & 0x1;
			small_table[i].offset = (entry >> 2) & 0x3FFFFF; /* 22 bits */
			small_table[i].length = (entry >> 24) & 0xFF; /* 8 bits */
		}
	}

	/* Read overflow string table */
	ut64 overflow_table_offset = small_table_offset + (h->stringCount * 4);
	overflow_table_offset = (overflow_table_offset + 3) & ~3; /* Align to 4 bytes */

	OffsetLengthPair *overflow_table = NULL;
	if (h->overflowStringCount > 0) {
		overflow_table = (OffsetLengthPair *)malloc (h->overflowStringCount * sizeof (OffsetLengthPair));
		if (!overflow_table) {
			free (string_kinds);
			free (small_table);
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
		}

		for (u32 i = 0; i < h->overflowStringCount; i++) {
			ut8 offset_bytes[4], length_bytes[4];
			ut64 entry_offset = overflow_table_offset + (i * 8);

			if (r_buf_read_at (rp->buf, entry_offset, offset_bytes, 4) != 4 ||
				r_buf_read_at (rp->buf, entry_offset + 4, length_bytes, 4) != 4) {
				free (string_kinds);
				free (small_table);
				free (overflow_table);
				return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read overflow string table");
			}

			overflow_table[i].offset = offset_bytes[0] | (offset_bytes[1] << 8) | (offset_bytes[2] << 16) | (offset_bytes[3] << 24);
			overflow_table[i].length = length_bytes[0] | (length_bytes[1] << 8) | (length_bytes[2] << 16) | (length_bytes[3] << 24);
		}
	}

	/* Calculate string storage offset */
	ut64 string_storage_offset = overflow_table_offset + (h->overflowStringCount * 8);
	string_storage_offset = (string_storage_offset + 3) & ~3; /* Align to 4 bytes */

	/* Store in cache */
	rp->cached_string_tables.string_count = h->stringCount;
	rp->cached_string_tables.small_string_table = small_table;
	rp->cached_string_tables.overflow_string_table = overflow_table;
	rp->cached_string_tables.string_storage_offset = string_storage_offset;
	rp->string_tables_loaded = true;

	free (string_kinds); /* We don't need this for now */

	return SUCCESS_RESULT ();
}

/**
 * Get pre-parsed string table data.
 */
Result hbc_data_provider_get_string_tables(HBCDataProvider *provider, struct HBCStringTables *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Parse and cache on first call */
	if (!rp->string_tables_loaded) {
		Result res = parse_string_tables (rp);
		if (res.code != RESULT_SUCCESS) {
			return res;
		}
	}

	/* Return cached tables */
	*out = rp->cached_string_tables;
	return SUCCESS_RESULT ();
}

/**
 * Get source/module name associated with a function (optional, may be NULL).
 */
Result hbc_data_provider_get_function_source(HBCDataProvider *provider, u32 function_id, const char **out_src) {

	if (!provider || !out_src) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	(void)function_id; /* Unused */

	/* Function source metadata is optional; return NULL if not available */
	*out_src = NULL;
	return SUCCESS_RESULT ();
}

/**
 * Low-level: Read raw bytes from the binary at a specific offset.
 */
Result hbc_data_provider_read_raw(
	HBCDataProvider *provider,
	u64 offset,
	u32 size,
	const u8 **out_ptr) {

	if (!provider || !out_ptr) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Allocate buffer if needed */
	if (!rp->tmp_read_buffer || rp->tmp_buffer_size < size) {
		ut8 *new_buf = (ut8 *)realloc (rp->tmp_read_buffer, size);
		if (!new_buf) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
		}
		rp->tmp_read_buffer = new_buf;
		rp->tmp_buffer_size = size;
	}

	/* Read directly from r2's buffer */
	int bytes_read = r_buf_read_at (rp->buf, (ut64)offset, rp->tmp_read_buffer, size);
	if (bytes_read != (int)size) {
		return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read buffer");
	}

	*out_ptr = rp->tmp_read_buffer;
	return SUCCESS_RESULT ();
}

/**
 * Free a data provider and all associated resources.
 */
void hbc_data_provider_free(HBCDataProvider *provider) {
	if (!provider) {
		return;
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Free cached string tables */
	if (rp->string_tables_loaded) {
		free ((void *)rp->cached_string_tables.small_string_table);
		free ((void *)rp->cached_string_tables.overflow_string_table);
	}

	/* Free temporary buffers */
	if (rp->tmp_read_buffer) {
		free (rp->tmp_read_buffer);
		rp->tmp_read_buffer = NULL;
	}

	/* Don't free bf, bin, buf: they are owned by r2 */
	free (rp);
}

/* ============================================================================
 * New short API wrappers - These delegate to the old data provider API
 * ============================================================================ */

Result hbc_hdr(
	HBC *provider,
	HBCHeader *out) {

	return hbc_data_provider_get_header (provider, out);
}

Result hbc_func_count(
	HBC *provider,
	u32 *out_count) {

	return hbc_data_provider_get_function_count (provider, out_count);
}

Result hbc_func_info(
	HBC *provider,
	u32 function_id,
	HBCFunctionInfo *out) {

	return hbc_data_provider_get_function_info (provider, function_id, out);
}

Result hbc_str_count(
	HBC *provider,
	u32 *out_count) {

	return hbc_data_provider_get_string_count (provider, out_count);
}

Result hbc_str(
	HBC *provider,
	u32 string_id,
	const char **out_str) {

	return hbc_data_provider_get_string (provider, string_id, out_str);
}

Result hbc_str_meta(
	HBC *provider,
	u32 string_id,
	HBCStringMeta *out) {

	return hbc_data_provider_get_string_meta (provider, string_id, out);
}

Result hbc_bytecode(
	HBC *provider,
	u32 function_id,
	const u8 **out_ptr,
	u32 *out_size) {

	return hbc_data_provider_get_bytecode (provider, function_id, out_ptr, out_size);
}

Result hbc_str_tbl(
	HBC *provider,
	HBCStringTables *out) {

	return hbc_data_provider_get_string_tables (provider, out);
}

Result hbc_src(
	HBC *provider,
	u32 function_id,
	const char **out_src) {

	return hbc_data_provider_get_function_source (provider, function_id, out_src);
}

Result hbc_read(
	HBC *provider,
	u64 offset,
	u32 size,
	const u8 **out_ptr) {

	return hbc_data_provider_read_raw (provider, offset, size, out_ptr);
}

void hbc_free(HBC *provider) {
	hbc_data_provider_free (provider);
}
