/* radare2 - LGPL - Copyright 2025-2026 - pancake */
/* R2 HBC Provider: Read HBC data from r2 RBinFile without separate file I/O */

#include <r_bin.h>
#include <hbc/hbc.h>
#include <hbc/common.h>
#include <hbc/parser.h>
#include <stdlib.h>
#include <string.h>

/**
 * R2 provider reads from an r2 RBinFile without opening a separate file.
 * Data is already parsed and cached by r2's bin_hbc plugin.
 */
struct HBC {
	RBinFile *bf; /* r2 binary file handle (not owned) */
	RBin *bin; /* r2 bin handle (not owned) */
	void *buf; /* r2 buffer for binary data (not owned) */

	HBCHeader cached_header; /* Cache to avoid re-parsing */
	bool header_loaded;

	/* String tables cache */
	HBCStrs cached_string_tables;
	bool string_tables_loaded;

	/* Temporary buffer for bytecode reads */
	ut8 *tmp_read_buffer;
	size_t tmp_buffer_size;
};

/**
 * Parse HBC header from RBuffer at offset 0.
 */
static Result parse_header_from_buffer(void *buf, HBCHeader *out) {
	if (!buf || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	ut8 header_buf[256];
	if (r_buf_read_at (buf, 0, header_buf, 256) < 32) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_DATA, "Cannot read header");
	}

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
 * Parse and cache string tables from the binary.
 */
static Result parse_string_tables(HBC *hbc) {
	if (!hbc || !hbc->buf) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	if (!hbc->header_loaded) {
		Result res = parse_header_from_buffer (hbc->buf, &hbc->cached_header);
		if (res.code != RESULT_SUCCESS) {
			return res;
		}
		hbc->header_loaded = true;
	}

	HBCHeader *h = &hbc->cached_header;

	ut64 string_kind_offset = 112 + (h->functionCount * 32);

	ut8 *string_kinds = (ut8 *)malloc (h->stringKindCount);
	if (!string_kinds) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}
	if (r_buf_read_at (hbc->buf, string_kind_offset, string_kinds, h->stringKindCount) != (int)h->stringKindCount) {
		free (string_kinds);
		return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read string kinds");
	}

	ut64 identifier_offset = string_kind_offset + h->stringKindCount;
	ut64 small_table_offset = identifier_offset + (h->identifierCount * 4);
	small_table_offset = (small_table_offset + 3) & ~3;

	StringTableEntry *small_table = (StringTableEntry *)calloc (h->stringCount, sizeof (StringTableEntry));
	if (!small_table) {
		free (string_kinds);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}

	for (u32 i = 0; i < h->stringCount; i++) {
		ut8 entry_bytes[4];
		if (r_buf_read_at (hbc->buf, small_table_offset + (i * 4), entry_bytes, 4) != 4) {
			free (string_kinds);
			free (small_table);
			return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read small string table entry");
		}

		u32 entry = entry_bytes[0] | (entry_bytes[1] << 8) | (entry_bytes[2] << 16) | (entry_bytes[3] << 24);

		if (h->version >= 56) {
			small_table[i].isUTF16 = entry & 0x1;
			small_table[i].offset = (entry >> 1) & 0x7FFFFF;
			small_table[i].length = (entry >> 24) & 0xFF;
			small_table[i].isIdentifier = 0;
		} else {
			small_table[i].isUTF16 = entry & 0x1;
			small_table[i].isIdentifier = (entry >> 1) & 0x1;
			small_table[i].offset = (entry >> 2) & 0x3FFFFF;
			small_table[i].length = (entry >> 24) & 0xFF;
		}
	}

	ut64 overflow_table_offset = small_table_offset + (h->stringCount * 4);
	overflow_table_offset = (overflow_table_offset + 3) & ~3;

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

			if (r_buf_read_at (hbc->buf, entry_offset, offset_bytes, 4) != 4 ||
				r_buf_read_at (hbc->buf, entry_offset + 4, length_bytes, 4) != 4) {
				free (string_kinds);
				free (small_table);
				free (overflow_table);
				return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read overflow string table");
			}

			overflow_table[i].offset = offset_bytes[0] | (offset_bytes[1] << 8) | (offset_bytes[2] << 16) | (offset_bytes[3] << 24);
			overflow_table[i].length = length_bytes[0] | (length_bytes[1] << 8) | (length_bytes[2] << 16) | (length_bytes[3] << 24);
		}
	}

	ut64 string_storage_offset = overflow_table_offset + (h->overflowStringCount * 8);
	string_storage_offset = (string_storage_offset + 3) & ~3;

	hbc->cached_string_tables.string_count = h->stringCount;
	hbc->cached_string_tables.small_string_table = small_table;
	hbc->cached_string_tables.overflow_string_table = overflow_table;
	hbc->cached_string_tables.string_storage_offset = string_storage_offset;
	hbc->string_tables_loaded = true;

	free (string_kinds);
	return SUCCESS_RESULT ();
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

HBC *r2_hbc_new_r2(RBinFile *bf) {
	if (!bf || !bf->buf) {
		return NULL;
	}
	HBC *hbc = R_NEW0 (HBC);
	hbc->bf = bf;
	hbc->bin = bf->rbin;
	hbc->buf = bf->buf;
	return hbc;
}

Result r2_hbc_hdr(HBC *hbc, HBCHeader *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	if (hbc->header_loaded) {
		memcpy (out, &hbc->cached_header, sizeof (HBCHeader));
		return SUCCESS_RESULT ();
	}

	Result res = parse_header_from_buffer (hbc->buf, &hbc->cached_header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	hbc->header_loaded = true;
	memcpy (out, &hbc->cached_header, sizeof (HBCHeader));
	return SUCCESS_RESULT ();
}

Result r2_hbc_func_count(HBC *hbc, u32 *out_count) {
	if (!hbc || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	HBCHeader header;
	Result res = r2_hbc_hdr (hbc, &header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	*out_count = header.functionCount;
	return SUCCESS_RESULT ();
}

Result r2_hbc_func_info(HBC *hbc, u32 function_id, HBCFunc *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	if (!hbc->bf || !hbc->bf->bo) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No binary object in file");
	}

	RBinObject *bo = (RBinObject *)hbc->bf->bo;
	if (!bo->symbols) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No symbols in binary");
	}

	RListIter *iter;
	RBinSymbol *sym;
	r_list_foreach (bo->symbols, iter, sym) {
		if (sym && sym->ordinal == function_id) {
			out->name = sym->name? (const char *)sym->name: "unknown";
			out->offset = sym->paddr;
			out->size = sym->size;
			out->param_count = 0;
			return SUCCESS_RESULT ();
		}
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "Function not found");
}

Result r2_hbc_str_count(HBC *hbc, u32 *out_count) {
	if (!hbc || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	HBCHeader header;
	Result res = r2_hbc_hdr (hbc, &header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	*out_count = header.stringCount;
	return SUCCESS_RESULT ();
}

Result r2_hbc_str(HBC *hbc, u32 string_id, const char **out_str) {
	if (!hbc || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	if (!hbc->bf || !hbc->bf->bo) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No binary object");
	}

	RBinObject *bo = (RBinObject *)hbc->bf->bo;
	if (!bo->strings) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No strings");
	}

	RListIter *iter;
	RBinString *str;
	r_list_foreach (bo->strings, iter, str) {
		if (str && str->ordinal == string_id) {
			*out_str = str->string;
			return SUCCESS_RESULT ();
		}
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "String not found");
}

Result r2_hbc_str_meta(HBC *hbc, u32 string_id, HBCStringMeta *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	if (!hbc->bf || !hbc->bf->bo) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No binary object");
	}

	RBinObject *bo = (RBinObject *)hbc->bf->bo;
	if (!bo->strings) {
		return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "No strings");
	}

	RListIter *iter;
	RBinString *str;
	r_list_foreach (bo->strings, iter, str) {
		if (str && str->ordinal == string_id) {
			out->offset = str->paddr;
			out->length = str->length;
			out->isUTF16 = false;
			out->kind = HERMES_STRING_KIND_STRING;
			return SUCCESS_RESULT ();
		}
	}

	return ERROR_RESULT (RESULT_ERROR_NOT_FOUND, "String not found");
}

Result r2_hbc_bytecode(HBC *hbc, u32 function_id, const u8 **out_ptr, u32 *out_size) {
	if (!hbc || !out_ptr || !out_size) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	HBCFunc info;
	Result res = r2_hbc_func_info (hbc, function_id, &info);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	if (!hbc->tmp_read_buffer || hbc->tmp_buffer_size < info.size) {
		ut8 *new_buf = (ut8 *)realloc (hbc->tmp_read_buffer, info.size);
		if (!new_buf) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
		}
		hbc->tmp_read_buffer = new_buf;
		hbc->tmp_buffer_size = info.size;
	}

	int bytes_read = r_buf_read_at (hbc->buf, info.offset, hbc->tmp_read_buffer, info.size);
	if (bytes_read != (int)info.size) {
		return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read bytecode");
	}

	*out_ptr = hbc->tmp_read_buffer;
	*out_size = info.size;
	return SUCCESS_RESULT ();
}

Result r2_hbc_str_tbl(HBC *hbc, HBCStrs *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	if (!hbc->string_tables_loaded) {
		Result res = parse_string_tables (hbc);
		if (res.code != RESULT_SUCCESS) {
			return res;
		}
	}

	*out = hbc->cached_string_tables;
	return SUCCESS_RESULT ();
}

Result r2_hbc_src(HBC *hbc, u32 function_id, const char **out_src) {
	if (!hbc || !out_src) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}
	(void)function_id;
	*out_src = NULL;
	return SUCCESS_RESULT ();
}

Result r2_hbc_read(HBC *hbc, u64 offset, u32 size, const u8 **out_ptr) {
	if (!hbc || !out_ptr) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	if (!hbc->tmp_read_buffer || hbc->tmp_buffer_size < size) {
		ut8 *new_buf = (ut8 *)realloc (hbc->tmp_read_buffer, size);
		if (!new_buf) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
		}
		hbc->tmp_read_buffer = new_buf;
		hbc->tmp_buffer_size = size;
	}

	int bytes_read = r_buf_read_at (hbc->buf, (ut64)offset, hbc->tmp_read_buffer, size);
	if (bytes_read != (int)size) {
		return ERROR_RESULT (RESULT_ERROR_READ, "Cannot read buffer");
	}

	*out_ptr = hbc->tmp_read_buffer;
	return SUCCESS_RESULT ();
}

void r2_hbc_free(HBC *hbc) {
	if (R_LIKELY (hbc)) {
		if (hbc->string_tables_loaded) {
			free ((void *)hbc->cached_string_tables.small_string_table);
			free ((void *)hbc->cached_string_tables.overflow_string_table);
		}
		free (hbc->tmp_read_buffer);
		free (hbc);
	}
}
