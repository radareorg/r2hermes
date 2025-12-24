/* radare2 - LGPL - Copyright 2025 - pancake */
/* R2DataProvider: Read HBC data from r2 RBinFile without separate file I/O */

#include <r_bin.h>
#include <hbc/hbc.h>
#include <hbc/data_provider.h>
#include <hbc/common.h>
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
	rp->tmp_read_buffer = NULL;
	rp->tmp_buffer_size = 0;

	return (HBCDataProvider *)rp;
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
 * Get pre-parsed string table data.
 */
Result hbc_data_provider_get_string_tables(HBCDataProvider *provider, struct HBCStringTables *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	(void)provider; /* Unused in this basic implementation */

	/* String tables would need more detailed parsing from the binary
	 * For now, return a basic error - the decompiler can handle this
	 * and fall back to parsing strings on-demand via get_string () */
	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED,
		"String tables not yet implemented for R2DataProvider");
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

	/* Free temporary buffers */
	if (rp->tmp_read_buffer) {
		free (rp->tmp_read_buffer);
		rp->tmp_read_buffer = NULL;
	}

	/* Don't free bf, bin, buf: they are owned by r2 */
	free (rp);
}
