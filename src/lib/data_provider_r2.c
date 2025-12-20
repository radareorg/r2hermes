/* radare2 - LGPL - Copyright 2025 - libhbc */
/* R2DataProvider: Read HBC data from r2 RBinFile without separate file I/O */

#include <hbc/hbc.h>
#include <hbc/data_provider.h>
#include <hbc/common.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* r2 type definitions (from r2/types.h) */
typedef u8 ut8;
typedef u16 ut16;
typedef u32 ut32;
typedef u64 ut64;
typedef int8_t st8;
typedef int16_t st16;
typedef int32_t st32;
typedef int64_t st64;

/* r2 type forward declarations */
/* These are minimal declarations sufficient for the provider */
typedef struct {
	void *next;
	void *prev;
	void *data;
} RListItem;

typedef struct {
	RListItem *head;
	RListItem *tail;
	void *free;
	size_t length;
	void *pool;
} RList;

typedef RListItem RListIter;

typedef struct {
	char *name;       /* Symbol name */
	ut64 paddr;       /* Physical address (file offset) */
	ut64 vaddr;       /* Virtual address */
	ut32 size;        /* Size in bytes */
	ut32 ordinal;     /* Index/ordinal number */
	int type;         /* Symbol type */
	int bits;         /* Bits */
} RBinSymbol;

typedef struct {
	char *string;    /* Actual string content */
	ut64 paddr;      /* Physical address (offset in file) */
	ut64 vaddr;      /* Virtual address */
	ut32 length;     /* String length */
	ut32 ordinal;    /* Index/ordinal */
	int type;        /* String type */
} RBinString;

typedef struct RBinFile {
	RList *symbols;   /* List of RBinSymbol */
	RList *strings;   /* List of RBinString */
	void *rbin;       /* r2 RBin instance */
	void *buf;        /* RBuffer */
	char *file;       /* File path */
	/* ... other fields ... */
} RBinFile;

typedef struct {
	int dummy;
} RBin;

typedef struct {
	int dummy;
} RBuffer;

/* Define named structs for forward-declared types in data_provider.h */
/* This works because C allows struct to be defined multiple times if identical */
struct HBCFunctionInfo {
	const char *name;
	u32 offset;
	u32 size;
	u32 param_count;
};

struct HBCStringMeta {
	bool isUTF16;
	u32 offset;
	u32 length;
	int kind;
};

/* r2 API function declarations */
extern int r_buf_read_at(void *buf, ut64 offset, ut8 *buf_out, int size);
extern ut64 r_buf_size(void *buf);
extern ut32 r_read_le32(const ut8 *buf);
extern ut64 r_read_le64(const ut8 *buf);

/**
 * R2DataProvider reads from an r2 RBinFile without opening a separate file.
 * Data is already parsed and cached by r2's bin_hbc plugin.
 */
struct R2DataProvider {
	RBinFile *bf;              /* r2 binary file handle (not owned) */
	RBin *bin;                 /* r2 bin handle (not owned) */
	void *buf;                 /* r2 buffer for binary data (not owned) */
	
	HBCHeader cached_header;   /* Cache to avoid re-parsing */
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
HBCDataProvider *hbc_data_provider_from_rbinfile(struct RBinFile *bf) {
	if (!bf || !bf->rbin || !bf->buf) {
		return NULL;
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)malloc(sizeof(*rp));
	if (!rp) {
		return NULL;
	}

	memset(rp, 0, sizeof(*rp));
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
static Result parse_header_from_buffer(struct RBuffer *buf, HBCHeader *out) {
	if (!buf || !out) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	ut8 header_buf[256];
	if (r_buf_read_at(buf, 0, header_buf, 256) < 32) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_DATA, "Cannot read header");
	}

	/* Parse header fields at known offsets */
	/* Offset 0: magic (8 bytes, little-endian) */
	memcpy(&out->magic, header_buf + 0, 8);
	
	/* Offset 8: version (4 bytes, little-endian) */
	out->version = r_read_le32(header_buf + 8);
	
	/* Offset 12: sourceHash (20 bytes) */
	memcpy(out->sourceHash, header_buf + 12, 20);
	
	/* Offset 32: fileLength (4 bytes) */
	out->fileLength = r_read_le32(header_buf + 32);
	
	/* Offset 36: globalCodeIndex (4 bytes) */
	out->globalCodeIndex = r_read_le32(header_buf + 36);
	
	/* Offset 40: functionCount (4 bytes) */
	out->functionCount = r_read_le32(header_buf + 40);
	
	/* Offset 44: stringKindCount (4 bytes) */
	out->stringKindCount = r_read_le32(header_buf + 44);
	
	/* Offset 48: identifierCount (4 bytes) */
	out->identifierCount = r_read_le32(header_buf + 48);
	
	/* Offset 52: stringCount (4 bytes) */
	out->stringCount = r_read_le32(header_buf + 52);
	
	/* Offset 56: overflowStringCount (4 bytes) */
	out->overflowStringCount = r_read_le32(header_buf + 56);
	
	/* Offset 60: stringStorageSize (4 bytes) */
	out->stringStorageSize = r_read_le32(header_buf + 60);
	
	/* Offset 64: bigIntCount (4 bytes) */
	out->bigIntCount = r_read_le32(header_buf + 64);
	
	/* Offset 68: bigIntStorageSize (4 bytes) */
	out->bigIntStorageSize = r_read_le32(header_buf + 68);
	
	/* Offset 72: regExpCount (4 bytes) */
	out->regExpCount = r_read_le32(header_buf + 72);
	
	/* Offset 76: regExpStorageSize (4 bytes) */
	out->regExpStorageSize = r_read_le32(header_buf + 76);
	
	/* Offset 80: arrayBufferSize (4 bytes) */
	out->arrayBufferSize = r_read_le32(header_buf + 80);
	
	/* Offset 84: objKeyBufferSize (4 bytes) */
	out->objKeyBufferSize = r_read_le32(header_buf + 84);
	
	/* Offset 88: objValueBufferSize (4 bytes) */
	out->objValueBufferSize = r_read_le32(header_buf + 88);
	
	/* Offset 92: segmentID (4 bytes) */
	out->segmentID = r_read_le32(header_buf + 92);
	
	/* Offset 96: cjsModuleCount (4 bytes) */
	out->cjsModuleCount = r_read_le32(header_buf + 96);
	
	/* Offset 100: functionSourceCount (4 bytes) */
	out->functionSourceCount = r_read_le32(header_buf + 100);
	
	/* Offset 104: debugInfoOffset (4 bytes) */
	out->debugInfoOffset = r_read_le32(header_buf + 104);
	
	/* Offset 108: flags (1 byte each) */
	out->staticBuiltins = (header_buf[108] & 0x01) != 0;
	out->cjsModulesStaticallyResolved = (header_buf[108] & 0x02) != 0;
	out->hasAsync = (header_buf[108] & 0x04) != 0;

	return SUCCESS_RESULT();
}

/**
 * Get the HBC file header.
 * Caches the header on first call to avoid re-parsing.
 */
Result hbc_data_provider_get_header(
	HBCDataProvider *provider,
	struct HBCHeader *out) {
	
	if (!provider || !out) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Return cached header on subsequent calls */
	if (rp->header_loaded) {
		memcpy(out, &rp->cached_header, sizeof(HBCHeader));
		return SUCCESS_RESULT();
	}

	/* Parse header on first call */
	Result res = parse_header_from_buffer(rp->buf, &rp->cached_header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	rp->header_loaded = true;
	memcpy(out, &rp->cached_header, sizeof(HBCHeader));
	return SUCCESS_RESULT();
}

/**
 * Get the total number of functions in the binary.
 */
Result hbc_data_provider_get_function_count(
	HBCDataProvider *provider,
	u32 *out_count) {
	
	if (!provider || !out_count) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;
	
	/* Get header first */
	HBCHeader header;
	Result res = hbc_data_provider_get_header(provider, &header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	*out_count = header.functionCount;
	return SUCCESS_RESULT();
}

/**
 * Get metadata for a specific function.
 * Function data is pre-parsed by bin_hbc.c and stored in RBinFile->symbols.
 */
Result hbc_data_provider_get_function_info(
	HBCDataProvider *provider,
	u32 function_id,
	struct HBCFunctionInfo *out) {
	
	if (!provider || !out) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* RBinFile has a list of RBinSymbol entries from bin_hbc.c::symbols() */
	if (!rp->bf || !rp->bf->symbols) {
		return ERROR_RESULT(RESULT_ERROR_NOT_FOUND, "No symbols in binary");
	}

	/* Iterate symbols to find function with matching ordinal */
	RListIter *iter = NULL;
	RBinSymbol *sym = NULL;

	/* Iterate symbols to find function with matching ordinal */
	if (rp->bf->symbols) {
		RList *symbols = (RList *)rp->bf->symbols;
		RListIter *iter = symbols->head;
		
		while (iter) {
			RBinSymbol *sym = (RBinSymbol *)iter->data;
			if (sym && sym->ordinal == function_id) {
				/* Found the function */
				out->name = sym->name ? sym->name : "unknown";
				out->offset = sym->paddr;
				out->size = sym->size;
				out->param_count = 0;
				return SUCCESS_RESULT();
			}
			iter = iter->next;
		}
	}

	return ERROR_RESULT(RESULT_ERROR_NOT_FOUND, "Function not found");
}

/**
 * Get the total number of strings in the binary.
 */
Result hbc_data_provider_get_string_count(
	HBCDataProvider *provider,
	u32 *out_count) {
	
	if (!provider || !out_count) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Get header to get string count */
	HBCHeader header;
	Result res = hbc_data_provider_get_header(provider, &header);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	*out_count = header.stringCount;
	return SUCCESS_RESULT();
}

/**
 * Get a string by index.
 * String data is pre-parsed by bin_hbc.c and stored in RBinFile->strings.
 */
Result hbc_data_provider_get_string(
	HBCDataProvider *provider,
	u32 string_id,
	const char **out_str) {
	
	if (!provider || !out_str) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Strings are in rp->bf->strings (RBinString list) */
	if (!rp->bf || !rp->bf->strings) {
		return ERROR_RESULT(RESULT_ERROR_NOT_FOUND, "No strings");
	}

	RListIter *iter = NULL;
	RBinString *str = NULL;

	/* Iterate strings to find one with matching ordinal */
	if (rp->bf->strings) {
		RList *strings = (RList *)rp->bf->strings;
		RListIter *iter = strings->head;
		
		while (iter) {
			RBinString *str = (RBinString *)iter->data;
			if (str && str->ordinal == string_id) {
				*out_str = str->string;
				return SUCCESS_RESULT();
			}
			iter = iter->next;
		}
	}

	return ERROR_RESULT(RESULT_ERROR_NOT_FOUND, "String not found");
}

/**
 * Get metadata for a string (offset, length, kind).
 */
Result hbc_data_provider_get_string_meta(
	HBCDataProvider *provider,
	u32 string_id,
	struct HBCStringMeta *out) {
	
	if (!provider || !out) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	if (!rp->bf || !rp->bf->strings) {
		return ERROR_RESULT(RESULT_ERROR_NOT_FOUND, "No strings");
	}

	RListIter *iter = NULL;
	RBinString *str = NULL;

	/* Iterate strings to find metadata */
	if (rp->bf->strings) {
		RList *strings = (RList *)rp->bf->strings;
		RListIter *iter = strings->head;
		
		while (iter) {
			RBinString *str = (RBinString *)iter->data;
			if (str && str->ordinal == string_id) {
				out->offset = str->paddr;
				out->length = str->length;
				out->isUTF16 = false;   /* r2 stores UTF8 strings */
				out->kind = HERMES_STRING_KIND_STRING;
				return SUCCESS_RESULT();
			}
			iter = iter->next;
		}
	}

	return ERROR_RESULT(RESULT_ERROR_NOT_FOUND, "String not found");
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
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Get function info to find bytecode location */
	struct HBCFunctionInfo info;
	Result res = hbc_data_provider_get_function_info(provider, function_id, &info);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	/* Allocate or reallocate temporary buffer for bytecode */
	if (!rp->tmp_read_buffer || rp->tmp_buffer_size < info.size) {
		ut8 *new_buf = (ut8 *)realloc(rp->tmp_read_buffer, info.size);
		if (!new_buf) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
		}
		rp->tmp_read_buffer = new_buf;
		rp->tmp_buffer_size = info.size;
	}

	/* Read bytecode from buffer at function offset */
	int bytes_read = r_buf_read_at(rp->buf, info.offset, rp->tmp_read_buffer, info.size);
	if (bytes_read != (int)info.size) {
		return ERROR_RESULT(RESULT_ERROR_READ, "Cannot read bytecode");
	}

	*out_ptr = rp->tmp_read_buffer;
	*out_size = info.size;
	return SUCCESS_RESULT();
}

/**
 * Get pre-parsed string table data.
 */
Result hbc_data_provider_get_string_tables(
	HBCDataProvider *provider,
	struct HBCStringTables *out) {
	
	if (!provider || !out) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	(void)provider;  /* Unused in this basic implementation */

	/* String tables would need more detailed parsing from the binary
	 * For now, return a basic error - the decompiler can handle this
	 * and fall back to parsing strings on-demand via get_string() */
	return ERROR_RESULT(RESULT_ERROR_NOT_IMPLEMENTED, 
		"String tables not yet implemented for R2DataProvider");
}

/**
 * Get source/module name associated with a function (optional, may be NULL).
 */
Result hbc_data_provider_get_function_source(
	HBCDataProvider *provider,
	u32 function_id,
	const char **out_src) {
	
	if (!provider || !out_src) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	(void)function_id; /* Unused */

	/* Function source metadata is optional; return NULL if not available */
	*out_src = NULL;
	return SUCCESS_RESULT();
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
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct R2DataProvider *rp = (struct R2DataProvider *)provider;

	/* Allocate buffer if needed */
	if (!rp->tmp_read_buffer || rp->tmp_buffer_size < size) {
		ut8 *new_buf = (ut8 *)realloc(rp->tmp_read_buffer, size);
		if (!new_buf) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
		}
		rp->tmp_read_buffer = new_buf;
		rp->tmp_buffer_size = size;
	}

	/* Read directly from r2's buffer */
	int bytes_read = r_buf_read_at(rp->buf, (ut64)offset, rp->tmp_read_buffer, size);
	if (bytes_read != (int)size) {
		return ERROR_RESULT(RESULT_ERROR_READ, "Cannot read buffer");
	}

	*out_ptr = rp->tmp_read_buffer;
	return SUCCESS_RESULT();
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
		free(rp->tmp_read_buffer);
		rp->tmp_read_buffer = NULL;
	}

	/* Don't free bf, bin, buf: they are owned by r2 */
	free(rp);
}
