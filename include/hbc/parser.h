#ifndef LIBHBC_FILE_PARSER_H
#define LIBHBC_FILE_PARSER_H

#include <hbc/common.h>

/* Constants */
#define HEADER_MAGIC 0x1f1903c103bc1fc6ULL
#define SHA1_NUM_BYTES 20
#define MAX_FUNCTIONS 1000000
#define MAX_STRINGS 1000000

/* Enums */
typedef enum {
	STRING_KIND_STRING = 0,
	STRING_KIND_IDENTIFIER = 1,
	STRING_KIND_PREDEFINED = 2 /* Unused since version 0.3.0 */
} StringKind;

typedef enum {
	PROHIBIT_CALL = 0,
	PROHIBIT_CONSTRUCT = 1,
	PROHIBIT_NONE = 2
} ProhibitInvoke;

/* Forward declarations */
struct BytecodeModule;
typedef struct BytecodeModule BytecodeModule;

/* Header structure that varies based on bytecode version */
#ifndef HBC_HEADER_DEFINED
#define HBC_HEADER_DEFINED
typedef struct HBCHeader {
	u64 magic;
	u32 version;
	u8 sourceHash[SHA1_NUM_BYTES];
	u32 fileLength;
	u32 globalCodeIndex;
	u32 functionCount;
	u32 stringKindCount;
	u32 identifierCount;
	u32 stringCount;
	u32 overflowStringCount;
	u32 stringStorageSize;
	/* Optional fields based on version */
	u32 bigIntCount; /* >=87 */
	u32 bigIntStorageSize; /* >=87 */
	u32 regExpCount;
	u32 regExpStorageSize;
	u32 arrayBufferSize;
	u32 objKeyBufferSize;
	u32 objValueBufferSize;
	u32 segmentID; /* cjsModuleOffset before v78 */
	u32 cjsModuleCount;
	u32 functionSourceCount; /* >=84 */
	u32 debugInfoOffset;
	bool staticBuiltins;
	bool cjsModulesStaticallyResolved;
	bool hasAsync;
} HBCHeader;
#endif

/* Function header structure (small function header) */
typedef struct {
	u32 offset : 25;
	u32 paramCount : 7;

	u32 bytecodeSizeInBytes : 15;
	u32 functionName : 17;

	u32 infoOffset : 25;
	u32 frameSize : 7;

	u8 environmentSize;
	u8 highestReadCacheIndex;
	u8 highestWriteCacheIndex;

	u8 prohibitInvoke : 2;
	u8 strictMode : 1;
	u8 hasExceptionHandler : 1;
	u8 hasDebugInfo : 1;
	u8 overflowed : 1;
	u8 unused : 2;
} SmallFunctionHeader;

/* Large function header for when fields overflow */
typedef struct {
	u32 offset;
	u32 paramCount;

	u32 bytecodeSizeInBytes;
	u32 functionName;

	u32 infoOffset;
	u32 frameSize;

	u32 environmentSize;
	u8 highestReadCacheIndex;
	u8 highestWriteCacheIndex;

	u8 prohibitInvoke : 2;
	u8 strictMode : 1;
	u8 hasExceptionHandler : 1;
	u8 hasDebugInfo : 1;
	u8 overflowed : 1;
	u8 unused : 2;
} LargeFunctionHeader;

/* Combined function header with extended fields */
typedef struct {
	/* Small function header fields */
	u32 offset;
	u32 paramCount;
	u32 bytecodeSizeInBytes;
	u32 functionName;
	u32 infoOffset;
	u32 frameSize;
	u8 environmentSize;
	u8 highestReadCacheIndex;
	u8 highestWriteCacheIndex;
	u8 prohibitInvoke;
	u8 strictMode;
	u8 hasExceptionHandler;
	u8 hasDebugInfo;
	u8 overflowed;
	u8 unused;

	/* Bytes of the actual function bytecode, allocated dynamically */
	u8 *bytecode;
} FunctionHeader;

/* Exception handler info */
typedef struct {
	u32 start;
	u32 end;
	u32 target;
} ExceptionHandlerInfo;

/* Debug offsets */
typedef struct {
	u32 source_locations;
	u32 scope_desc_data;
	u32 textified_callees; /* >=91 */
} DebugOffsets;

/* String table entry (in-memory representation). On-disk it is one u32 per entry. */
typedef struct {
	u8 isUTF16; /* 1 if UTF-16, 0 if ASCII */
	u8 isIdentifier; /* Only meaningful for version < 56 */
	u32 offset; /* Absolute offset within the string storage area */
	u32 length; /* Character count (UTF-16 code units or ASCII bytes) */
} StringTableEntry;

/* Offset-length pair for various tables */
typedef struct {
	u32 offset;
	u32 length;
} OffsetLengthPair;

/* Symbol-offset pair for CJS modules */
typedef struct {
	u32 symbol_id;
	u32 offset;
} SymbolOffsetPair;

/* Function source entry */
typedef struct {
	u32 function_id;
	u32 string_id;
} FunctionSourceEntry;

/* Debug info header (version dependent) */
typedef struct {
	u32 filename_count;
	u32 filename_storage_size;
	u32 file_region_count;
	u32 scope_desc_data_offset;
	u32 textified_data_offset; /* >=91 */
	u32 string_table_offset; /* >=91 */
	u32 debug_data_size;
} DebugInfoHeader;

/* Debug file region */
typedef struct {
	u32 from_address;
	u32 filename_id;
	u32 source_mapping_id;
} DebugFileRegion;

/* Exception handler list */
typedef struct {
	ExceptionHandlerInfo *handlers;
	u32 count;
} ExceptionHandlerList;

/* Bytecode module (opcode handlers) */
struct BytecodeModule {
	u32 version;
	const char **builtin_function_names;
	u32 builtin_function_count;
	void *opcode_handlers; /* Will be cast to appropriate type */
};

/* Main HBC reader structure */
struct HBCReader {
	/* File data */
	BufferReader file_buffer;

	/* Parsed header and tables */
	HBCHeader header;

	/* Function data */
	FunctionHeader *function_headers;
	ExceptionHandlerList *function_id_to_exc_handlers;
	DebugOffsets *function_id_to_debug_offsets;

	/* String data */
	StringKind *string_kinds;
	u32 *identifier_hashes;
	StringTableEntry *small_string_table;
	OffsetLengthPair *overflow_string_table;
	char **strings;

	/* String storage base (file absolute offset) */
	u32 string_storage_file_offset;

	/* Array and object data */
	u8 *arrays;
	u8 *object_keys;
	u8 *object_values;

	/* BigInt data */
	i64 *bigint_values;
	size_t bigint_count;

	/* RegExp data */
	OffsetLengthPair *regexp_table;
	u8 *regexp_storage;
	size_t regexp_storage_size;

	/* CJS module data */
	union {
		u32 *cjs_module_ids; /* version < 77 */
		SymbolOffsetPair *cjs_modules; /* version >= 77 */
	};

	/* Function source data */
	FunctionSourceEntry *function_sources;
	size_t function_source_count;

	/* Debug info */
	DebugInfoHeader debug_info_header;
	OffsetLengthPair *debug_string_table;
	u8 *debug_string_storage;
	size_t debug_string_storage_size;
	DebugFileRegion *debug_file_regions;
	size_t debug_file_region_count;
	u8 *sources_data_storage;
	size_t sources_data_storage_size;
	u8 *scope_desc_data_storage;
	size_t scope_desc_data_storage_size;
	u8 *textified_data_storage;
	size_t textified_data_storage_size;
	u8 *string_table_storage;
	size_t string_table_storage_size;

	/* Bytecode module (contains version-specific parsers) */
	BytecodeModule *parser_module;
};

/* Function declarations */
Result _hbc_reader_init(HBCReader *reader);
Result _hbc_reader_cleanup(HBCReader *reader);
Result _hbc_reader_read_file(HBCReader *reader, const char *filename);
Result _hbc_reader_read_header(HBCReader *reader);
Result _hbc_reader_read_functions(HBCReader *reader);
Result _hbc_reader_read_functions_robust(HBCReader *reader);
Result _hbc_reader_read_string_kinds(HBCReader *reader);
Result _hbc_reader_read_identifier_hashes(HBCReader *reader);
Result _hbc_reader_read_string_tables(HBCReader *reader);
Result _hbc_reader_read_arrays(HBCReader *reader);
Result _hbc_reader_read_bigints(HBCReader *reader);
Result _hbc_reader_read_regexp(HBCReader *reader);
Result _hbc_reader_read_cjs_modules(HBCReader *reader);
Result _hbc_reader_read_function_sources(HBCReader *reader);
Result _hbc_reader_read_debug_info(HBCReader *reader);
Result _hbc_reader_read_whole_file(HBCReader *reader, const char *filename);

/* Utility functions */
const char *_hbc_string_kind_to_string(StringKind kind);
BytecodeModule *_hbc_get_bytecode_module(u32 bytecode_version);

#endif /* LIBHBC_FILE_PARSER_H */
