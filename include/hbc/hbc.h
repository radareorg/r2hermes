#ifndef HBC_API_H
#define HBC_API_H

#include <hbc/common.h>

/* ============================================================================
 * PUBLIC TYPES (Stable across library versions)
 * ============================================================================ */

/* HBC File Header */
#ifndef HBC_HEADER_DEFINED
#define HBC_HEADER_DEFINED
typedef struct HBCHeader {
	u64 magic;
	u32 version;
	u8 sourceHash[20];
	u32 fileLength;
	u32 globalCodeIndex;
	u32 functionCount;
	u32 stringKindCount;
	u32 identifierCount;
	u32 stringCount;
	u32 overflowStringCount;
	u32 stringStorageSize;
	u32 bigIntCount;
	u32 bigIntStorageSize;
	u32 regExpCount;
	u32 regExpStorageSize;
	u32 arrayBufferSize;
	u32 objKeyBufferSize;
	u32 objValueBufferSize;
	u32 segmentID;
	u32 cjsModuleCount;
	u32 functionSourceCount;
	u32 debugInfoOffset;
	bool staticBuiltins;
	bool cjsModulesStaticallyResolved;
	bool hasAsync;
} HBCHeader;
#endif

typedef enum {
	HERMES_STRING_KIND_STRING = 0,
	HERMES_STRING_KIND_IDENTIFIER = 1,
	HERMES_STRING_KIND_PREDEFINED = 2
} HBCStringKind;

typedef struct HBCStringMeta {
	bool isUTF16;
	u32 offset;
	u32 length;
	HBCStringKind kind;
} HBCStringMeta;

/* Public disassembly options (stable, decoupled from internals) */
typedef struct {
	bool verbose; /* Show detailed metadata */
	bool output_json; /* Output in JSON format instead of text */
	bool show_bytecode; /* Show raw bytecode bytes */
	bool show_debug_info; /* Show debug information */
	bool asm_syntax; /* Output CPU-like asm syntax (mnemonic operands) */
	bool resolve_string_ids; /* Resolve string IDs to actual addresses */
} HBCDisassemblyOptions;

/* Callback types for decompilation integration with host tools (r2, IDE, etc) */
typedef char *(*HBCCommentCallback)(void *context, u64 address);
typedef char *(*HBCFlagCallback)(void *context, u64 address);

/* Public decompilation options */
typedef struct {
	bool pretty_literals; /* Whether to format literals nicely */
	bool suppress_comments; /* Whether to omit comments */
	bool show_offsets; /* Whether to show statement offsets */
	u64 function_base; /* Base offset of current function (for absolute addresses) */
	HBCCommentCallback comment_callback; /* Optional callback for r2 comments */
	void *comment_context; /* Context passed to comment_callback */
	HBCFlagCallback flag_callback; /* Optional callback for r2 flag/symbol names */
	void *flag_context; /* Context passed to flag_callback */
	/* Optimization/transformation pass control */
	bool skip_pass1_metadata; /* Skip pass 1: metadata collection */
	bool skip_pass2_transform; /* Skip pass 2: code transformation */
	bool skip_pass3_forin; /* Skip pass 3: for-in loop parsing */
	bool skip_pass4_closure; /* Skip pass 4: closure variable naming */
	/* Control flow rendering options */
	bool force_dispatch; /* Force switch/case dispatch loop for linear functions */
	bool inline_closures; /* Inline closure definitions (default: true) */
	int inline_threshold; /* Max instruction count to inline (0 = no limit, -1 = no inline) */
} HBCDecompileOptions;

/* Public per-instruction details */
typedef struct {
	/* Addresses */
	u32 rel_addr; /* Offset within function bytecode */
	u32 abs_addr; /* File-absolute address (function offset + rel_addr) */

	/* Opcode identity */
	u8 opcode; /* Raw opcode byte */
	const char *mnemonic; /* Pointer to mnemonic string (lives as long as HBC) */
	bool is_jump; /* Classified as jump */
	bool is_call; /* Classified as call */

	/* Operands snapshot (raw values) */
	u32 operands[6]; /* Up to 6 operands */
	u32 operand_count; /* Number of valid operands */

	/* Registers accessed (flat list; may include dest and sources) */
	u32 regs[6];
	u32 regs_count;

	/* Referenced entities */
	u32 code_targets[8]; /* Absolute code targets (e.g., jumps) */
	u32 code_targets_count;
	u32 function_ids[4]; /* Referenced function ids */
	u32 function_ids_count;
	u32 string_ids[4]; /* Referenced string ids */
	u32 string_ids_count;

	/* Full decoded disassembly line (heap-allocated; caller frees via hbc_free_instructions) */
	char *text;
} HBCInstruction;

/* ============================================================================
 * PRIMARY API: HBCDataProvider
 * 
 * This is the recommended interface for all libhbc consumers.
 * HBCDataProvider abstracts the data source (file, memory buffer, r2 RBinFile)
 * and provides unified query and decompilation operations.
 * ============================================================================ */

/* Opaque data provider handle - PRIMARY PUBLIC INTERFACE */
typedef struct HBCDataProvider HBCDataProvider;

/* ============================================================================
 * HBCDataProvider Factories - Create a provider from different sources
 * ============================================================================ */

/**
 * Create a data provider from a file on disk.
 * Internally opens and manages the file. Returns NULL on failure.
 * RECOMMENDED for standalone tools and CLI usage.
 */
HBCDataProvider *hbc_data_provider_from_file(const char *path);

/**
 * Create a data provider from a memory buffer.
 * Data must remain valid for the lifetime of the provider.
 * Returns NULL on failure.
 * RECOMMENDED for in-memory bytecode analysis.
 */
HBCDataProvider *hbc_data_provider_from_buffer(const u8 *data, size_t size);

/**
 * Create a data provider from an r2 RBinFile.
 * Reads data via r2's RBuffer API (no separate file opens).
 * Returns NULL if bf is NULL or invalid.
 * NOTE: Only available when linked with r2 libraries.
 * RECOMMENDED for r2 plugin integration.
 */
typedef struct r_bin_file_t RBinFile;
HBCDataProvider *hbc_data_provider_from_rbinfile(RBinFile *bf);

/**
 * Free a data provider and all associated resources.
 * After this call, all pointers returned by provider queries are invalid.
 */
void hbc_data_provider_free(HBCDataProvider *provider);

/* ============================================================================
 * HBCDataProvider Query Methods - Access parsed binary data
 * ============================================================================ */

/**
 * Get the HBC file header.
 * Returns RESULT_SUCCESS if header was read successfully.
 */
Result hbc_data_provider_get_header(
	HBCDataProvider *provider,
	HBCHeader *out);

/**
 * Get the total number of functions in the binary.
 * Returns RESULT_SUCCESS on success, RESULT_ERROR_INVALID_ARGUMENT if provider is NULL.
 */
Result hbc_data_provider_get_function_count(
	HBCDataProvider *provider,
	u32 *out_count);

/**
 * Function metadata structure
 */
typedef struct HBCFunctionInfo {
	const char *name; // Valid while provider is alive; caller must not free
	u32 offset;       // Bytecode offset in file
	u32 size;         // Size in bytes
	u32 param_count;  // Number of parameters
} HBCFunctionInfo;

/**
 * Get metadata for a specific function.
 * out->name is valid while provider is alive; caller must not free.
 */
Result hbc_data_provider_get_function_info(
	HBCDataProvider *provider,
	u32 function_id,
	HBCFunctionInfo *out);

/**
 * Get the total number of strings in the binary.
 */
Result hbc_data_provider_get_string_count(
	HBCDataProvider *provider,
	u32 *out_count);

/**
 * Get a string by index (const reference, valid while provider is alive).
 * out_str should not be freed by caller.
 */
Result hbc_data_provider_get_string(
	HBCDataProvider *provider,
	u32 string_id,
	const char **out_str);

/**
 * Get metadata for a string (offset, length, kind).
 */
Result hbc_data_provider_get_string_meta(
	HBCDataProvider *provider,
	u32 string_id,
	HBCStringMeta *out);

/**
 * Get the raw bytecode bytes for a function.
 * out_ptr and out_size should not be freed; valid while provider is alive.
 */
Result hbc_data_provider_get_bytecode(
	HBCDataProvider *provider,
	u32 function_id,
	const u8 **out_ptr,
	u32 *out_size);

/**
 * Get pre-parsed string table data (small_string_table, overflow_string_table, etc).
 * Used for efficient string ID resolution during instruction decoding.
 */
typedef struct HBCStringTables {
	u32 string_count;
	const void *small_string_table;
	const void *overflow_string_table;
	u64 string_storage_offset;
} HBCStringTables;

Result hbc_data_provider_get_string_tables(
	HBCDataProvider *provider,
	HBCStringTables *out);

/**
 * Get source/module name associated with a function (optional, may be NULL).
 * Used for contextual naming in decompilation output.
 */
Result hbc_data_provider_get_function_source(
	HBCDataProvider *provider,
	u32 function_id,
	const char **out_src);

/**
 * Low-level: Read raw bytes from the binary at a specific offset.
 * Used internally for parsing variable-length structures.
 * out_ptr is valid until next provider call; do not hold references.
 */
Result hbc_data_provider_read_raw(
	HBCDataProvider *provider,
	u64 offset,
	u32 size,
	const u8 **out_ptr);

/* ============================================================================
 * HBCDataProvider Decompilation - Primary decompilation API
 * ============================================================================ */

/**
 * Decompile a specific function.
 * Returns allocated string that caller must free with free().
 */
Result hbc_data_provider_decompile_function(
	HBCDataProvider *provider,
	u32 function_id,
	HBCDecompileOptions options,
	char **out_str);

/**
 * Decompile all functions.
 * Returns allocated string that caller must free with free().
 */
Result hbc_data_provider_decompile_all(
	HBCDataProvider *provider,
	HBCDecompileOptions options,
	char **out_str);

/**
 * Disassemble a specific function.
 * Returns allocated string that caller must free with free().
 */
Result hbc_data_provider_disassemble_function(
	HBCDataProvider *provider,
	u32 function_id,
	HBCDisassemblyOptions options,
	char **out_str);

/**
 * Disassemble all functions.
 * Returns allocated string that caller must free with free().
 */
Result hbc_data_provider_disassemble_all(
	HBCDataProvider *provider,
	HBCDisassemblyOptions options,
	char **out_str);

/**
 * Single instruction decode output
 */
typedef struct {
	char *text; // Caller must free with free ()
	u32 size;
	u8 opcode;
	bool is_jump;
	bool is_call;
	u64 jump_target;
} HBCSingleInstructionInfo;

/**
 * Batch function query (convenience helper)
 */
typedef struct {
	HBCFunctionInfo *functions;  // Caller must free with hbc_free_function_array
	u32 count;
} HBCFunctionArray;

/**
 * Get all functions at once.
 * Returns array that caller must free with hbc_free_function_array.
 */
Result hbc_data_provider_get_all_functions(
	HBCDataProvider *provider,
	HBCFunctionArray *out);

/**
 * Free function array returned by hbc_data_provider_get_all_functions.
 */
void hbc_free_function_array(HBCFunctionArray *arr);

/**
 * Decoded instructions list
 */
typedef struct {
	HBCInstruction *instructions; // Caller must free with hbc_free_instructions
	u32 count;
} HBCDecodedInstructions;

/**
 * Decode a function into an array of HBCInstruction entries.
 * Works with any data provider.
 */
Result hbc_data_provider_decode_function_instructions(
	HBCDataProvider *provider,
	u32 function_id,
	HBCDecodedInstructions *out);

/**
 * Free an array returned by hbc_data_provider_decode_function_instructions.
 */
void hbc_free_instructions(HBCInstruction *insns, u32 count);

/**
 * Encoding buffer and functions
 */
typedef struct {
	u8 *buffer;
	size_t buffer_size;
	size_t bytes_written;
} HBCEncodeBuffer;

/* ============================================================================
 * Single-Instruction Decoding (Stateless API)
 * ============================================================================ */

/** Configuration for single-instruction decode */
typedef struct {
	/* Input data */
	const u8 *bytes;            // Raw bytecode bytes
	size_t len;                 // Length of bytes buffer
	u64 pc;                     // Program counter / absolute address

	/* Configuration */
	u32 bytecode_version;       // Hermes bytecode version (e.g., 96)
	bool asm_syntax;            // Output CPU-like asm syntax
	bool resolve_string_ids;    // Resolve string IDs to addresses

	/* String tables (optional, for string resolution) */
	const HBCStringTables *string_tables;
} HBCDecodeContext;

/**
 * Decode a single instruction using a context struct (preferred API).
 * All configuration is passed via the HBCDecodeContext struct.
 * Returns decoded info in out.
 */
Result hbc_decode(const HBCDecodeContext *ctx, HBCSingleInstructionInfo *out);

/**
 * Legacy API: Decode a single instruction from raw bytes.
 * DEPRECATED - use hbc_decode() with HBCDecodeContext instead.
 * - bytecode_version: Hermes bytecode version (e.g. 96). If 0, defaults to 96.
 * - pc: absolute address used to compute jump targets for pretty printing.
 * - asm_syntax: when true, renders mnemonic and operands like CPU asm.
 * - resolve_string_ids: when true, resolves string IDs to actual addresses.
 * - string_ctx: string table context.
 */
Result hbc_decode_single_instruction(
	const u8 *bytes,
	size_t len,
	u32 bytecode_version,
	u64 pc,
	bool asm_syntax,
	bool resolve_string_ids,
	const HBCStringTables *string_ctx,
	HBCSingleInstructionInfo *out);

/* ============================================================================
 * Instruction Encoding
 * ============================================================================ */

/**
 * Encode a single instruction from asm text to bytecode.
 * Returns bytecode in buffer that caller must free with free().
 */
Result hbc_encode_instruction(
	const char *asm_line,
	u32 bytecode_version,
	HBCEncodeBuffer *out);

/**
 * Encode multiple instructions from asm text to bytecode.
 * Returns bytecode in buffer that caller must free with free().
 */
Result hbc_encode_instructions(
	const char *asm_text,
	u32 bytecode_version,
	HBCEncodeBuffer *out);

/* ============================================================================
 * CLI Convenience Functions
 * ============================================================================ */

/**
 * Decompile a file and write output to another file.
 * Convenience wrapper for CLI usage.
 */
Result hbc_decompile_file(const char *input_file, const char *output_file);

/**
 * Generate an r2 script from a bytecode file.
 * Convenience wrapper for CLI usage.
 */
Result hbc_generate_r2_script(const char *input_file, const char *output_file);

#endif /* HERMESDEC_API_H */
