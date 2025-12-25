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

/* Disassembly options */
typedef struct {
	bool verbose; /* Show detailed metadata */
	bool output_json; /* Output in JSON format instead of text */
	bool show_bytecode; /* Show raw bytecode bytes */
	bool show_debug_info; /* Show debug information */
	bool asm_syntax; /* Output CPU-like asm syntax (mnemonic operands) */
	bool resolve_string_ids; /* Resolve string IDs to actual addresses */
} HBCDisOptions;

/* Callback types for decompilation integration with host tools (r2, IDE, etc) */
typedef char *(*HBCCommentCallback)(void *context, u64 address);
typedef char *(*HBCFlagCallback)(void *context, u64 address);

/* Decompilation options */
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
} HBCDecompOptions;

/* Per-instruction details */
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

	/* Full decoded disassembly line (heap-allocated; caller frees via hbc_free_insns) */
	char *text;
} HBCInsn;

/* ============================================================================
 * PRIMARY API: HBC
 *
 * This is the recommended interface for all libhbc consumers.
 * HBC abstracts the data source (file, memory buffer, r2 RBinFile)
 * and provides unified query and decompilation operations.
 * ============================================================================ */

/* Opaque data provider handle */
typedef struct HBC HBC;

/* ============================================================================
 * HBC Factories - Create a provider from different sources
 * ============================================================================ */

/**
 * Create a provider from a file on disk.
 * Internally opens and manages the file. Returns NULL on failure.
 */
HBC *hbc_new_file(const char *path);

/**
 * Create a provider from a memory buffer.
 * Data must remain valid for the lifetime of the provider.
 * Returns NULL on failure.
 */
HBC *hbc_new_buf(const u8 *data, size_t size);

/**
 * Create a provider from an r2 RBinFile.
 * Reads data via r2's RBuffer API (no separate file opens).
 * Returns NULL if bf is NULL or invalid.
 */
typedef struct r_bin_file_t RBinFile;
HBC *hbc_new_r2(RBinFile *bf);

/**
 * Free a provider and all associated resources.
 * After this call, all pointers returned by provider queries are invalid.
 */
void hbc_free(HBC *provider);

/* ============================================================================
 * Query Methods - Access parsed binary data
 * ============================================================================ */

/**
 * Get the HBC file header.
 */
Result hbc_hdr(
	HBC *provider,
	HBCHeader *out);

/**
 * Get the total number of functions in the binary.
 */
Result hbc_func_count(
	HBC *provider,
	u32 *out_count);

/**
 * Function metadata structure
 */
typedef struct {
	const char *name; // Valid while provider is alive; caller must not free
	u32 offset; // Bytecode offset in file
	u32 size; // Size in bytes
	u32 param_count; // Number of parameters
} HBCFunc;

/**
 * Get metadata for a specific function.
 */
Result hbc_func_info(
	HBC *provider,
	u32 function_id,
	HBCFunc *out);

/**
 * Get the total number of strings in the binary.
 */
Result hbc_str_count(
	HBC *provider,
	u32 *out_count);

/**
 * Get a string by index.
 */
Result hbc_str(
	HBC *provider,
	u32 string_id,
	const char **out_str);

/**
 * Get metadata for a string (offset, length, kind).
 */
Result hbc_str_meta(
	HBC *provider,
	u32 string_id,
	HBCStringMeta *out);

/**
 * Get the raw bytecode bytes for a function.
 */
Result hbc_bytecode(
	HBC *provider,
	u32 function_id,
	const u8 **out_ptr,
	u32 *out_size);

/**
 * String table data.
 */
typedef struct {
	u32 string_count;
	const void *small_string_table;
	const void *overflow_string_table;
	u64 string_storage_offset;
} HBCStrs;

Result hbc_str_tbl(
	HBC *provider,
	HBCStrs *out);

/**
 * Get source/module name associated with a function.
 */
Result hbc_src(
	HBC *provider,
	u32 function_id,
	const char **out_src);

/**
 * Read raw bytes from the binary at a specific offset.
 */
Result hbc_read(
	HBC *provider,
	u64 offset,
	u32 size,
	const u8 **out_ptr);

/* ============================================================================
 * Decompilation API
 * ============================================================================ */

/**
 * Decompile a specific function.
 */
Result hbc_decomp_fn(
	HBC *provider,
	u32 function_id,
	HBCDecompOptions options,
	char **out_str);

/**
 * Decompile all functions.
 */
Result hbc_decomp_all(
	HBC *provider,
	HBCDecompOptions options,
	char **out_str);

/**
 * Disassemble a specific function.
 */
Result hbc_disasm_fn(
	HBC *provider,
	u32 function_id,
	HBCDisOptions options,
	char **out_str);

/**
 * Disassemble all functions.
 */
Result hbc_disasm_all(
	HBC *provider,
	HBCDisOptions options,
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
} HBCInsnInfo;

/**
 * Function array structure
 */
typedef struct {
	HBCFunc *functions;
	u32 count;
} HBCFuncArray;

/**
 * Get all functions at once.
 */
Result hbc_all_funcs(
	HBC *provider,
	HBCFuncArray *out);

/**
 * Free function array.
 */
void hbc_free_funcs(HBCFuncArray *arr);

/**
 * Decoded instructions list
 */
typedef struct {
	HBCInsn *instructions;
	u32 count;
} HBCInsns;

/**
 * Decode a function into an array of instructions.
 */
Result hbc_decode_fn(
	HBC *provider,
	u32 function_id,
	HBCInsns *out);

/**
 * Free instruction array.
 */
void hbc_free_insns(HBCInsn *insns, u32 count);

/**
 * Encoding buffer and functions
 */
typedef struct {
	u8 *buffer;
	size_t buffer_size;
	size_t bytes_written;
} HBCEncBuf;

/* ============================================================================
 * Single-Instruction Decoding (Stateless API)
 * ============================================================================ */

/** Configuration for single-instruction decode */
typedef struct {
	/* Input data */
	const u8 *bytes; // Raw bytecode bytes
	size_t len; // Length of bytes buffer
	u64 pc; // Program counter / absolute address

	/* Configuration */
	u32 bytecode_version; // Hermes bytecode version (e.g., 96)
	bool asm_syntax; // Output CPU-like asm syntax
	bool resolve_string_ids; // Resolve string IDs to addresses

	/* String tables (optional, for string resolution) */
	const HBCStrs *string_tables;
} HBCDecodeCtx;

/**
 * Decode a single instruction using a context struct.
 */
Result hbc_dec(const HBCDecodeCtx *ctx, HBCInsnInfo *out);

/**
 * Decode a single instruction from raw bytes.
 */
Result hbc_dec_insn(
	const u8 *bytes,
	size_t len,
	u32 bytecode_version,
	u64 pc,
	bool asm_syntax,
	bool resolve_string_ids,
	const HBCStrs *string_ctx,
	HBCInsnInfo *out);

/* ============================================================================
 * Instruction Encoding
 * ============================================================================ */

/**
 * Encode a single instruction from asm text to bytecode.
 */
Result hbc_enc(
	const char *asm_line,
	u32 bytecode_version,
	HBCEncBuf *out);

/**
 * Encode multiple instructions from asm text to bytecode.
 */
Result hbc_enc_multi(
	const char *asm_text,
	u32 bytecode_version,
	HBCEncBuf *out);

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
