#ifndef LIBHBC_API_H
#define LIBHBC_API_H

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

/* Function metadata structure */
typedef struct {
	const char *name; // Valid while provider is alive; caller must not free
	u32 offset; // Bytecode offset in file
	u32 size; // Size in bytes
	u32 param_count; // Number of parameters
} HBCFunc;

/* String table data */
typedef struct {
	u32 string_count;
	const void *small_string_table;
	const void *overflow_string_table;
	u64 string_storage_offset;
} HBCStrs;

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
/* ============================================================================
 * HBC - Direct File Access API
 *
 * Low-level API for direct file access without abstraction layer.
 * These functions work directly with HBC files and provide the most
 * efficient access to the underlying data structures.
 * ============================================================================ */

/* Opaque state handle for direct file access */
typedef struct HBC HBC;

/**
 * Open an HBC file from disk.
 * Creates an HBC for direct access to file data.
 */
Result hbc_open(const char *path, HBC **out);

/**
 * Open an HBC file from memory buffer.
 * Creates an HBC for direct access to in-memory data.
 */
Result hbc_open_from_memory(const u8 *data, size_t size, HBC **out);

/**
 * Close an HBC and free all resources.
 * After this call, all pointers returned from the state are invalid.
 */
void hbc_close(HBC *hbc);

/**
 * Get the total number of functions in the HBC file.
 */
u32 hbc_function_count(HBC *hbc);

/**
 * Get the total number of strings in the HBC file.
 */
u32 hbc_string_count(HBC *hbc);

/**
 * Get the HBC file header information.
 */
Result hbc_get_header(HBC *hbc, HBCHeader *out);

/**
 * Get metadata for a specific function.
 */
Result hbc_get_function_info(HBC *hbc, u32 function_id, HBCFunc *out);

/**
 * Get a string by index.
 */
Result hbc_get_string(HBC *hbc, u32 index, const char **out_str);

/**
 * Get metadata for a string (offset, length, kind).
 */
Result hbc_get_string_meta(HBC *hbc, u32 index, HBCStringMeta *out);

/**
 * Get string table data for decoding purposes.
 */
Result hbc_get_string_tables(HBC *hbc, HBCStrs *out);

/**
 * Get source/module name associated with a function.
 */
Result hbc_get_function_source(HBC *hbc, u32 function_id, const char **out_src);

/**
 * Get the raw bytecode bytes for a function.
 */
Result hbc_get_function_bytecode(HBC *hbc, u32 function_id, const u8 **out_ptr, u32 *out_size);

/* ============================================================================
 * Decompilation API
 * ============================================================================ */

/**
 * Decompile a specific function.
 */
Result hbc_decomp_fn(
	HBC *hbc,
	u32 function_id,
	HBCDecompOptions options,
	char **out_str);

/**
 * Decompile all functions.
 */
Result hbc_decomp_all(
	HBC *hbc,
	HBCDecompOptions options,
	char **out_str);

/**
 * Disassemble a specific function.
 */
Result hbc_disasm_fn(
	HBC *hbc,
	u32 function_id,
	HBCDisOptions options,
	char **out_str);

/**
 * Disassemble all functions.
 */
Result hbc_disasm_all(
	HBC *hbc,
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
	HBC *hbc,
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
	HBC *hbc,
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

#endif /* LIBHBC_API_H */
