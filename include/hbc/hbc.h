#ifndef HBC_API_H
#define HBC_API_H

#include <hbc/common.h>

/* Public header summary (stable API independent of internal structs) */
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

/* Opaque public state */
typedef struct HBCState HBCState;

/* Backward-compatible alias */
typedef HBCState HBC;

/* Proposed new structs for API redesign */

typedef struct HBCFunctionInfo {
	const char *name; // Valid while HBC is alive
	u32 offset;
	u32 size;
	u32 param_count;
} HBCFunctionInfo;

typedef struct HBCStringTables {
	u32 string_count;
	const void *small_string_table;
	const void *overflow_string_table;
	u64 string_storage_offset;
} HBCStringTables;

typedef struct {
	char *text; // Caller must free with free ()
	u32 size;
	u8 opcode;
	bool is_jump;
	bool is_call;
	u64 jump_target;
} HBCSingleInstructionInfo;

typedef struct {
	HBCInstruction *instructions; // Caller must free with hbc_free_instructions
	u32 count;
} HBCDecodedInstructions;

typedef struct {
	u8 *buffer;
	size_t buffer_size;
	size_t bytes_written;
} HBCEncodeBuffer;

/* Callback type for retrieving comments from r2 (or other host)
 * Returns a heap-allocated string (caller frees), or NULL if no comment */
typedef char *(*HBCCommentCallback)(void *context, u64 address);

/* Callback type for retrieving flag/symbol names at an address
 * Returns a heap-allocated string (caller frees), or NULL if no flag */
typedef char *(*HBCFlagCallback)(void *context, u64 address);

typedef struct {
	bool pretty_literals; // Whether to format literals nicely
	bool suppress_comments; // Whether to omit comments
	bool show_offsets; // Whether to show statement offsets (for pd:ho)
	u64 function_base; // Base offset of current function (for absolute addresses)
	HBCCommentCallback comment_callback; // Optional callback for r2 comments
	void *comment_context; // Context passed to comment_callback
	HBCFlagCallback flag_callback; // Optional callback for r2 flag/symbol names
	void *flag_context; // Context passed to flag_callback
	// Optimization/transformation pass control
	bool skip_pass1_metadata; // Skip pass 1: metadata collection
	bool skip_pass2_transform; // Skip pass 2: code transformation
	bool skip_pass3_forin; // Skip pass 3: for-in loop parsing (structural recovery)
	bool skip_pass4_closure; // Skip pass 4: closure variable naming
	// Control flow rendering options
	bool force_dispatch; // Force switch/case dispatch loop even for linear functions
	bool inline_closures; // Inline closure definitions (default: true)
	int inline_threshold; // Max instruction count to inline (0 = no limit, -1 = no inline)
} HBCDecompileOptions;

/* Decode context for single-instruction decoding (consolidates parameters) */
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
	const HBCStringTables *string_tables;
} HBCDecodeContext;

/* Lifecycle */
Result hbc_open(const char *path, HBCState **out);
Result hbc_open_from_memory(const u8 *data, size_t size, HBCState **out);
void hbc_close(HBCState *hd);

/* Introspection */
u32 hbc_function_count(HBCState *hd);
u32 hbc_string_count(HBCState *hd);
Result hbc_get_header(HBCState *hd, HBCHeader *out);

/* Retrieve basic function info */
Result hbc_get_function_info(HBCState *hd, u32 function_id, HBCFunctionInfo *out);

/* Resolve string by index (pointer valid while hd is alive) */
Result hbc_get_string(HBCState *hd, u32 index, const char **out_str);
Result hbc_get_string_meta(HBCState *hd, u32 index, HBCStringMeta *out);

/* Get raw string table data for single-instruction decoding */
Result hbc_get_string_tables(HBCState *hd, HBCStringTables *out);
/* Optional metadata: map function_id to an associated source string (version >= 84).
 * This commonly references a string tied to the function, which can sometimes
 * encode module/container context. Returns SUCCESS with out_str=NULL if not found. */
Result hbc_get_function_source(HBCState *hd, u32 function_id, const char **out_str);

/* Function bytecode access */
Result hbc_get_function_bytecode(HBCState *hd, u32 function_id, const u8 **out_ptr, u32 *out_size);

/* Disassembly helpers - new API returns allocated strings */
Result hbc_disassemble_function(
	HBCState *hd,
	HBCDisassemblyOptions options,
	u32 function_id,
	char **out_str);

Result hbc_disassemble_all(
	HBCState *hd,
	HBCDisassemblyOptions options,
	char **out_str);

/* Legacy buffer-based API (deprecated, use hbc_disassemble_* above) */
Result hbc_disassemble_function_to_buffer(
	HBCState *hd,
	HBCDisassemblyOptions options,
	u32 function_id,
	StringBuffer *out);

Result hbc_disassemble_all_to_buffer(
	HBCState *hd,
	HBCDisassemblyOptions options,
	StringBuffer *out);

/* Decode a function into an array of HBCInstruction entries */
Result hbc_decode_function_instructions(
	HBCState *hd,
	u32 function_id,
	HBCDecodedInstructions *out);

/* Free an array returned by hbc_decode_function_instructions */
void hbc_free_instructions(HBCInstruction *insns, u32 count);

/* Decompiler APIs - new versions return allocated strings */
Result hbc_decompile_all(HBCState *hd, HBCDecompileOptions options, char **out_str);
Result hbc_decompile_function(HBCState *hd, u32 function_id, HBCDecompileOptions options, char **out_str);

/* Legacy buffer-based API (deprecated, use hbc_decompile_* above) */
Result hbc_decompile_all_to_buffer(HBCState *hd, HBCDecompileOptions options, StringBuffer *out);
Result hbc_decompile_function_to_buffer(HBCState *hd, u32 function_id, HBCDecompileOptions options, StringBuffer *out);

/* File-based convenience functions */
Result hbc_decompile_file(const char *input_file, const char *output_file);

/* r2 script generation function */
Result hbc_generate_r2_script(const char *input_file, const char *output_file);

/* Validation/report helpers */
Result hbc_validate_basic(HBCState *hd, char **out_str);

/* Legacy buffer-based validation (deprecated) */
Result hbc_validate_basic_to_buffer(HBCState *hd, StringBuffer *out);

/* Memory management for string results */

/* Minimal single-instruction disassembler (no file context) */

/*
 * Decode a single instruction using a context struct (preferred API).
 * All configuration is passed via the HBCDecodeContext struct.
 * Returns decoded info in out.
 */
Result hbc_decode(const HBCDecodeContext *ctx, HBCSingleInstructionInfo *out);

/*
 * Legacy API: Decode a single instruction from raw bytes.
 * Prefer hbc_decode () with HBCDecodeContext for new code.
 * - bytecode_version: Hermes bytecode version (e.g. 96). If 0, defaults to 96 with a warning.
 * - pc: absolute address used only to compute jump targets for pretty printing.
 * - asm_syntax: when true, renders mnemonic and operands like a CPU asm line.
 * - resolve_string_ids: when true, resolves string IDs to actual addresses using provided tables.
 * - string_ctx: string table context.
 * Returns decoded info in out.
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

/* Encoding functions */

/* Encode a single instruction from asm text to bytecode */
Result hbc_encode_instruction(
	const char *asm_line,
	u32 bytecode_version,
	HBCEncodeBuffer *out);

/* Encode multiple instructions from asm text to bytecode */
Result hbc_encode_instructions(
	const char *asm_text,
	u32 bytecode_version,
	HBCEncodeBuffer *out);

#endif /* HERMESDEC_API_H */
