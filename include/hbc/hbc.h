#ifndef HBC_API_H
#define HBC_API_H

#include "../common.h"

/* Opaque handle to a parsed Hermes bytecode object */
typedef struct HBC HBC;

/* Public header summary (stable API independent of internal structs) */
#ifndef HBC_HEADER_DEFINED
#define HBC_HEADER_DEFINED
typedef struct {
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

typedef struct {
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
#define HERMES_DEC_DISASM_OPTS_DEFINED 1

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

/* Lifecycle */
Result hbc_open(const char *path, HBC **out);
Result hbc_open_from_memory(const u8 *data, size_t size, HBC **out);
void hbc_close(HBC *hd);

/* Introspection */
u32 hbc_function_count(HBC *hd);
u32 hbc_string_count(HBC *hd);
Result hbc_get_header(HBC *hd, HBCHeader *out);

/* Retrieve basic function info and name pointer (valid while hd is alive) */
Result hbc_get_function_info(
	HBC *hd,
	u32 function_id,
	const char **out_name,
	u32 *out_offset,
	u32 *out_size,
	u32 *out_param_count);

/* Resolve string by index (pointer valid while hd is alive) */
Result hbc_get_string(HBC *hd, u32 index, const char **out_str);
Result hbc_get_string_meta(HBC *hd, u32 index, HBCStringMeta *out);

/* Get raw string table data for single-instruction decoding */
Result hbc_get_string_tables(HBC *hd, u32 *out_string_count,
	const void **out_small_string_table,
	const void **out_overflow_string_table,
	u64 *out_string_storage_offset);
/* Optional metadata: map function_id to an associated source string (version >= 84).
 * This commonly references a string tied to the function, which can sometimes
 * encode module/container context. Returns SUCCESS with out_str=NULL if not found. */
Result hbc_get_function_source(HBC *hd, u32 function_id, const char **out_str);

/* Function bytecode access */
Result hbc_get_function_bytecode(HBC *hd, u32 function_id, const u8 **out_ptr, u32 *out_size);

/* Disassembly helpers that append into provided StringBuffer */
Result hbc_disassemble_function_to_buffer(
	HBC *hd,
	u32 function_id,
	HBCDisassemblyOptions options,
	StringBuffer *out);

Result hbc_disassemble_all_to_buffer(
	HBC *hd,
	HBCDisassemblyOptions options,
	StringBuffer *out);

/* Decode a function into an array of HBCInstruction entries */
Result hbc_decode_function_instructions(
	HBC *hd,
	u32 function_id,
	HBCInstruction **out_instructions,
	u32 *out_count);

/* Free an array returned by hbc_decode_function_instructions */
void hbc_free_instructions(HBCInstruction *insns, u32 count);

/* Decompiler wrappers */
/* Decompiler APIs */
/* High-level: decompile entire file into provided StringBuffer */
Result hbc_decompile_all_to_buffer(HBC *hd, StringBuffer *out);
/* High-level: decompile single function into provided StringBuffer */
Result hbc_decompile_function_to_buffer(HBC *hd, u32 function_id, StringBuffer *out);
/* Legacy convenience: decompile and write to file (kept for compatibility) */
Result hbc_decompile_file(const char *input_file, const char *output_file);

/* r2 script generation function */
Result hbc_generate_r2_script(const char *input_file, const char *output_file);

/* Validation/report helpers */
Result hbc_validate_basic(HBC *hd, StringBuffer *out);

/* Minimal single-instruction disassembler (no file context) */
/*
 * Decode a single instruction from raw bytes without loading a Hermes file.
 * - bytecode_version: Hermes bytecode version (e.g. 96). If 0, defaults to 96 with a warning.
 * - pc: absolute address used only to compute jump targets for pretty printing.
 * - asm_syntax: when true, renders mnemonic and operands like a CPU asm line.
 * - resolve_string_ids: when true, resolves string IDs to actual addresses using provided tables.
 * - string_count: number of strings in the string table.
 * - small_string_table: pointer to small string table entries.
 * - overflow_string_table: pointer to overflow string table entries.
 * - string_storage_offset: file offset where string storage begins.
 * Returns allocated text in out_text (caller must free with free ()),
 * the decoded size in out_size, and opcode/classification details.
 */
Result hbc_decode_single_instruction(
	const u8 *bytes,
	size_t len,
	u32 bytecode_version,
	u64 pc,
	bool asm_syntax,
	bool resolve_string_ids,
	u32 string_count,
	const void *small_string_table,
	const void *overflow_string_table,
	u64 string_storage_offset,
	char **out_text,
	u32 *out_size,
	u8 *out_opcode,
	bool *out_is_jump,
	bool *out_is_call,
	u64 *out_jump_target);

/* Encoding functions */

/* Encode a single instruction from asm text to bytecode */
Result hbc_encode_instruction(
	const char *asm_line,
	u32 bytecode_version,
	u8 *out_buffer,
	size_t buffer_size,
	size_t *out_bytes_written);

/* Encode multiple instructions from asm text to bytecode */
Result hbc_encode_instructions(
	const char *asm_text,
	u32 bytecode_version,
	u8 *out_buffer,
	size_t buffer_size,
	size_t *out_bytes_written);

#endif /* HERMESDEC_API_H */
