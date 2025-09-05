#ifndef HERMESDEC_API_H
#define HERMESDEC_API_H

#include "../common.h"

/* Opaque handle to a parsed Hermes bytecode object */
typedef struct HermesDec HermesDec;

/* Public header summary (stable API independent of internal structs) */
typedef struct {
    u64 magic;
    u32 version;
    u8  sourceHash[20];
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
} HermesHeader;

typedef enum {
    HERMES_STRING_KIND_STRING = 0,
    HERMES_STRING_KIND_IDENTIFIER = 1,
    HERMES_STRING_KIND_PREDEFINED = 2
} HermesStringKind;

typedef struct {
    bool isUTF16;
    u32 offset;
    u32 length;
    HermesStringKind kind;
} HermesStringMeta;

/* Public disassembly options (stable, decoupled from internals) */
typedef struct {
    bool verbose;           /* Show detailed metadata */
    bool output_json;       /* Output in JSON format instead of text */
    bool show_bytecode;     /* Show raw bytecode bytes */
    bool show_debug_info;   /* Show debug information */
    bool asm_syntax;        /* Output CPU-like asm syntax (mnemonic operands) */
} DisassemblyOptions;
#define HERMES_DEC_DISASM_OPTS_DEFINED 1

/* Public per-instruction details */
typedef struct {
    /* Addresses */
    u32 rel_addr;      /* Offset within function bytecode */
    u32 abs_addr;      /* File-absolute address (function offset + rel_addr) */

    /* Opcode identity */
    u8 opcode;         /* Raw opcode byte */
    const char* mnemonic; /* Pointer to mnemonic string (lives as long as HermesDec) */
    bool is_jump;      /* Classified as jump */
    bool is_call;      /* Classified as call */

    /* Operands snapshot (raw values) */
    u32 operands[6];   /* Up to 6 operands */
    u32 operand_count; /* Number of valid operands */

    /* Registers accessed (flat list; may include dest and sources) */
    u32 regs[6];
    u32 regs_count;

    /* Referenced entities */
    u32 code_targets[8];    /* Absolute code targets (e.g., jumps) */
    u32 code_targets_count;
    u32 function_ids[4];    /* Referenced function ids */
    u32 function_ids_count;
    u32 string_ids[4];      /* Referenced string ids */
    u32 string_ids_count;

    /* Full decoded disassembly line (heap-allocated; caller frees via hermesdec_free_instructions) */
    char* text;
} HermesInstruction;

/* Lifecycle */
Result hermesdec_open(const char* path, HermesDec** out);
Result hermesdec_open_from_memory(const u8* data, size_t size, HermesDec** out);
void hermesdec_close(HermesDec* hd);

/* Introspection */
u32 hermesdec_function_count(HermesDec* hd);
u32 hermesdec_string_count(HermesDec* hd);
Result hermesdec_get_header(HermesDec* hd, HermesHeader* out);

/* Retrieve basic function info and name pointer (valid while hd is alive) */
Result hermesdec_get_function_info(
    HermesDec* hd,
    u32 function_id,
    const char** out_name,
    u32* out_offset,
    u32* out_size,
    u32* out_param_count);

/* Resolve string by index (pointer valid while hd is alive) */
Result hermesdec_get_string(HermesDec* hd, u32 index, const char** out_str);
Result hermesdec_get_string_meta(HermesDec* hd, u32 index, HermesStringMeta* out);

/* Function bytecode access */
Result hermesdec_get_function_bytecode(HermesDec* hd, u32 function_id, const u8** out_ptr, u32* out_size);

/* Disassembly helpers that append into provided StringBuffer */
Result hermesdec_disassemble_function_to_buffer(
    HermesDec* hd,
    u32 function_id,
    DisassemblyOptions options,
    StringBuffer* out);

Result hermesdec_disassemble_all_to_buffer(
    HermesDec* hd,
    DisassemblyOptions options,
    StringBuffer* out);

/* Decode a function into an array of HermesInstruction entries */
Result hermesdec_decode_function_instructions(
    HermesDec* hd,
    u32 function_id,
    HermesInstruction** out_instructions,
    u32* out_count);

/* Free an array returned by hermesdec_decode_function_instructions */
void hermesdec_free_instructions(HermesInstruction* insns, u32 count);

/* Decompiler wrappers */
/* Decompiler APIs */
/* High-level: decompile entire file into provided StringBuffer */
Result hermesdec_decompile_all_to_buffer(HermesDec* hd, StringBuffer* out);
/* High-level: decompile single function into provided StringBuffer */
Result hermesdec_decompile_function_to_buffer(HermesDec* hd, u32 function_id, StringBuffer* out);
/* Legacy convenience: decompile and write to file (kept for compatibility) */
Result hermesdec_decompile_file(const char* input_file, const char* output_file);

/* r2 script generation function */
Result hermesdec_generate_r2_script(const char* input_file, const char* output_file);

/* Validation/report helpers */
Result hermesdec_validate_basic(HermesDec* hd, StringBuffer* out);

#endif /* HERMESDEC_API_H */
