#include "hermesdec/hermesdec.h"
#include "../include/hermesdec/hermesdec.h"
#include "../include/hermes_encoder.h"
#include "../include/parsers/hbc_file_parser.h"
#include "../include/disassembly/hbc_disassembler.h"
#include "../include/decompilation/decompiler.h"
#include "../include/opcodes/hermes_opcodes.h"

struct HermesDec {
    HBCReader reader;
};

/* Open and fully parse a Hermes bytecode file */
Result hermesdec_open(const char* path, HermesDec** out) {
    if (!path || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_open");
    }
    
    HermesDec* hd = (HermesDec*)calloc(1, sizeof(HermesDec));
    if (!hd) {
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HermesDec");
    }

    Result res = hbc_reader_init(&hd->reader);
    if (res.code != RESULT_SUCCESS) {
        free(hd);
        return res;
    }

    res = hbc_reader_read_whole_file(&hd->reader, path);
    if (res.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&hd->reader);
        free(hd);
        return res;
    }

    *out = hd;
    return SUCCESS_RESULT();
}

/* Open and parse from an in-memory buffer */
Result hermesdec_open_from_memory(const u8* data, size_t size, HermesDec** out) {
    if (!data || size == 0 || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_open_from_memory");
    }

    HermesDec* hd = (HermesDec*)calloc(1, sizeof(HermesDec));
    if (!hd) {
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HermesDec");
    }

    Result res = hbc_reader_init(&hd->reader);
    if (res.code != RESULT_SUCCESS) {
        free(hd);
        return res;
    }

    res = buffer_reader_init_from_memory(&hd->reader.file_buffer, data, size);
    if (res.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&hd->reader);
        free(hd);
        return res;
    }

    /* Parse header and all sections */
    res = hbc_reader_read_header(&hd->reader);
    if (res.code != RESULT_SUCCESS) {
        hermesdec_close(hd);
        return res;
    }
    res = hbc_reader_read_functions_robust(&hd->reader);
    if (res.code != RESULT_SUCCESS) {
        hermesdec_close(hd);
        return res;
    }
    res = hbc_reader_read_string_kinds(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    res = hbc_reader_read_identifier_hashes(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    res = hbc_reader_read_string_tables(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    res = hbc_reader_read_arrays(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    res = hbc_reader_read_bigints(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    res = hbc_reader_read_regexp(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    res = hbc_reader_read_cjs_modules(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    res = hbc_reader_read_function_sources(&hd->reader);
    if (res.code != RESULT_SUCCESS) { hermesdec_close(hd); return res; }
    (void)hbc_reader_read_debug_info; /* Debug info optional; callers can request if needed */

    *out = hd;
    return SUCCESS_RESULT();
}

void hermesdec_close(HermesDec* hd) {
    if (!hd) return;
    hbc_reader_cleanup(&hd->reader);
    free(hd);
}

u32 hermesdec_function_count(HermesDec* hd) {
    if (!hd) return 0;
    return hd->reader.header.functionCount;
}

u32 hermesdec_string_count(HermesDec* hd) {
    if (!hd) return 0;
    return hd->reader.header.stringCount;
}

Result hermesdec_get_header(HermesDec* hd, HermesHeader* out) {
    if (!hd || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_get_header");
    }
    HBCHeader* h = &hd->reader.header;
    out->magic = h->magic;
    out->version = h->version;
    memcpy(out->sourceHash, h->sourceHash, sizeof(out->sourceHash));
    out->fileLength = h->fileLength;
    out->globalCodeIndex = h->globalCodeIndex;
    out->functionCount = h->functionCount;
    out->stringKindCount = h->stringKindCount;
    out->identifierCount = h->identifierCount;
    out->stringCount = h->stringCount;
    out->overflowStringCount = h->overflowStringCount;
    out->stringStorageSize = h->stringStorageSize;
    out->bigIntCount = h->bigIntCount;
    out->bigIntStorageSize = h->bigIntStorageSize;
    out->regExpCount = h->regExpCount;
    out->regExpStorageSize = h->regExpStorageSize;
    out->arrayBufferSize = h->arrayBufferSize;
    out->objKeyBufferSize = h->objKeyBufferSize;
    out->objValueBufferSize = h->objValueBufferSize;
    out->segmentID = h->segmentID;
    out->cjsModuleCount = h->cjsModuleCount;
    out->functionSourceCount = h->functionSourceCount;
    out->debugInfoOffset = h->debugInfoOffset;
    out->staticBuiltins = h->staticBuiltins;
    out->cjsModulesStaticallyResolved = h->cjsModulesStaticallyResolved;
    out->hasAsync = h->hasAsync;
    return SUCCESS_RESULT();
}

Result hermesdec_get_function_info(
    HermesDec* hd,
    u32 function_id,
    const char** out_name,
    u32* out_offset,
    u32* out_size,
    u32* out_param_count) {
    if (!hd) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "HermesDec handle is NULL");
    }
    HBCReader* r = &hd->reader;
    if (function_id >= r->header.functionCount || !r->function_headers) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id");
    }
    FunctionHeader* fh = &r->function_headers[function_id];
    if (out_name) {
        const char* fn = NULL;
        if (fh->functionName < r->header.stringCount && r->strings) {
            fn = r->strings[fh->functionName];
        }
        *out_name = fn ? fn : "unknown";
    }
    if (out_offset) *out_offset = fh->offset;
    if (out_size) *out_size = fh->bytecodeSizeInBytes;
    if (out_param_count) *out_param_count = fh->paramCount;
    return SUCCESS_RESULT();
}

Result hermesdec_get_string(HermesDec* hd, u32 index, const char** out_str) {
    if (!hd || !out_str) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_get_string");
    }
    HBCReader* r = &hd->reader;
    if (!r->strings || index >= r->header.stringCount) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid string index");
    }
    *out_str = r->strings[index];
    return SUCCESS_RESULT();
}

Result hermesdec_get_function_source(HermesDec* hd, u32 function_id, const char** out_str) {
    if (!hd || !out_str) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_get_function_source");
    }
    *out_str = NULL;
    HBCReader* r = &hd->reader;
    if (!r->function_sources || r->function_source_count == 0) {
        return SUCCESS_RESULT();
    }
    for (size_t i = 0; i < r->function_source_count; i++) {
        if (r->function_sources[i].function_id == function_id) {
            u32 sid = r->function_sources[i].string_id;
            if (sid < r->header.stringCount && r->strings) {
                *out_str = r->strings[sid];
            }
            break;
        }
    }
    return SUCCESS_RESULT();
}

Result hermesdec_get_string_meta(HermesDec* hd, u32 index, HermesStringMeta* out) {
    if (!hd || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_get_string_meta");
    }
    HBCReader* r = &hd->reader;
    if (index >= r->header.stringCount) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid string index");
    }
    u32 is_utf16 = r->small_string_table[index].isUTF16;
    u32 length = r->small_string_table[index].length;
    u32 off = r->small_string_table[index].offset;
    if (length == 0xFF) {
        u32 oi = off;
        off = r->overflow_string_table[oi].offset;
        length = r->overflow_string_table[oi].length;
    }
    out->isUTF16 = is_utf16 != 0;
    out->offset = r->string_storage_file_offset + off;  // Return absolute file offset
    out->length = length;
    out->kind = (HermesStringKind)(r->string_kinds ? r->string_kinds[index] : 0);
    return SUCCESS_RESULT();
}

Result hermesdec_get_string_tables(HermesDec* hd, u32* out_string_count,
                                   const void** out_small_string_table,
                                   const void** out_overflow_string_table,
                                   u64* out_string_storage_offset) {
    if (!hd || !out_string_count || !out_small_string_table || !out_overflow_string_table || !out_string_storage_offset) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_get_string_tables");
    }
    HBCReader* r = &hd->reader;
    *out_string_count = r->header.stringCount;
    *out_small_string_table = r->small_string_table;
    *out_overflow_string_table = r->overflow_string_table;
    *out_string_storage_offset = r->string_storage_file_offset;
    return SUCCESS_RESULT();
}

Result hermesdec_get_function_bytecode(HermesDec* hd, u32 function_id, const u8** out_ptr, u32* out_size) {
    if (!hd || !out_ptr || !out_size) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_get_function_bytecode");
    }
    HBCReader* r = &hd->reader;
    if (function_id >= r->header.functionCount) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id");
    }
    FunctionHeader* fh = &r->function_headers[function_id];
    if (!fh) return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "No function header");
    if (!fh->bytecode && fh->bytecodeSizeInBytes > 0) {
        /* Load bytecode slice from file buffer */
        if (fh->offset + fh->bytecodeSizeInBytes <= r->file_buffer.size) {
            fh->bytecode = (u8*)malloc(fh->bytecodeSizeInBytes);
            if (!fh->bytecode) {
                return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "OOM allocating bytecode buffer");
            }
            size_t saved = r->file_buffer.position;
            Result sr = buffer_reader_seek(&r->file_buffer, fh->offset);
            if (sr.code != RESULT_SUCCESS) {
                free(fh->bytecode); fh->bytecode = NULL;
                return sr;
            }
            sr = buffer_reader_read_bytes(&r->file_buffer, fh->bytecode, fh->bytecodeSizeInBytes);
            r->file_buffer.position = saved;
            if (sr.code != RESULT_SUCCESS) {
                free(fh->bytecode); fh->bytecode = NULL;
                return sr;
            }
        } else {
            return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Bytecode slice out of bounds");
        }
    }
    *out_ptr = fh->bytecode;
    if (out_size) *out_size = fh->bytecodeSizeInBytes;
    return SUCCESS_RESULT();
}

typedef Result (*DisasmWorkFn)(Disassembler*, void*);

static Result disassemble_into(StringBuffer* out, DisassemblyOptions options, HBCReader* r, DisasmWorkFn work, void* ctx) {
    Disassembler d;
    if (options.asm_syntax) {
        fprintf(stderr, "[hermesdec] passing asm_syntax=1 to disassembler\n");
    }
    Result res = disassembler_init(&d, r, options);
    if (res.code != RESULT_SUCCESS) return res;
    res = work(&d, ctx);
    if (res.code == RESULT_SUCCESS) {
        /* Append the disassembler output into provided buffer */
        res = string_buffer_append(out, d.output.data ? d.output.data : "");
    }
    disassembler_cleanup(&d);
    return res;
}

static Result work_disassemble_all(Disassembler* d, void* ctx) {
    (void)ctx;
    return disassemble_all_functions(d);
}

typedef struct { u32 function_id; } WorkFnCtx;

static Result work_disassemble_one(Disassembler* d, void* ctx) {
    WorkFnCtx* c = (WorkFnCtx*)ctx;
    return disassemble_function(d, c->function_id);
}

Result hermesdec_disassemble_function_to_buffer(
    HermesDec* hd,
    u32 function_id,
    DisassemblyOptions options,
    StringBuffer* out) {
    if (!hd || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_disassemble_function_to_buffer");
    }
    HBCReader* r = &hd->reader;
    WorkFnCtx c = { .function_id = function_id };
    return disassemble_into(out, options, r, work_disassemble_one, &c);
}

Result hermesdec_disassemble_all_to_buffer(
    HermesDec* hd,
    DisassemblyOptions options,
    StringBuffer* out) {
    if (!hd || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_disassemble_all_to_buffer");
    }
    HBCReader* r = &hd->reader;
    return disassemble_into(out, options, r, work_disassemble_all, NULL);
}

Result hermesdec_decompile_all_to_buffer(HermesDec* hd, StringBuffer* out) {
    if (!hd || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_decompile_all_to_buffer");
    }
    return decompile_all_to_buffer(&hd->reader, out);
}

Result hermesdec_decompile_function_to_buffer(HermesDec* hd, u32 function_id, StringBuffer* out) {
    if (!hd || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_decompile_function_to_buffer");
    }
    return decompile_function_to_buffer(&hd->reader, function_id, out);
}

Result hermesdec_decompile_file(const char* input_file, const char* output_file) {
    return decompile_file(input_file, output_file);
}

Result hermesdec_generate_r2_script(const char* input_file, const char* output_file) {
    return generate_r2_script(input_file, output_file);
}

Result hermesdec_validate_basic(HermesDec* hd, StringBuffer* out) {
    if (!hd || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_validate_basic");
    }
    HBCReader* r = &hd->reader;
    Result res = string_buffer_append(out, "Validation report:\n");
    if (res.code != RESULT_SUCCESS) return res;
    char buf[256];
    snprintf(buf, sizeof(buf), "Functions count: %u\n", r->header.functionCount);
    RETURN_IF_ERROR(string_buffer_append(out, buf));
    size_t min_bytes = (size_t)r->header.functionCount * 16;
    size_t remaining = (r->file_buffer.size > sizeof(HBCHeader)) ? (r->file_buffer.size - sizeof(HBCHeader)) : 0;
    snprintf(buf, sizeof(buf), "Bytes available after header: %zu (need >= %zu for function headers)\n", remaining, min_bytes);
    RETURN_IF_ERROR(string_buffer_append(out, buf));
    if (remaining < min_bytes) {
        RETURN_IF_ERROR(string_buffer_append(out, "Warning: file may be too small for declared function headers\n"));
    } else {
        RETURN_IF_ERROR(string_buffer_append(out, "Function headers fit in file size.\n"));
    }
    /* Dump first 16 bytes at current function data position as a hint */
    size_t saved_pos = r->file_buffer.position;
    r->file_buffer.position = sizeof(HBCHeader);
    /* Skip function headers area */
    r->file_buffer.position += (size_t)r->header.functionCount * 16;
    if (r->file_buffer.position + 16 <= r->file_buffer.size) {
        RETURN_IF_ERROR(string_buffer_append(out, "First 16 bytes at function data position: "));
        for (int i = 0; i < 16; i++) {
            snprintf(buf, sizeof(buf), "%02x ", r->file_buffer.data[r->file_buffer.position + i]);
            RETURN_IF_ERROR(string_buffer_append(out, buf));
        }
        RETURN_IF_ERROR(string_buffer_append(out, "\n"));
    }
    r->file_buffer.position = saved_pos;
    return SUCCESS_RESULT();
}

/* Build per-instruction details for a function */
Result hermesdec_decode_function_instructions(
    HermesDec* hd,
    u32 function_id,
    HermesInstruction** out_instructions,
    u32* out_count) {
    if (!hd || !out_instructions || !out_count) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hermesdec_decode_function_instructions");
    }
    HBCReader* r = &hd->reader;
    if (function_id >= r->header.functionCount) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id");
    }
    /* Ensure bytecode is loaded */
    const u8* bc = NULL; u32 bc_sz = 0;
    Result rr = hermesdec_get_function_bytecode(hd, function_id, &bc, &bc_sz);
    if (rr.code != RESULT_SUCCESS) return rr;

    ParsedInstructionList list;
    Result pr = parse_function_bytecode(r, function_id, &list);
    if (pr.code != RESULT_SUCCESS) return pr;

    HermesInstruction* arr = (HermesInstruction*)calloc(list.count, sizeof(HermesInstruction));
    if (!arr) {
        parsed_instruction_list_free(&list);
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "OOM allocating HermesInstruction array");
    }

    FunctionHeader* fh = &r->function_headers[function_id];

    for (u32 i = 0; i < list.count; i++) {
        ParsedInstruction* ins = &list.instructions[i];
        HermesInstruction* hi = &arr[i];
        hi->rel_addr = ins->original_pos;
        hi->abs_addr = fh->offset + ins->original_pos;
        hi->opcode = ins->inst->opcode;
        hi->mnemonic = ins->inst->name;
        hi->is_jump = is_jump_instruction(ins->inst->opcode);
        hi->is_call = is_call_instruction(ins->inst->opcode);

        /* Operands */
        hi->operand_count = 0;
        for (u32 j = 0; j < 6; j++) {
            if (ins->inst->operands[j].operand_type == OPERAND_TYPE_NONE) continue;
            u32 v = 0;
            switch (j) {
                case 0: v = ins->arg1; break; case 1: v = ins->arg2; break; case 2: v = ins->arg3; break;
                case 3: v = ins->arg4; break; case 4: v = ins->arg5; break; case 5: v = ins->arg6; break;
            }
            if (hi->operand_count < 6) {
                hi->operands[hi->operand_count++] = v;
            }
        }

        /* Registers accessed */
        hi->regs_count = 0;
        for (u32 j = 0; j < 6; j++) {
            OperandType t = ins->inst->operands[j].operand_type;
            if (t == OPERAND_TYPE_REG8 || t == OPERAND_TYPE_REG32) {
                u32 v = (j==0)?ins->arg1:(j==1)?ins->arg2:(j==2)?ins->arg3:(j==3)?ins->arg4:(j==4)?ins->arg5:ins->arg6;
                if (hi->regs_count < 6) hi->regs[hi->regs_count++] = v;
            }
        }

        /* References */
        hi->code_targets_count = 0;
        hi->function_ids_count = 0;
        hi->string_ids_count = 0;

        for (u32 j = 0; j < 6; j++) {
            OperandType t = ins->inst->operands[j].operand_type;
            OperandMeaning m = ins->inst->operands[j].operand_meaning;
            u32 v = (j==0)?ins->arg1:(j==1)?ins->arg2:(j==2)?ins->arg3:(j==3)?ins->arg4:(j==4)?ins->arg5:ins->arg6;

            if ((t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32) && hi->code_targets_count < 8) {
                u32 rel = ins->original_pos + v;
                if (is_jump_instruction(ins->inst->opcode)) {
                    rel = ins->original_pos + ins->inst->binary_size + v;
                }
                hi->code_targets[hi->code_targets_count++] = fh->offset + rel;
            }
            if (m == OPERAND_MEANING_FUNCTION_ID && hi->function_ids_count < 4) {
                hi->function_ids[hi->function_ids_count++] = v;
            }
            if (m == OPERAND_MEANING_STRING_ID && hi->string_ids_count < 4) {
                hi->string_ids[hi->string_ids_count++] = v;
            }
        }
        /* Switch tables as extra code targets */
        if (ins->switch_jump_table && ins->switch_jump_table_size > 0) {
            for (u32 k = 0; k < ins->switch_jump_table_size && hi->code_targets_count < 8; k++) {
                hi->code_targets[hi->code_targets_count++] = fh->offset + ins->switch_jump_table[k];
            }
        }

        /* Full decoded string */
        StringBuffer sb;
        Result sr = string_buffer_init(&sb, 256);
        if (sr.code == RESULT_SUCCESS) {
            sr = instruction_to_string(ins, &sb);
            if (sr.code == RESULT_SUCCESS && sb.data) {
                size_t len = sb.length;
                hi->text = (char*)malloc(len + 1);
                if (hi->text) {
                    memcpy(hi->text, sb.data, len);
                    hi->text[len] = '\0';
                }
            }
            string_buffer_free(&sb);
        }
    }

    parsed_instruction_list_free(&list);
    *out_instructions = arr;
    *out_count = (u32) (arr ? list.count : 0);
    return SUCCESS_RESULT();
}

void hermesdec_free_instructions(HermesInstruction* insns, u32 count) {
    if (!insns) return;
    for (u32 i = 0; i < count; i++) {
        free(insns[i].text);
    }
    free(insns);
}

/* --- Single-instruction decode (no file context) --- */

static Instruction* select_instruction_set(u32 ver, u32* out_count) {
    if (!ver) {
        fprintf(stderr, "[hermesdec] Warning: bytecode_version not specified, defaulting to v96\n");
    }
    /* For now we only expose v96 table; reuse it for nearby versions. */
    Instruction* set96 = get_instruction_set_v96(out_count);
    return set96;
}

static const Instruction* find_inst_in_set(Instruction* set, u32 count, u8 opcode) {
    if (!set) return NULL;
    if (!count) count = 256; /* full table fallback */
    for (u32 i = 0; i < count; i++) {
        if (set[i].opcode == opcode) {
            return &set[i];
        }
    }
    return NULL;
}

static void to_snake_lower_simple(const char* in, char* out, size_t outsz) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < outsz; i++) {
        char c = in[i];
        if (c >= 'A' && c <= 'Z') {
            if (j && out[j - 1] != '_') {
                out[j++] = '_';
            }
            c = (char)(c - 'A' + 'a');
        }
        out[j++] = c;
    }
    if (outsz > 0) out[j < outsz ? j : outsz - 1] = '\0';
}

Result hermesdec_decode_single_instruction(
    const u8* bytes,
    size_t len,
    u32 bytecode_version,
    u64 pc,
    bool asm_syntax,
    bool resolve_string_ids,
    u32 string_count,
    const void* small_string_table,
    const void* overflow_string_table,
    u64 string_storage_offset,
    char** out_text,
    u32* out_size,
    u8* out_opcode,
    bool* out_is_jump,
    bool* out_is_call,
    u64* out_jump_target
) {
    if (!bytes || len == 0 || !out_text || !out_size || !out_opcode || !out_is_jump || !out_is_call || !out_jump_target) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for single-instruction decode");
    }

    u32 isz = 0;
    char* text = NULL;
    *out_text = NULL;
    *out_size = 0;
    *out_opcode = 0;
    *out_is_jump = false;
    *out_is_call = false;
    *out_jump_target = 0;

    /* Fetch instruction set */
    u32 set_count = 0;
    Instruction* set = select_instruction_set(bytecode_version, &set_count);
    if (!set) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "No opcode table available");
    }

    u8 opc = bytes[0];
    const Instruction* inst = find_inst_in_set(set, set_count, opc);
    if (!inst) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Unknown opcode");
    }
    isz = inst->binary_size;
    if (len < isz) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Truncated instruction");
    }

    /* Read operands from the provided bytes */
    u32 ops[6] = {0};
    size_t pos = 1;
    for (int i = 0; i < 6; i++) {
        OperandType t = inst->operands[i].operand_type;
        if (t == OPERAND_TYPE_NONE) continue;
        switch (t) {
        case OPERAND_TYPE_REG8:
        case OPERAND_TYPE_IMM8:
        case OPERAND_TYPE_ADDR8:
            ops[i] = (pos + 1 <= len) ? bytes[pos] : 0; pos += 1; break;
        case OPERAND_TYPE_IMM16: {
            if (pos + 2 <= len) {
                u16 v = (u16)(bytes[pos] | ((u16)bytes[pos + 1] << 8));
                ops[i] = v;
            }
            pos += 2; break; }
        case OPERAND_TYPE_REG32:
        case OPERAND_TYPE_IMM32:
        case OPERAND_TYPE_ADDR32: {
            if (pos + 4 <= len) {
                u32 v = (u32)(bytes[pos] | ((u32)bytes[pos + 1] << 8) | ((u32)bytes[pos + 2] << 16) | ((u32)bytes[pos + 3] << 24));
                ops[i] = v;
            }
            pos += 4; break; }
        default: break;
        }
    }

    /* Classification */
    bool is_j = is_jump_instruction(opc);
    bool is_c = is_call_instruction(opc);
    *out_is_jump = is_j;
    *out_is_call = is_c;
    *out_opcode = opc;
    *out_size = isz;

    /* Compute primary jump target for jmp-like insns (using relative pc) */
    u64 jtg = 0;
    for (int i = 0; i < 6; i++) {
        OperandType t = inst->operands[i].operand_type;
        if (t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32) {
            /* Hermes uses rel to (pc + size) for conditional/unconditional jumps */
            u64 base = pc + (is_j ? (u64)isz : 0);
            jtg = base + (u64)ops[i];
            break;
        }
    }
    *out_jump_target = jtg;

    /* Render text */
    StringBuffer sb;
    Result sr = string_buffer_init(&sb, 128);
    if (sr.code != RESULT_SUCCESS) {
        return sr;
    }
    char mnem[64];
    if (asm_syntax) {
        to_snake_lower_simple(inst->name, mnem, sizeof(mnem));
    } else {
        /* Keep original name if not asm syntax */
        snprintf(mnem, sizeof(mnem), "%s", inst->name ? inst->name : "unk");
    }
    RETURN_IF_ERROR(string_buffer_append(&sb, mnem));

    bool first = true;
    for (int i = 0; i < 6; i++) {
        OperandType t = inst->operands[i].operand_type;
        if (t == OPERAND_TYPE_NONE) continue;
        RETURN_IF_ERROR(string_buffer_append(&sb, first ? " " : ", "));
        first = false;
        char buf[64];
        switch (t) {
        case OPERAND_TYPE_REG8:
        case OPERAND_TYPE_REG32:
            snprintf(buf, sizeof(buf), "r%u", ops[i]);
            break;
        case OPERAND_TYPE_ADDR8:
        case OPERAND_TYPE_ADDR32: {
            u64 base = pc + (is_j ? (u64)isz : 0);
            u64 abs = base + (u64)ops[i];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)abs);
            break; }
        default: {
            /* Check if this is a string ID that should be resolved */
            if (resolve_string_ids && inst->operands[i].operand_meaning == OPERAND_MEANING_STRING_ID) {
                u32 string_id = ops[i];
                u64 resolved_addr = 0;

                if (string_id < string_count && small_string_table) {
                    const StringTableEntry* entry = (const StringTableEntry*)small_string_table + string_id;
                    if (entry->length == 0xFF && overflow_string_table) {
                        /* Use overflow table */
                        const OffsetLengthPair* overflow_entry = (const OffsetLengthPair*)overflow_string_table + entry->offset;
                        resolved_addr = string_storage_offset + overflow_entry->offset;
                    } else {
                        /* Use small table */
                        resolved_addr = string_storage_offset + entry->offset;
                    }
                }

                if (resolved_addr != 0) {
                    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)resolved_addr);
                } else {
                    /* Fallback to raw ID if resolution fails */
                    snprintf(buf, sizeof(buf), "%u", ops[i]);
                }
            } else {
                snprintf(buf, sizeof(buf), "%u", ops[i]);
            }
            break; }
        }
        RETURN_IF_ERROR(string_buffer_append(&sb, buf));
    }

    /* Materialize buffer */
    size_t L = sb.length;
    text = (char*)malloc(L + 1);
    if (!text) {
        string_buffer_free(&sb);
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "OOM for output text");
    }
    memcpy(text, sb.data, L);
    text[L] = '\0';
    string_buffer_free(&sb);

    *out_text = text;
    return SUCCESS_RESULT();
}

/* Encoding functions */
Result hermesdec_encode_instruction(
    const char* asm_line,
    u32 bytecode_version,
    u8* out_buffer,
    size_t buffer_size,
    size_t* out_bytes_written
) {
    if (!asm_line || !out_buffer || !out_bytes_written) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    /* Initialize encoder */
    HermesEncoder encoder;
    Result res = hermes_encoder_init(&encoder, bytecode_version);
    if (res.code != RESULT_SUCCESS) {
        return res;
    }

    /* Parse and encode */
    EncodedInstruction instruction;
    res = hermes_encoder_parse_instruction(&encoder, asm_line, &instruction);
    if (res.code != RESULT_SUCCESS) {
        hermes_encoder_cleanup(&encoder);
        return res;
    }

    res = hermes_encoder_encode_instruction(&encoder, &instruction,
                                          out_buffer, buffer_size, out_bytes_written);

    hermes_encoder_cleanup(&encoder);
    return res;
}

Result hermesdec_encode_instructions(
    const char* asm_text,
    u32 bytecode_version,
    u8* out_buffer,
    size_t buffer_size,
    size_t* out_bytes_written
) {
    if (!asm_text || !out_buffer || !out_bytes_written) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    /* Initialize encoder */
    HermesEncoder encoder;
    Result res = hermes_encoder_init(&encoder, bytecode_version);
    if (res.code != RESULT_SUCCESS) {
        return res;
    }

    /* Encode all instructions */
    res = hermes_encoder_encode_instructions(&encoder, asm_text,
                                           out_buffer, buffer_size, out_bytes_written);

    hermes_encoder_cleanup(&encoder);
    return res;
}
