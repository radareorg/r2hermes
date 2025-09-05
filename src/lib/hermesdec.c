#include "hermesdec/hermesdec.h"
#include "parsers/hbc_file_parser.h"
#include "disassembly/hbc_disassembler.h"
#include "decompilation/decompiler.h"

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
    out->offset = off;
    out->length = length;
    out->kind = (HermesStringKind)(r->string_kinds ? r->string_kinds[index] : 0);
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
