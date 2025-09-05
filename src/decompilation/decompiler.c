#include "../../include/decompilation/decompiler.h"
#include "../../include/decompilation/token.h"
#include "../../include/parsers/hbc_file_parser.h"
#include "../../include/parsers/hbc_bytecode_parser.h"
#include "../../include/disassembly/hbc_disassembler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Result decompiler_init(HermesDecompiler* decompiler) {
    if (!decompiler) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler pointer");
    }
    
    decompiler->calldirect_function_ids = NULL;
    decompiler->calldirect_function_ids_count = 0;
    decompiler->calldirect_function_ids_capacity = 0;
    decompiler->indent_level = 0;
    
    // Initialize string buffer for output
    string_buffer_init(&decompiler->output, 4096);  // Start with 4KB buffer
    
    return SUCCESS_RESULT();
}

Result decompiler_cleanup(HermesDecompiler* decompiler) {
    if (!decompiler) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler pointer");
    }
    
    // Free calldirect function ids array
    if (decompiler->calldirect_function_ids) {
        free(decompiler->calldirect_function_ids);
        decompiler->calldirect_function_ids = NULL;
    }
    
    // Cleanup string buffer
    string_buffer_free(&decompiler->output);
    
    return SUCCESS_RESULT();
}

Result decompile_file(const char* input_file, const char* output_file) {
    Result result;
    HermesDecompiler decompiler;
    HBCReader reader;
    
    // Initialize structs
    result = decompiler_init(&decompiler);
    if (result.code != RESULT_SUCCESS) {
        return result;
    }
    
    result = hbc_reader_init(&reader);
    if (result.code != RESULT_SUCCESS) {
        decompiler_cleanup(&decompiler);
        return result;
    }
    
    // Store file paths
    decompiler.input_file = (char*)input_file;
    decompiler.output_file = (char*)output_file;
    decompiler.hbc_reader = &reader;
    
    // Read and parse the file
    result = hbc_reader_read_file(&reader, input_file);
    if (result.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&reader);
        decompiler_cleanup(&decompiler);
        return result;
    }
    
    // Read header
    result = hbc_reader_read_header(&reader);
    if (result.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&reader);
        decompiler_cleanup(&decompiler);
        return result;
    }
    
    // Produce decompilation into a temporary buffer, then write to file/stdout
    StringBuffer sb;
    string_buffer_init(&sb, 64 * 1024);
    result = decompile_all_to_buffer(&reader, &sb);
    if (result.code != RESULT_SUCCESS) {
        string_buffer_free(&sb);
        hbc_reader_cleanup(&reader);
        decompiler_cleanup(&decompiler);
        return result;
    }

    FILE* out = stdout;
    if (output_file) {
        out = fopen(output_file, "w");
        if (!out) {
            string_buffer_free(&sb);
            hbc_reader_cleanup(&reader);
            decompiler_cleanup(&decompiler);
            return ERROR_RESULT(RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file for writing");
        }
    }
    fputs(sb.data ? sb.data : "", out);
    if (output_file && out != stdout) {
        fclose(out);
    }
    string_buffer_free(&sb);
    
    // Cleanup
    hbc_reader_cleanup(&reader);
    decompiler_cleanup(&decompiler);
    
    return SUCCESS_RESULT();
}

/* Internal helper to emit a single function stub + disassembly comments */
static Result emit_function_stub_with_disassembly(HBCReader* reader, u32 function_id, StringBuffer* out) {
    if (!reader || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for emit_function_stub_with_disassembly");
    }
    if (function_id >= reader->header.functionCount) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Function id out of range");
    }

    FunctionHeader* fh = &reader->function_headers[function_id];
    const char* name = NULL;
    if (reader->strings && fh->functionName < reader->header.stringCount) {
        name = reader->strings[fh->functionName];
    }
    if (!name || !*name) name = "anonymous";

    // Emit function signature
    RETURN_IF_ERROR(string_buffer_append(out, "function "));
    RETURN_IF_ERROR(string_buffer_append(out, name));
    RETURN_IF_ERROR(string_buffer_append(out, "("));
    for (u32 i = 0; i < fh->paramCount; i++) {
        if (i) RETURN_IF_ERROR(string_buffer_append(out, ", "));
        char pbuf[32]; snprintf(pbuf, sizeof(pbuf), "a%u", i);
        RETURN_IF_ERROR(string_buffer_append(out, pbuf));
    }
    RETURN_IF_ERROR(string_buffer_append(out, ") {\n"));

    // Emit simple header summary
    RETURN_IF_ERROR(string_buffer_append(out, "  // id: "));
    char nbuf[64]; snprintf(nbuf, sizeof(nbuf), "%u", function_id);
    RETURN_IF_ERROR(string_buffer_append(out, nbuf));
    RETURN_IF_ERROR(string_buffer_append(out, ", offset: 0x"));
    char off[32]; snprintf(off, sizeof(off), "%x", fh->offset);
    RETURN_IF_ERROR(string_buffer_append(out, off));
    RETURN_IF_ERROR(string_buffer_append(out, ", size: "));
    char sz[32]; snprintf(sz, sizeof(sz), "%u", fh->bytecodeSizeInBytes);
    RETURN_IF_ERROR(string_buffer_append(out, sz));
    RETURN_IF_ERROR(string_buffer_append(out, " bytes\n"));

    // Use the disassembler to generate per-instruction comments
    Disassembler d;
    DisassemblyOptions opts = {0};
    RETURN_IF_ERROR(disassembler_init(&d, reader, opts));
    Result res = disassemble_function(&d, function_id);
    if (res.code == RESULT_SUCCESS) {
        // Prefix each line with "  // " inside the function body
        const char* text = d.output.data ? d.output.data : "";
        const char* cur = text;
        while (*cur) {
            const char* nl = strchr(cur, '\n');
            size_t len = nl ? (size_t)(nl - cur) : strlen(cur);
            RETURN_IF_ERROR(string_buffer_append(out, "  // "));
            if (len) {
                char* tmp = (char*)malloc(len + 1);
                if (!tmp) { disassembler_cleanup(&d); return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "OOM"); }
                memcpy(tmp, cur, len); tmp[len] = '\0';
                RETURN_IF_ERROR(string_buffer_append(out, tmp));
                free(tmp);
            }
            RETURN_IF_ERROR(string_buffer_append(out, "\n"));
            if (!nl) break;
            cur = nl + 1;
        }
    }
    disassembler_cleanup(&d);

    // Close function body
    RETURN_IF_ERROR(string_buffer_append(out, "}\n\n"));
    return SUCCESS_RESULT();
}

Result decompile_function_to_buffer(HBCReader* reader, u32 function_id, StringBuffer* out) {
    // For now emit a JS function stub with disassembly comments
    return emit_function_stub_with_disassembly(reader, function_id, out);
}

Result decompile_all_to_buffer(HBCReader* reader, StringBuffer* out) {
    if (!reader || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for decompile_all_to_buffer");
    }
    // File preamble
    RETURN_IF_ERROR(string_buffer_append(out, "// Decompiled Hermes bytecode\n"));
    RETURN_IF_ERROR(string_buffer_append(out, "// Version: "));
    char vbuf[32]; snprintf(vbuf, sizeof(vbuf), "%u", reader->header.version);
    RETURN_IF_ERROR(string_buffer_append(out, vbuf));
    RETURN_IF_ERROR(string_buffer_append(out, "\n\n"));

    for (u32 i = 0; i < reader->header.functionCount; i++) {
        RETURN_IF_ERROR(decompile_function_to_buffer(reader, i, out));
    }
    return SUCCESS_RESULT();
}

// These functions can be implemented later as needed
Result pass1_set_metadata(HermesDecompiler* state, DecompiledFunctionBody* function_body) {
    // Stub implementation
    (void)state;
    (void)function_body;
    return SUCCESS_RESULT();
}

Result pass2_transform_code(HermesDecompiler* state, DecompiledFunctionBody* function_body) {
    // Stub implementation
    (void)state;
    (void)function_body;
    return SUCCESS_RESULT();
}

Result pass3_parse_forin_loops(HermesDecompiler* state, DecompiledFunctionBody* function_body) {
    // Stub implementation
    (void)state;
    (void)function_body;
    return SUCCESS_RESULT();
}

Result pass4_name_closure_vars(HermesDecompiler* state, DecompiledFunctionBody* function_body) {
    // Stub implementation
    (void)state;
    (void)function_body;
    return SUCCESS_RESULT();
}

Result output_code(HermesDecompiler* state, DecompiledFunctionBody* function_body) {
    // Stub implementation
    (void)state;
    (void)function_body;
    return SUCCESS_RESULT();
}

Result decompile_function(HermesDecompiler* state, u32 function_id, Environment* parent_environment, 
                         int environment_id, bool is_closure, bool is_generator, bool is_async) {
    // Stub implementation
    (void)state;
    (void)function_id;
    (void)parent_environment;
    (void)environment_id;
    (void)is_closure;
    (void)is_generator;
    (void)is_async;
    return SUCCESS_RESULT();
}

Result function_body_init(DecompiledFunctionBody* body, u32 function_id, FunctionHeader* function_object, bool is_global) {
    // Stub implementation
    (void)body;
    (void)function_id;
    (void)function_object;
    (void)is_global;
    return SUCCESS_RESULT();
}

void function_body_cleanup(DecompiledFunctionBody* body) {
    // Stub implementation
    (void)body;
}

Result add_jump_target(DecompiledFunctionBody* body, u32 address) {
    // Stub implementation
    (void)body;
    (void)address;
    return SUCCESS_RESULT();
}

Result create_basic_block(DecompiledFunctionBody* body, u32 start_address, u32 end_address) {
    // Stub implementation
    (void)body;
    (void)start_address;
    (void)end_address;
    return SUCCESS_RESULT();
}
