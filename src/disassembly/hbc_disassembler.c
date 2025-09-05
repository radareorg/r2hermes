#include "../../include/disassembly/hbc_disassembler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Initialize disassembler */
Result disassembler_init(Disassembler* disassembler, HBCReader* reader, DisassemblyOptions options) {
    if (!disassembler || !reader) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for disassembler_init");
    }
    
    disassembler->reader = reader;
    disassembler->options = options;
    if (options.asm_syntax) {
        fprintf(stderr, "[disassembler] asm_syntax=1\n");
    }
    disassembler->current_function_id = 0;
    
    return string_buffer_init(&disassembler->output, 8192);
}

/* Clean up disassembler */
void disassembler_cleanup(Disassembler* disassembler) {
    if (disassembler) {
        string_buffer_free(&disassembler->output);
    }
}

/* Print function header */
Result print_function_header(Disassembler* disassembler, FunctionHeader* function_header, u32 function_id) {
    if (!disassembler || !function_header) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for print_function_header");
    }
    
    HBCReader* reader = disassembler->reader;
    StringBuffer* output = &disassembler->output;
    bool verbose = disassembler->options.verbose;
    
    /* Get function name with validation */
    const char* function_name = "unknown";
    if (function_header->functionName < reader->header.stringCount && 
        reader->strings && reader->strings[function_header->functionName]) {
        function_name = reader->strings[function_header->functionName];
    } else if (function_header->functionName >= reader->header.stringCount) {
        fprintf(stderr, "Warning: Function #%u has invalid name index %u (max %u)\n", 
            function_id, function_header->functionName, reader->header.stringCount);
    }
    
    /* Basic function information */
    RETURN_IF_ERROR(string_buffer_append(output, "=> [Function #"));
    RETURN_IF_ERROR(string_buffer_append_int(output, function_id));
    RETURN_IF_ERROR(string_buffer_append(output, " \""));
    RETURN_IF_ERROR(string_buffer_append(output, function_name));
    RETURN_IF_ERROR(string_buffer_append(output, "\" of "));
    RETURN_IF_ERROR(string_buffer_append_int(output, function_header->bytecodeSizeInBytes));
    RETURN_IF_ERROR(string_buffer_append(output, " bytes]: "));
    RETURN_IF_ERROR(string_buffer_append_int(output, function_header->paramCount));
    RETURN_IF_ERROR(string_buffer_append(output, " params, frame size="));
    RETURN_IF_ERROR(string_buffer_append_int(output, function_header->frameSize));
    RETURN_IF_ERROR(string_buffer_append(output, ", env size="));
    RETURN_IF_ERROR(string_buffer_append_int(output, function_header->environmentSize));
    
    /* Verbose information */
    if (verbose) {
        RETURN_IF_ERROR(string_buffer_append(output, ", read index sz="));
        RETURN_IF_ERROR(string_buffer_append_int(output, function_header->highestReadCacheIndex));
        RETURN_IF_ERROR(string_buffer_append(output, ", write index sz="));
        RETURN_IF_ERROR(string_buffer_append_int(output, function_header->highestWriteCacheIndex));
        RETURN_IF_ERROR(string_buffer_append(output, ", strict="));
        RETURN_IF_ERROR(string_buffer_append(output, function_header->strictMode ? "true" : "false"));
        RETURN_IF_ERROR(string_buffer_append(output, ", exc handler="));
        RETURN_IF_ERROR(string_buffer_append(output, function_header->hasExceptionHandler ? "true" : "false"));
        RETURN_IF_ERROR(string_buffer_append(output, ", debug info="));
        RETURN_IF_ERROR(string_buffer_append(output, function_header->hasDebugInfo ? "true" : "false"));
    }
    
    /* Offset information */
    RETURN_IF_ERROR(string_buffer_append(output, " @ offset 0x"));
    char hex_offset[16];
    snprintf(hex_offset, sizeof(hex_offset), "%08x", function_header->offset);
    RETURN_IF_ERROR(string_buffer_append(output, hex_offset));
    
    /* Exception handler information */
    if (function_header->hasExceptionHandler && disassembler->options.show_debug_info) {
        RETURN_IF_ERROR(string_buffer_append(output, "\n  [Exception handlers:"));
        
        ExceptionHandlerList* exc_handlers = &reader->function_id_to_exc_handlers[function_id];
        for (u32 i = 0; i < exc_handlers->count; i++) {
            ExceptionHandlerInfo* handler = &exc_handlers->handlers[i];
            
            char hex_start[16], hex_end[16], hex_target[16];
            snprintf(hex_start, sizeof(hex_start), "%x", handler->start);
            snprintf(hex_end, sizeof(hex_end), "%x", handler->end);
            snprintf(hex_target, sizeof(hex_target), "%x", handler->target);
            
            RETURN_IF_ERROR(string_buffer_append(output, " [start=0x"));
            RETURN_IF_ERROR(string_buffer_append(output, hex_start));
            RETURN_IF_ERROR(string_buffer_append(output, ", end=0x"));
            RETURN_IF_ERROR(string_buffer_append(output, hex_end));
            RETURN_IF_ERROR(string_buffer_append(output, ", target=0x"));
            RETURN_IF_ERROR(string_buffer_append(output, hex_target));
            RETURN_IF_ERROR(string_buffer_append(output, "]"));
        }
        
        RETURN_IF_ERROR(string_buffer_append(output, " ]"));
    }
    
    /* Debug information */
    if (function_header->hasDebugInfo && disassembler->options.show_debug_info) {
        DebugOffsets* debug_offsets = &reader->function_id_to_debug_offsets[function_id];
        
        RETURN_IF_ERROR(string_buffer_append(output, "\n  [Debug offsets: "));
        RETURN_IF_ERROR(string_buffer_append(output, "source_locs=0x"));
        
        char hex_source_loc[16], hex_scope_desc[16];
        snprintf(hex_source_loc, sizeof(hex_source_loc), "%x", debug_offsets->source_locations);
        snprintf(hex_scope_desc, sizeof(hex_scope_desc), "%x", debug_offsets->scope_desc_data);
        
        RETURN_IF_ERROR(string_buffer_append(output, hex_source_loc));
        RETURN_IF_ERROR(string_buffer_append(output, ", scope_desc_data=0x"));
        RETURN_IF_ERROR(string_buffer_append(output, hex_scope_desc));
        RETURN_IF_ERROR(string_buffer_append(output, "]"));
    }
    
    /* End the function header */
    RETURN_IF_ERROR(string_buffer_append(output, "\n\n"));
    
    return SUCCESS_RESULT();
}

/* Print a single instruction */
/* Helpers for asm-syntax formatting */
static void to_snake_lower(const char* in, char* out, size_t outsz) {
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < outsz; i++) {
        char c = in[i];
        if (c >= 'A' && c <= 'Z') {
            if (i != 0 && out[j-1] != '_') {
                if (j + 1 < outsz) out[j++] = '_';
            }
            c = (char)(c - 'A' + 'a');
        }
        out[j++] = c;
    }
    if (outsz > 0) out[j < outsz ? j : outsz - 1] = '\0';
}

static Result format_operand_asm(Disassembler* d, ParsedInstruction* ins, int idx, StringBuffer* out) {
    OperandType t = ins->inst->operands[idx].operand_type;
    OperandMeaning m = ins->inst->operands[idx].operand_meaning;
    u32 v = 0;
    switch (idx) {
        case 0: v = ins->arg1; break; case 1: v = ins->arg2; break; case 2: v = ins->arg3; break;
        case 3: v = ins->arg4; break; case 4: v = ins->arg5; break; case 5: v = ins->arg6; break;
    }

    HBCReader* r = d->reader;
    FunctionHeader* fh = &r->function_headers[d->current_function_id];

    char buf[64];
    if (t == OPERAND_TYPE_REG8 || t == OPERAND_TYPE_REG32) {
        snprintf(buf, sizeof(buf), "r%u", v);
        return string_buffer_append(out, buf);
    }

    if (m == OPERAND_MEANING_FUNCTION_ID) {
        if (v < r->header.functionCount) {
            u32 off = r->function_headers[v].offset;
            snprintf(buf, sizeof(buf), "0x%x", off);
            return string_buffer_append(out, buf);
        }
        snprintf(buf, sizeof(buf), "%u", v);
        return string_buffer_append(out, buf);
    }

    if (m == OPERAND_MEANING_STRING_ID) {
        u32 off = 0;
        if (v < r->header.stringCount && r->small_string_table) {
            if (r->small_string_table[v].length == 0xFF && r->overflow_string_table) {
                u32 oi = r->small_string_table[v].offset;
                off = r->overflow_string_table[oi].offset;
            } else {
                off = r->small_string_table[v].offset;
            }
        }
        u32 abs = r->string_storage_file_offset + off;
        snprintf(buf, sizeof(buf), "0x%x", abs);
        return string_buffer_append(out, buf);
    }

    if (t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32) {
        /* local helper to detect jump-like opcodes */
        bool is_jump = false;
        switch (ins->inst->opcode) {
            case 142: case 143: case 144: case 145: case 146: case 147: case 148: case 149:
            case 150: case 151: case 152: case 153: case 154: case 155: case 156: case 157:
            case 158: case 159: case 160: case 161: case 162: case 163: case 164: case 165:
            case 166: case 167: case 168: case 169: case 170: case 171: case 172: case 173:
            case 174: case 175: case 176: case 177: case 178: case 179: case 180: case 181:
            case 182: case 183: case 184: case 185: case 186: case 187: case 188: case 189:
            case 190: case 191:
                is_jump = true; break;
            default: break;
        }
        /* For jumps, Hermes stores relative to (pc + size); convert to file-absolute */
        u32 abs_rel = ins->original_pos + (is_jump ? ins->inst->binary_size : 0) + v;
        u32 file_abs = fh->offset + abs_rel;
        snprintf(buf, sizeof(buf), "0x%x", file_abs);
        return string_buffer_append(out, buf);
    }

    /* Default: decimal immediate */
    snprintf(buf, sizeof(buf), "%u", v);
    return string_buffer_append(out, buf);
}

static Result print_instruction_asm(Disassembler* disassembler, ParsedInstruction* instruction) {
    StringBuffer* out = &disassembler->output;
    /* mnemonic */
    char mnem[64];
    to_snake_lower(instruction->inst->name, mnem, sizeof(mnem));
    RETURN_IF_ERROR(string_buffer_append(out, mnem));
    
    bool first = true;
    for (int i = 0; i < 6; i++) {
        if (instruction->inst->operands[i].operand_type == OPERAND_TYPE_NONE) continue;
        RETURN_IF_ERROR(string_buffer_append(out, first ? " " : ", "));
        first = false;
        RETURN_IF_ERROR(format_operand_asm(disassembler, instruction, i, out));
    }
    RETURN_IF_ERROR(string_buffer_append(out, "\n"));
    return SUCCESS_RESULT();
}

Result print_instruction(Disassembler* disassembler, ParsedInstruction* instruction) {
    if (!disassembler || !instruction || !instruction->inst) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for print_instruction");
    }
    
    /* Force asm path to ensure consistent output as requested */
    if (disassembler->options.asm_syntax) {
    	return print_instruction_asm(disassembler, instruction);
    }
    StringBuffer* output = &disassembler->output;
    
    /* Print instruction address */
    char hex_addr[16];
    snprintf(hex_addr, sizeof(hex_addr), "%08x", instruction->original_pos);
    RETURN_IF_ERROR(string_buffer_append(output, "==> "));
    RETURN_IF_ERROR(string_buffer_append(output, hex_addr));
    RETURN_IF_ERROR(string_buffer_append(output, ": <"));
    RETURN_IF_ERROR(string_buffer_append(output, instruction->inst->name));
    RETURN_IF_ERROR(string_buffer_append(output, ">: <"));
    
    /* Print operands */
    bool first = true;
    for (int i = 0; i < 6; i++) {
        OperandType operand_type = instruction->inst->operands[i].operand_type;
        if (operand_type == OPERAND_TYPE_NONE) {
            continue;
        }
        
        if (!first) {
            RETURN_IF_ERROR(string_buffer_append(output, ", "));
        }
        first = false;
        
        /* Get operand name */
        const char* operand_name = "Unknown";
        switch (instruction->inst->operands[i].operand_meaning) {
            case OPERAND_MEANING_NONE:
                switch (operand_type) {
                    case OPERAND_TYPE_REG8:
                    case OPERAND_TYPE_REG32:
                        operand_name = "Reg";
                        break;
                    case OPERAND_TYPE_IMM8:
                    case OPERAND_TYPE_IMM16:
                    case OPERAND_TYPE_IMM32:
                        operand_name = "Imm";
                        break;
                    case OPERAND_TYPE_ADDR8:
                    case OPERAND_TYPE_ADDR32:
                        operand_name = "Addr";
                        break;
                    default:
                        operand_name = "Unknown";
                        break;
                }
                break;
            case OPERAND_MEANING_STRING_ID:
                operand_name = "string_id";
                break;
            case OPERAND_MEANING_BIGINT_ID:
                operand_name = "bigint_id";
                break;
            case OPERAND_MEANING_FUNCTION_ID:
                operand_name = "function_id";
                break;
            case OPERAND_MEANING_BUILTIN_ID:
                operand_name = "builtin_id";
                break;
            case OPERAND_MEANING_ARRAY_ID:
                operand_name = "array_id";
                break;
            case OPERAND_MEANING_OBJ_KEY_ID:
                operand_name = "obj_key_id";
                break;
            case OPERAND_MEANING_OBJ_VAL_ID:
                operand_name = "obj_val_id";
                break;
        }
        
        /* Print operand name and value */
        RETURN_IF_ERROR(string_buffer_append(output, operand_name));
        RETURN_IF_ERROR(string_buffer_append(output, ": "));
        
        /* Get operand value */
        u32 value;
        switch (i) {
            case 0: value = instruction->arg1; break;
            case 1: value = instruction->arg2; break;
            case 2: value = instruction->arg3; break;
            case 3: value = instruction->arg4; break;
            case 4: value = instruction->arg5; break;
            case 5: value = instruction->arg6; break;
            default: value = 0;
        }
        
        /* Print operand value */
        RETURN_IF_ERROR(string_buffer_append_int(output, value));
    }
    
    RETURN_IF_ERROR(string_buffer_append(output, ">"));
    
    /* Add comments for special operands */
    HBCReader* reader = disassembler->reader;
    
    for (int i = 0; i < 6; i++) {
        OperandMeaning operand_meaning = instruction->inst->operands[i].operand_meaning;
        if (operand_meaning == OPERAND_MEANING_NONE) {
            continue;
        }
        
        u32 value;
        switch (i) {
            case 0: value = instruction->arg1; break;
            case 1: value = instruction->arg2; break;
            case 2: value = instruction->arg3; break;
            case 3: value = instruction->arg4; break;
            case 4: value = instruction->arg5; break;
            case 5: value = instruction->arg6; break;
            default: value = 0;
        }
        
        switch (operand_meaning) {
            case OPERAND_MEANING_STRING_ID:
                if (value < reader->header.stringCount && 
                    reader->strings && reader->strings[value]) {
                    RETURN_IF_ERROR(string_buffer_append(output, "  # String: \""));
                    RETURN_IF_ERROR(string_buffer_append(output, reader->strings[value]));
                    RETURN_IF_ERROR(string_buffer_append(output, "\" ("));
                    if (value < reader->header.stringCount && reader->string_kinds) {
                        RETURN_IF_ERROR(string_buffer_append(output, string_kind_to_string(reader->string_kinds[value])));
                    } else {
                        RETURN_IF_ERROR(string_buffer_append(output, "Unknown"));
                    }
                    RETURN_IF_ERROR(string_buffer_append(output, ")"));
                }
                break;
                
            case OPERAND_MEANING_BIGINT_ID:
                if (value < reader->bigint_count) {
                    RETURN_IF_ERROR(string_buffer_append(output, "  # BigInt: "));
                    RETURN_IF_ERROR(string_buffer_append_int(output, reader->bigint_values[value]));
                }
                break;
                
            case OPERAND_MEANING_FUNCTION_ID:
                if (value < reader->header.functionCount && reader->function_headers) {
                    FunctionHeader* func = &reader->function_headers[value];
                    const char* func_name = "unknown";
                    if (func->functionName < reader->header.stringCount && 
                        reader->strings && reader->strings[func->functionName]) {
                        func_name = reader->strings[func->functionName];
                    }
                    
                    RETURN_IF_ERROR(string_buffer_append(output, "  # Function: [#"));
                    RETURN_IF_ERROR(string_buffer_append_int(output, value));
                    RETURN_IF_ERROR(string_buffer_append(output, " "));
                    RETURN_IF_ERROR(string_buffer_append(output, func_name));
                    RETURN_IF_ERROR(string_buffer_append(output, " of "));
                    RETURN_IF_ERROR(string_buffer_append_int(output, func->bytecodeSizeInBytes));
                    RETURN_IF_ERROR(string_buffer_append(output, " bytes]: "));
                    RETURN_IF_ERROR(string_buffer_append_int(output, func->paramCount));
                    RETURN_IF_ERROR(string_buffer_append(output, " params @ offset 0x"));
                    
                    char hex_offset[16];
                    snprintf(hex_offset, sizeof(hex_offset), "%08x", func->offset);
                    RETURN_IF_ERROR(string_buffer_append(output, hex_offset));
                }
                break;
                
            case OPERAND_MEANING_BUILTIN_ID:
                /* We'll implement this later when we have builtin function tables */
                break;
                
            default:
                break;
        }
    }
    
    /* Add address comments for address operands */
    for (int i = 0; i < 6; i++) {
        OperandType operand_type = instruction->inst->operands[i].operand_type;
        if (operand_type != OPERAND_TYPE_ADDR8 && operand_type != OPERAND_TYPE_ADDR32) {
            continue;
        }
        
        u32 value;
        switch (i) {
            case 0: value = instruction->arg1; break;
            case 1: value = instruction->arg2; break;
            case 2: value = instruction->arg3; break;
            case 3: value = instruction->arg4; break;
            case 4: value = instruction->arg5; break;
            case 5: value = instruction->arg6; break;
            default: value = 0;
        }
        
        RETURN_IF_ERROR(string_buffer_append(output, "  # Address: "));
        
        char hex_addr[16];
        snprintf(hex_addr, sizeof(hex_addr), "%08x", instruction->original_pos + value);
        RETURN_IF_ERROR(string_buffer_append(output, hex_addr));
    }
    
    /* Add jump table comment for switch instructions */
    if (strcmp(instruction->inst->name, "SwitchImm") == 0) {
        if (instruction->switch_jump_table && instruction->switch_jump_table_size > 0) {
            RETURN_IF_ERROR(string_buffer_append(output, "  # Jump table: ["));
            
            for (u32 i = 0; i < instruction->switch_jump_table_size; i++) {
                if (i > 0) {
                    RETURN_IF_ERROR(string_buffer_append(output, ", "));
                }
                
                char hex_addr[16];
                snprintf(hex_addr, sizeof(hex_addr), "%08x", instruction->switch_jump_table[i]);
                RETURN_IF_ERROR(string_buffer_append(output, hex_addr));
            }
            
            RETURN_IF_ERROR(string_buffer_append(output, "]"));
        }
    }
    
    /* End the instruction */
    RETURN_IF_ERROR(string_buffer_append(output, "\n"));
    
    return SUCCESS_RESULT();
}

/* Disassemble a single function */
Result disassemble_function(Disassembler* disassembler, u32 function_id) {
    if (!disassembler) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Disassembler is NULL");
    }
    
    HBCReader* reader = disassembler->reader;
    
    if (function_id >= reader->header.functionCount) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid function ID");
    }
    
    /* Print function header */
    FunctionHeader* function_header = &reader->function_headers[function_id];
    disassembler->current_function_id = function_id;
    RETURN_IF_ERROR(print_function_header(disassembler, function_header, function_id));
    
    /* Print bytecode listing header */
    if (disassembler->options.asm_syntax) {
        RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "Bytecode listing (asm):\n\n"));
    } else {
        RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "Bytecode listing:\n\n"));
    }
    
    /* Debug mode - always show function offset info */
    const char* debug_func_name = "unknown";
    if (function_header->functionName < reader->header.stringCount && 
        reader->strings && reader->strings[function_header->functionName]) {
        debug_func_name = reader->strings[function_header->functionName];
    }
    
    fprintf(stderr, "Function #%u: name=%s, offset=0x%08x, size=%u\n",
           function_id, debug_func_name, function_header->offset, 
           function_header->bytecodeSizeInBytes);
           
    /* Only try to fetch bytecode if we don't have it yet but have valid size & offset */
    if (function_header->bytecodeSizeInBytes > 0 && !function_header->bytecode) {
        /* Skip functions with suspicious sizes */
        if (function_header->bytecodeSizeInBytes > 1024 * 1024) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, 
                "[Skipping function with unreasonably large bytecode size]\n"));
            return SUCCESS_RESULT();
        }
        
        /* Skip functions with offset 0 (likely invalid) */
        if (function_header->offset == 0) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, 
                "[No bytecode available for this function (invalid offset)]\n"));
            return SUCCESS_RESULT();
        }
        
        /* Verify offset is within file bounds */
        if (function_header->offset >= reader->file_buffer.size) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, 
                "[Bytecode offset beyond file size]\n"));
            return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Bytecode offset beyond file size");
        }
        
        /* Verify we can read the full bytecode from the file */
        if (function_header->offset + function_header->bytecodeSizeInBytes > reader->file_buffer.size) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, 
                "[Bytecode extends beyond file size, truncating]\n"));
            function_header->bytecodeSizeInBytes = reader->file_buffer.size - function_header->offset;
        }
        
        /* Allocate bytecode buffer */
        function_header->bytecode = (u8*)malloc(function_header->bytecodeSizeInBytes);
        if (!function_header->bytecode) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "[Memory allocation failed for bytecode]\n"));
            return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate bytecode buffer");
        }
        
        /* Save current position */
        size_t saved_pos = reader->file_buffer.position;
        
        /* Seek to bytecode offset */
        Result seek_result = buffer_reader_seek(&reader->file_buffer, function_header->offset);
        if (seek_result.code != RESULT_SUCCESS) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "[Failed to seek to bytecode location]\n"));
            free(function_header->bytecode);
            function_header->bytecode = NULL;
            return seek_result;
        }
        
        /* Read bytecode data */
        Result read_result = buffer_reader_read_bytes(&reader->file_buffer, 
                                                 function_header->bytecode, 
                                                 function_header->bytecodeSizeInBytes);
        
        /* Restore original position */
        buffer_reader_seek(&reader->file_buffer, saved_pos);
        
        if (read_result.code != RESULT_SUCCESS) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "[Failed to read bytecode data]\n"));
            free(function_header->bytecode);
            function_header->bytecode = NULL;
            return read_result;
        }
        
        /* Verify the first byte looks like a valid opcode */
        if (function_header->bytecodeSizeInBytes > 0) {
            u8 first_opcode = function_header->bytecode[0];
            if (first_opcode == 0 || first_opcode > 0xA2) { // Using known opcode range
                RETURN_IF_ERROR(string_buffer_append(&disassembler->output, 
                    "[Warning: First byte doesn't look like a valid opcode]\n"));
            }
        }
    }
    
    /* Parse the bytecode */
    ParsedInstructionList instructions;
    Result result = parse_function_bytecode(reader, function_id, &instructions);
    
    if (result.code != RESULT_SUCCESS) {
        /* Handle parsing error - Print more debug info */
        char debug_info[256];
        snprintf(debug_info, sizeof(debug_info), 
                "[Error parsing bytecode for function #%u: %s - Offset: %u, Size: %u]\n", 
                function_id, result.error_message[0] != '\0' ? result.error_message : "Unknown error",
                function_header->offset, function_header->bytecodeSizeInBytes);
                
        RETURN_IF_ERROR(string_buffer_append(&disassembler->output, debug_info));
        
        /* Skip this function but continue with others */
        return SUCCESS_RESULT();
    } else {
        /* Print raw bytecode if requested */
        if (disassembler->options.show_bytecode) {
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "Raw bytecode: "));
            for (u32 i = 0; i < function_header->bytecodeSizeInBytes; i++) {
                char hex[8];
                snprintf(hex, sizeof(hex), "%02x ", function_header->bytecode[i]);
                RETURN_IF_ERROR(string_buffer_append(&disassembler->output, hex));
                
                /* Line break every 16 bytes */
                if ((i + 1) % 16 == 0 && i + 1 < function_header->bytecodeSizeInBytes) {
                    RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "\n               "));
                }
            }
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "\n\n"));
        }
        
        /* Print instructions */
        for (u32 i = 0; i < instructions.count; i++) {
            ParsedInstruction* instruction = &instructions.instructions[i];
            if (disassembler->options.asm_syntax) {
                RETURN_IF_ERROR(print_instruction_asm(disassembler, instruction));
            } else {
                RETURN_IF_ERROR(print_instruction(disassembler, instruction));
            }
        }
        
        /* Free instruction list */
        parsed_instruction_list_free(&instructions);
    }
    
    /* End the function disassembly */
    RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "\n\n"));
    RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "===============\n\n"));
    
    return SUCCESS_RESULT();
}

/* Disassemble all functions */
Result disassemble_all_functions(Disassembler* disassembler) {
    if (!disassembler) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Disassembler is NULL");
    }
    
    HBCReader* reader = disassembler->reader;
    
    /* Try to disassemble global function (index 0) first, since Python does this */
    if (reader->header.functionCount > 0) {
        Result result = disassemble_function(disassembler, 0);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Warning: Failed to disassemble global function: %s\n", 
                   result.error_message[0] != '\0' ? result.error_message : "Unknown error");
        }
    }
    
    /* Disassemble each remaining function, ignoring errors */
    for (u32 i = 1; i < reader->header.functionCount; i++) {
        Result result = disassemble_function(disassembler, i);
        if (result.code != RESULT_SUCCESS) {
            /* Just log and continue with next function */
            fprintf(stderr, "Warning: Failed to disassemble function #%u: %s\n", 
                   i, result.error_message[0] != '\0' ? result.error_message : "Unknown error");
        }
    }
    
    return SUCCESS_RESULT();
}

/* Output disassembly to file or stdout */
Result output_disassembly(Disassembler* disassembler, const char* output_file) {
    if (!disassembler) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Disassembler is NULL");
    }
    
    FILE* out = stdout;
    
    /* Open output file if specified */
    if (output_file) {
        out = fopen(output_file, "w");
        if (!out) {
            return ERROR_RESULT(RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file");
        }
    }
    
    /* Write the output */
    fputs(disassembler->output.data, out);
    
    /* Close the file if we opened it */
    if (output_file) {
        fclose(out);
        printf("\n[+] Disassembly output wrote to \"%s\"\n\n", output_file);
    }
    
    return SUCCESS_RESULT();
}

/* Disassemble a file */
Result disassemble_file(const char* input_file, const char* output_file, DisassemblyOptions options) {
    if (!input_file) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Input file is NULL");
    }
    
    /* Initialize HBC reader */
    HBCReader reader;
    Result result = hbc_reader_init(&reader);
    if (result.code != RESULT_SUCCESS) {
        return result;
    }
    
    /* Read the whole file */
    result = hbc_reader_read_whole_file(&reader, input_file);
    if (result.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Initialize disassembler */
    Disassembler disassembler;
    result = disassembler_init(&disassembler, &reader, options);
    if (result.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Disassemble all functions */
    result = disassemble_all_functions(&disassembler);
    if (result.code != RESULT_SUCCESS) {
        disassembler_cleanup(&disassembler);
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Output the disassembly */
    result = output_disassembly(&disassembler, output_file);
    
    /* Clean up */
    disassembler_cleanup(&disassembler);
    hbc_reader_cleanup(&reader);
    
    return result;
}

/* Disassemble a buffer */
Result disassemble_buffer(const u8* buffer, size_t size, const char* output_file, DisassemblyOptions options) {
    if (!buffer || size == 0) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid buffer");
    }
    
    /* Initialize HBC reader */
    HBCReader reader;
    Result result = hbc_reader_init(&reader);
    if (result.code != RESULT_SUCCESS) {
        return result;
    }
    
    /* Initialize buffer reader */
    result = buffer_reader_init_from_memory(&reader.file_buffer, buffer, size);
    if (result.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Read header */
    result = hbc_reader_read_header(&reader);
    if (result.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Continue parsing the file */
    /* (This is a simplified version - we should call all the individual read_ functions) */
    
    /* Initialize disassembler */
    Disassembler disassembler;
    result = disassembler_init(&disassembler, &reader, options);
    if (result.code != RESULT_SUCCESS) {
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Disassemble all functions */
    result = disassemble_all_functions(&disassembler);
    if (result.code != RESULT_SUCCESS) {
        disassembler_cleanup(&disassembler);
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Output the disassembly */
    result = output_disassembly(&disassembler, output_file);
    
    /* Clean up */
    disassembler_cleanup(&disassembler);
    hbc_reader_cleanup(&reader);
    
    return result;
}

/* Generate r2 script with function flags - robust version inspired by the Python implementation */
Result generate_r2_script(const char* input_file, const char* output_file) {
    if (!input_file) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Input file is NULL");
    }
    
    /* Initialize HBC reader */
    HBCReader reader;
    Result result = hbc_reader_init(&reader);
    if (result.code != RESULT_SUCCESS) {
        return result;
    }
    
    /* Read and parse the file */
    result = hbc_reader_read_file(&reader, input_file);
    if (result.code != RESULT_SUCCESS) {
        fprintf(stderr, "Error reading file: %s\n", result.error_message);
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Parse header and function info */
    result = hbc_reader_read_header(&reader);
    if (result.code != RESULT_SUCCESS) {
        fprintf(stderr, "Error reading header: %s\n", result.error_message);
        hbc_reader_cleanup(&reader);
        return result;
    }
    
    /* Open output file early so we can at least output basic info even if function parsing fails */
    FILE* out = stdout;
    if (output_file) {
        out = fopen(output_file, "w");
        if (!out) {
            fprintf(stderr, "Error opening output file: %s\n", output_file);
            hbc_reader_cleanup(&reader);
            return ERROR_RESULT(RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file");
        }
    }
    
    /* Generate r2 script header */
    fprintf(out, "# R2 script for Hermes bytecode file: %s\n", input_file);
    fprintf(out, "# Generated by hermes-dec\n\n");
    
    /* Add basic file info as comments */
    fprintf(out, "# Hermes File Version: %u\n", reader.header.version);
    fprintf(out, "# File Size: %u bytes\n", reader.header.fileLength);
    fprintf(out, "# Function Count: %u\n\n", reader.header.functionCount);
    
    /* Create flag for HBC header */
    fprintf(out, "# Basic file structure flags\n");
    fprintf(out, "f hbc.header=0x0\n");
    fprintf(out, "f hbc.header.size=0x%lx\n", (unsigned long)sizeof(HBCHeader));
    
    /* ================= ROBUST FUNCTION PARSING ================= */
    
    /* Align buffer */
    result = buffer_reader_align(&reader.file_buffer, 4);
    if (result.code != RESULT_SUCCESS) {
        fprintf(stderr, "Warning: Error aligning buffer for functions: %s\n", result.error_message);
        fprintf(out, "# Warning: Error aligning buffer for functions: %s\n", result.error_message);
        hbc_reader_cleanup(&reader);
        return SUCCESS_RESULT(); /* Return success since we've written what we can */
    }

    /* Set reasonable limits for function count */
    const u32 MAX_SAFE_FUNCTIONS = 50000;
    u32 function_count = reader.header.functionCount;
    
    if (function_count > MAX_SAFE_FUNCTIONS) {
        fprintf(stderr, "Warning: Very large function count (%u). Limiting to %u for safety.\n", 
            reader.header.functionCount, MAX_SAFE_FUNCTIONS);
        function_count = MAX_SAFE_FUNCTIONS;
    }

    fprintf(stderr, "Reading functions at position %zu of %zu bytes.\n", 
        reader.file_buffer.position, reader.file_buffer.size);
    fprintf(out, "# Reading %u functions from position 0x%zx\n", 
        function_count, reader.file_buffer.position);
    
    /* Check for reasonable function count vs file size */
    size_t min_bytes_needed = function_count * 16; /* Each header is at least 16 bytes */
    if (reader.file_buffer.position + min_bytes_needed > reader.file_buffer.size) {
        fprintf(stderr, "Warning: File might be truncated. Need ~%zu more bytes for function headers.\n", 
            min_bytes_needed);
        fprintf(out, "# Warning: File appears too small for %u functions, may only read partial data\n", 
            function_count);
    }

    /* Create temporary array for function names to solve temp_name lifetime issues */
    char** function_names = (char**)calloc(function_count, sizeof(char*));
    if (!function_names) {
        fprintf(stderr, "Error: Failed to allocate memory for function names\n");
        if (output_file) {
            fclose(out);
        }
        hbc_reader_cleanup(&reader);
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function names");
    }
    
    /* Initialize all function names to NULL */
    for (u32 i = 0; i < function_count; i++) {
        function_names[i] = NULL;
    }
    
    /* Track functions we read successfully */
    size_t successful_functions = 0;
    u32* function_offsets = (u32*)calloc(function_count, sizeof(u32));
    u32* function_sizes = (u32*)calloc(function_count, sizeof(u32));
    
    if (!function_offsets || !function_sizes) {
        fprintf(stderr, "Error: Failed to allocate memory for function offsets or sizes\n");
        free(function_names);
        free(function_offsets);
        free(function_sizes);
        if (output_file) {
            fclose(out);
        }
        hbc_reader_cleanup(&reader);
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate memory");
    }
    
    /* Print current position in case we have issues */
    fprintf(stderr, "Function section start position: %zu\n", reader.file_buffer.position);
    
    /* Read all function headers directly from the buffer */
    for (u32 i = 0; i < function_count; i++) {
        /* Safety check - ensure we have enough buffer for a function header (16 bytes) */
        if (reader.file_buffer.position + 16 > reader.file_buffer.size) {
            fprintf(stderr, "Reached end of file after reading %zu of %u functions\n", 
                successful_functions, function_count);
            break;  /* End reading if we reach end of buffer */
        }
        
        /* Track position in case we need to restore it */
        size_t start_position = reader.file_buffer.position;
        
        /* Read function header raw data with explicit error handling */
        u32 raw_data[4];
        bool header_read_failed = false;
        
        for (int j = 0; j < 4; j++) {
            Result res = buffer_reader_read_u32(&reader.file_buffer, &raw_data[j]);
            if (res.code != RESULT_SUCCESS) {
                fprintf(stderr, "Error reading function %u header word %d: %s\n", 
                    i, j, res.error_message);
                header_read_failed = true;
                break;
            }
        }
        
        if (header_read_failed) {
            /* Restore position and break */
            buffer_reader_seek(&reader.file_buffer, start_position);
            break;
        }
        
        /* Extract fields from raw data based on the Python implementation */
        u32 offset = raw_data[0] & 0x1FFFFFF;          /* 25 bits */
        /* Unused: u32 paramCount = (raw_data[0] >> 25) & 0x7F; */
        
        u32 bytecodeSizeInBytes = raw_data[1] & 0x7FFF;  /* 15 bits */
        /* Unused: u32 functionName = (raw_data[1] >> 15) & 0x1FFFF; */
        
        /* Unused: 
        u32 infoOffset = raw_data[2] & 0x1FFFFFF;
        u32 frameSize = (raw_data[2] >> 25) & 0x7F;
        
        u8 flags = (u8)((raw_data[3] >> 24) & 0xFF);   
        bool overflowed = (flags >> 5) & 0x1;
        */
        
        /* Skip if offset is invalid or outside file bounds */
        if (offset == 0 || offset >= reader.file_buffer.size) {
            /* Skip this function silently */
            continue;
        }
        
        /* Store offset and size for flag generation */
        function_offsets[successful_functions] = offset;
        function_sizes[successful_functions] = bytecodeSizeInBytes;
        
        /* Generate a default function name based on index */
        char* temp_name = (char*)malloc(32);
        if (temp_name) {
            snprintf(temp_name, 32, "func_%u", i);
            function_names[successful_functions] = temp_name;
        }
        
        successful_functions++;
    }
    
    fprintf(stderr, "Successfully read %zu function headers\n", successful_functions);
    fprintf(out, "# Successfully read %zu function headers\n\n", successful_functions);
    
    /* ==== READ STRING TABLES AND CREATE STRING FLAGS ==== */
    /* Structure to store string info temporarily */
    typedef struct {
        u32 offset;   /* Offset in string storage */
        u32 length;   /* Length of string */
        bool isUTF16; /* Whether the string is UTF-16 encoded */
    } StringInfo;
    
    StringInfo* string_infos = NULL;
    u8* string_storage = NULL;
    size_t string_storage_size = 0;
    
    /* Output function flags */
    fprintf(out, "# Function flags\n");
    for (size_t i = 0; i < successful_functions; i++) {
        /* Use function names we generated earlier */
        const char* function_name = function_names[i] ? function_names[i] : "unknown";
        
        /* Generate sanitized name for r2 */
        char sanitized_name[256] = {0};
        size_t name_len = strlen(function_name);
        size_t sanitized_idx = 0;
        
        for (size_t j = 0; j < name_len && sanitized_idx < sizeof(sanitized_name) - 1; j++) {
            char c = function_name[j];
            if ((c >= 'a' && c <= 'z') || 
                (c >= 'A' && c <= 'Z') || 
                (c >= '0' && c <= '9') || 
                c == '_') {
                sanitized_name[sanitized_idx++] = c;
            } else {
                sanitized_name[sanitized_idx++] = '_';
            }
        }
        sanitized_name[sanitized_idx] = '\0';
        
        /* If sanitized name is empty, use a default */
        if (sanitized_name[0] == '\0') {
            snprintf(sanitized_name, sizeof(sanitized_name), "func_%zu", i);
        }
        
        /* Write the function flag */
        
        /* Add size info if available */
        if (function_sizes[i] > 0) {
            fprintf(out, "'f func.hermes.%s 0x%x 0x%x\n", sanitized_name, 
			    function_sizes[i], function_offsets[i]);
        } else {
            fprintf(out, "'f func.hermes.%s=0x%x\n", sanitized_name, function_offsets[i]);
	}
    }
    
    /* Now try to parse string tables based on Python implementation */
    fprintf(out, "\n# String flags\n");
    bool strings_parsed = false;
    
    /* First try to locate and read the string tables */
    /* Reset file position */
    if (buffer_reader_seek(&reader.file_buffer, sizeof(HBCHeader)).code == RESULT_SUCCESS) {
        /* Skip over functions section */
        u32 function_headers_bytes = reader.header.functionCount * 16; /* 16 bytes per small header */
        result = buffer_reader_seek(&reader.file_buffer, reader.file_buffer.position + function_headers_bytes);
        
        if (result.code == RESULT_SUCCESS) {
            /* Align for string kinds */
            result = buffer_reader_align(&reader.file_buffer, 4);
            if (result.code == RESULT_SUCCESS) {
                /* Skip over string kinds section */
                if (reader.header.stringKindCount > 0) {
                    result = buffer_reader_seek(&reader.file_buffer, 
                        reader.file_buffer.position + reader.header.stringKindCount * sizeof(u32));
                }
                
                if (result.code == RESULT_SUCCESS) {
                    /* Skip over identifier hashes section */
                    if (reader.header.identifierCount > 0) {
                        result = buffer_reader_align(&reader.file_buffer, 4);
                        if (result.code == RESULT_SUCCESS) {
                            result = buffer_reader_seek(&reader.file_buffer, 
                                reader.file_buffer.position + reader.header.identifierCount * sizeof(u32));
                        }
                    }
                    
                    if (result.code == RESULT_SUCCESS) {
                        /* Prepare to read string tables */
                        result = buffer_reader_align(&reader.file_buffer, 4);
                        
                        if (result.code == RESULT_SUCCESS && reader.header.stringCount > 0) {
                            fprintf(stderr, "Reading string tables at position %zu\n", reader.file_buffer.position);
                            
                            /* Allocate storage for string info */
                            u32 safe_string_count = reader.header.stringCount;
                            if (safe_string_count > 100000) {
                                safe_string_count = 100000; /* Safety limit */
                            }
                            
                            string_infos = (StringInfo*)calloc(safe_string_count, sizeof(StringInfo));
                            if (!string_infos) {
                                fprintf(stderr, "Failed to allocate memory for string infos\n");
                            } else {
                                /* Read the small string table entries */
                                bool read_success = true;
                                for (u32 i = 0; i < safe_string_count; i++) {
                                    u32 entry;
                                    result = buffer_reader_read_u32(&reader.file_buffer, &entry);
                                    if (result.code != RESULT_SUCCESS) {
                                        read_success = false;
                                        break;
                                    }
                                    
                                    /* Parse entry fields */
                                    string_infos[i].isUTF16 = entry & 0x1;
                                    string_infos[i].offset = (entry >> 1) & 0x7FFFFF; /* 23 bits */
                                    string_infos[i].length = (entry >> 24) & 0xFF; /* 8 bits */
                                }
                                
                                /* Skip overflow string table if present */
                                if (read_success && reader.header.overflowStringCount > 0) {
                                    result = buffer_reader_align(&reader.file_buffer, 4);
                                    if (result.code == RESULT_SUCCESS) {
                                        /* Skip past each overflow entry (8 bytes each) */
                                        result = buffer_reader_seek(&reader.file_buffer, 
                                            reader.file_buffer.position + reader.header.overflowStringCount * 8);
                                    }
                                }
                                
                                /* Now read the actual string data */
                                if (read_success && result.code == RESULT_SUCCESS) {
                                    /* Align buffer for string storage */
                                    result = buffer_reader_align(&reader.file_buffer, 4);
                                    if (result.code == RESULT_SUCCESS && reader.header.stringStorageSize > 0) {
                                        /* Safety check - limit large string storage */
                                        size_t storage_size = reader.header.stringStorageSize;
                                        if (storage_size > 10 * 1024 * 1024) { /* 10MB limit */
                                            storage_size = 10 * 1024 * 1024;
                                        }
                                        
                                        /* Make sure we have room to read */
                                        if (reader.file_buffer.position + storage_size <= reader.file_buffer.size) {
                                            /* Allocate space for string storage */
                                            string_storage = (u8*)malloc(storage_size);
                                            if (string_storage) {
                                                /* Read entire string storage section */
                                                result = buffer_reader_read_bytes(&reader.file_buffer, string_storage, storage_size);
                                                if (result.code == RESULT_SUCCESS) {
                                                    string_storage_size = storage_size;
                                                    strings_parsed = true;
                                                    fprintf(stderr, "Successfully read %zu bytes of string data\n", storage_size);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    /* Generate string flags if we managed to read the string data */
    if (strings_parsed && string_infos && string_storage) {
        u32 safe_string_count = reader.header.stringCount;
        if (safe_string_count > 100000) {
            safe_string_count = 100000;
        }
        
        /* Create flags for each string */
        u32 successful_strings = 0;
        for (u32 i = 0; i < safe_string_count; i++) {
            u32 offset = string_infos[i].offset;
            u32 length = string_infos[i].length;
            bool isUTF16 = string_infos[i].isUTF16;
            
            /* Skip strings with obviously invalid offsets/lengths */
            if (offset >= string_storage_size || 
                (isUTF16 && offset + (length * 2) > string_storage_size) ||
                (!isUTF16 && offset + length > string_storage_size)) {
                continue;
            }
            
            /* For very long strings, truncate for flag name purposes */
            u32 display_length = length;
            if (display_length > 32) {
                display_length = 32;
            }
            
            /* Generate a string value for the flag name */
            char str_value[64] = {0};
            if (isUTF16) {
                /* UTF-16 string - simplified handling */
                u32 chars_added = 0;
                for (u32 j = 0; j < display_length && chars_added < sizeof(str_value) - 1; j++) {
                    /* Read 16-bit character */
                    u16 c = (u16)(string_storage[offset + (j * 2)] | (string_storage[offset + (j * 2) + 1] << 8));
                    
                    /* Only add ASCII-printable characters to name */
                    if (c >= 32 && c < 127) {
                        str_value[chars_added++] = (char)c;
                    } else {
                        str_value[chars_added++] = '_';
                    }
                }
                str_value[chars_added] = '\0';
            } else {
                /* ASCII string */
                u32 chars_added = 0;
                for (u32 j = 0; j < display_length && chars_added < sizeof(str_value) - 1; j++) {
                    char c = (char)string_storage[offset + j];
                    
                    /* Only add printable characters to name */
                    if (c >= 32 && c < 127) {
                        str_value[chars_added++] = c;
                    } else {
                        str_value[chars_added++] = '_';
                    }
                }
                str_value[chars_added] = '\0';
            }
            
            /* Generate sanitized name for r2 - only include alphanumeric and underscores */
            char sanitized_name[64] = {0};
            size_t name_len = strlen(str_value);
            size_t sanitized_idx = 0;
            
            for (size_t j = 0; j < name_len && sanitized_idx < sizeof(sanitized_name) - 1; j++) {
                char c = str_value[j];
                if ((c >= 'a' && c <= 'z') || 
                    (c >= 'A' && c <= 'Z') || 
                    (c >= '0' && c <= '9') || 
                    c == '_') {
                    sanitized_name[sanitized_idx++] = c;
                } else {
                    sanitized_name[sanitized_idx++] = '_';
                }
            }
            sanitized_name[sanitized_idx] = '\0';
            
            /* Add index to name to ensure uniqueness */
            char unique_name[96];
            snprintf(unique_name, sizeof(unique_name), "%s_%u", 
                     sanitized_name[0] ? sanitized_name : "str", i);
            
            /* Write the string flag - offset is relative to string storage base */
            uint32_t size = (isUTF16)? length * 2: length;
	    uint32_t addr = (unsigned long)(reader.file_buffer.position - string_storage_size + offset);
            fprintf(out, "'f str.%s %d 0x%08x\n", unique_name, size, addr);
#if 0
            /* Add flag for string length */
            if (isUTF16) {
                fprintf(out, "f str.%s.size=0x%x\n", unique_name, length * 2);
            } else {
                fprintf(out, "f str.%s.size=0x%x\n", unique_name, length);
            }
#endif
            
            successful_strings++;
        }
        
        fprintf(stderr, "Generated flags for %u strings\n", successful_strings);
        fprintf(out, "# Generated %u string flags\n", successful_strings);
    } else {
        fprintf(stderr, "Could not parse strings\n");
        fprintf(out, "# Could not parse string data\n");
    }
    
    /* Clean up string parsing resources */
    if (string_infos) {
        free(string_infos);
    }
    if (string_storage) {
        free(string_storage);
    }
    
    /* Free function names */
    for (u32 i = 0; i < function_count; i++) {
        if (function_names[i]) {
            free(function_names[i]);
        }
    }
    free(function_names);
    free(function_offsets);
    free(function_sizes);
    
    /* Close output file if needed */
    if (output_file) {
        fclose(out);
        printf("\n[+] R2 script output wrote to \"%s\"\n\n", output_file);
    }
    
    /* Clean up */
    hbc_reader_cleanup(&reader);
    
    return SUCCESS_RESULT();
}
