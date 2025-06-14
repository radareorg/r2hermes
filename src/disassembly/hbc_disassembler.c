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
    
    /* Get function name */
    const char* function_name = "unknown";
    if (function_header->functionName < reader->header.stringCount) {
        function_name = reader->strings[function_header->functionName];
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
Result print_instruction(Disassembler* disassembler, ParsedInstruction* instruction) {
    if (!disassembler || !instruction || !instruction->inst) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for print_instruction");
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
                if (value < reader->header.stringCount) {
                    RETURN_IF_ERROR(string_buffer_append(output, "  # String: \""));
                    RETURN_IF_ERROR(string_buffer_append(output, reader->strings[value]));
                    RETURN_IF_ERROR(string_buffer_append(output, "\" ("));
                    RETURN_IF_ERROR(string_buffer_append(output, string_kind_to_string(reader->string_kinds[value])));
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
                if (value < reader->header.functionCount) {
                    FunctionHeader* func = &reader->function_headers[value];
                    const char* func_name = "unknown";
                    if (func->functionName < reader->header.stringCount) {
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
    RETURN_IF_ERROR(print_function_header(disassembler, function_header, function_id));
    
    /* Print bytecode listing header */
    RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "Bytecode listing:\n\n"));
    
    /* Check if function has bytecode */
    if (!function_header->bytecode || function_header->bytecodeSizeInBytes == 0) {
        RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "[No bytecode available for this function]\n"));
    } else {
        /* Parse the bytecode */
        ParsedInstructionList instructions;
        Result result = parse_function_bytecode(reader, function_id, &instructions);
        
        if (result.code != RESULT_SUCCESS) {
            /* Handle parsing error */
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "[Error parsing bytecode: "));
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, result.error_message));
            RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "]\n"));
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
                
                /* Initialize a temporary string buffer for the instruction */
                StringBuffer instr_str;
                RETURN_IF_ERROR(string_buffer_init(&instr_str, 256));
                
                /* Format the instruction */
                result = instruction_to_string(instruction, &instr_str);
                if (result.code != RESULT_SUCCESS) {
                    string_buffer_free(&instr_str);
                    RETURN_IF_ERROR(string_buffer_append(&disassembler->output, 
                        "[Error formatting instruction]\n"));
                    continue;
                }
                
                /* Add to main output */
                RETURN_IF_ERROR(string_buffer_append(&disassembler->output, instr_str.data));
                RETURN_IF_ERROR(string_buffer_append(&disassembler->output, "\n"));
                
                /* Clean up temporary buffer */
                string_buffer_free(&instr_str);
            }
            
            /* Free instruction list */
            parsed_instruction_list_free(&instructions);
        }
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
    
    /* Disassemble each function */
    for (u32 i = 0; i < reader->header.functionCount; i++) {
        RETURN_IF_ERROR(disassemble_function(disassembler, i));
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

