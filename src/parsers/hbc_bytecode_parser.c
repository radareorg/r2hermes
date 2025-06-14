#include "../../include/parsers/hbc_bytecode_parser.h"
#include "../../include/opcodes/hermes_opcodes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global instruction set definitions for different bytecode versions */
static Instruction* g_instruction_set_v96 = NULL;
static u32 g_instruction_set_v96_count = 0;

/* Initialize parsed instruction list */
Result parsed_instruction_list_init(ParsedInstructionList* list, u32 initial_capacity) {
    if (!list) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "List is NULL");
    }
    
    list->instructions = (ParsedInstruction*)malloc(initial_capacity * sizeof(ParsedInstruction));
    if (!list->instructions) {
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate instruction list");
    }
    
    list->count = 0;
    list->capacity = initial_capacity;
    
    return SUCCESS_RESULT();
}

/* Add instruction to parsed instruction list */
Result parsed_instruction_list_add(ParsedInstructionList* list, ParsedInstruction* instruction) {
    if (!list || !instruction) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for parsed_instruction_list_add");
    }
    
    /* Resize list if needed */
    if (list->count >= list->capacity) {
        u32 new_capacity = list->capacity * 2;
        ParsedInstruction* new_instructions = (ParsedInstruction*)realloc(
            list->instructions, new_capacity * sizeof(ParsedInstruction));
            
        if (!new_instructions) {
            return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to resize instruction list");
        }
        
        list->instructions = new_instructions;
        list->capacity = new_capacity;
    }
    
    /* Copy instruction to list */
    memcpy(&list->instructions[list->count], instruction, sizeof(ParsedInstruction));
    list->count++;
    
    return SUCCESS_RESULT();
}

/* Free parsed instruction list */
void parsed_instruction_list_free(ParsedInstructionList* list) {
    if (!list) {
        return;
    }
    
    if (list->instructions) {
        /* Free switch jump tables for any instructions that have them */
        for (u32 i = 0; i < list->count; i++) {
            if (list->instructions[i].switch_jump_table) {
                free(list->instructions[i].switch_jump_table);
            }
        }
        
        free(list->instructions);
    }
    
    list->instructions = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* Initialize the instruction set for the given bytecode version */
static Result initialize_instruction_set(u32 bytecode_version) {
    /* Currently we only support bytecode version 96 */
    if (bytecode_version > 96) {
        fprintf(stderr, "Warning: Bytecode version %u is newer than supported version (96). Using v96 opcodes.\n", 
            bytecode_version);
    }
    
    if (!g_instruction_set_v96) {
        g_instruction_set_v96 = get_instruction_set_v96(&g_instruction_set_v96_count);
        if (!g_instruction_set_v96) {
            return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to initialize instruction set");
        }
    }
    
    return SUCCESS_RESULT();
}

/* Find instruction definition by opcode */
static const Instruction* find_instruction(u8 opcode, u32 bytecode_version) {
    u32 count;
    Instruction* instruction_set = NULL;
    
    /* Select the appropriate instruction set based on bytecode version */
    if (bytecode_version <= 96) {
        instruction_set = g_instruction_set_v96;
        count = g_instruction_set_v96_count;
    } else {
        /* Default to the latest version we support */
        instruction_set = g_instruction_set_v96;
        count = g_instruction_set_v96_count;
    }
    
    /* Search for the instruction */
    for (u32 i = 0; i < count; i++) {
        if (instruction_set[i].opcode == opcode) {
            return &instruction_set[i];
        }
    }
    
    return NULL;
}

/* Parse instruction from bytecode buffer */
Result parse_instruction(HBCReader* reader, FunctionHeader* function_header, 
                       u32 offset, ParsedInstruction* out_instruction) {
    if (!reader || !function_header || !out_instruction) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for parse_instruction");
    }
    
    /* Check if the offset is within the function's bytecode */
    if (offset >= function_header->bytecodeSizeInBytes) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Instruction offset out of bounds");
    }
    
    /* Initialize instruction fields */
    memset(out_instruction, 0, sizeof(ParsedInstruction));
    out_instruction->original_pos = offset;
    out_instruction->hbc_reader = reader;
    
    /* Create a buffer reader for the function bytecode */
    BufferReader bytecode_reader;
    buffer_reader_init_from_memory(&bytecode_reader, 
                                  function_header->bytecode, 
                                  function_header->bytecodeSizeInBytes);
    
    /* Seek to the instruction offset */
    RETURN_IF_ERROR(buffer_reader_seek(&bytecode_reader, offset));
    
    /* Ensure we have at least one byte to read the opcode */
    if (bytecode_reader.position >= bytecode_reader.size) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "End of bytecode reached while parsing instruction");
    }
    
    /* Read opcode */
    u8 opcode;
    RETURN_IF_ERROR(buffer_reader_read_u8(&bytecode_reader, &opcode));
    
    /* Initialize instruction set if needed */
    RETURN_IF_ERROR(initialize_instruction_set(reader->header.version));
    
    /* Find instruction definition */
    const Instruction* inst = find_instruction(opcode, reader->header.version);
    if (!inst) {
        /* Unknown opcode - create a placeholder instruction */
        static Instruction unknown_instruction = {
            0xFF, "UnknownOpcode", 
            {{OPERAND_TYPE_NONE, OPERAND_MEANING_NONE}}, 1
        };
        
        inst = &unknown_instruction;
        unknown_instruction.opcode = opcode;
        
        fprintf(stderr, "Warning: Unknown opcode 0x%02x at offset 0x%08x\n", opcode, offset);
    }
    
    out_instruction->inst = inst;
    
    /* Parse operands based on instruction type */
    u32 operand_values[6] = {0};
    u32 operand_count = 0;
    
    for (int i = 0; i < 6; i++) {
        if (inst->operands[i].operand_type == OPERAND_TYPE_NONE) {
            continue;
        }
        
        /* Read operand value based on type */
        switch (inst->operands[i].operand_type) {
            case OPERAND_TYPE_REG8:
            case OPERAND_TYPE_IMM8:
            case OPERAND_TYPE_ADDR8: {
                u8 value;
                RETURN_IF_ERROR(buffer_reader_read_u8(&bytecode_reader, &value));
                operand_values[i] = value;
                break;
            }
            
            case OPERAND_TYPE_IMM16: {
                u16 value;
                RETURN_IF_ERROR(buffer_reader_read_u16(&bytecode_reader, &value));
                operand_values[i] = value;
                break;
            }
            
            case OPERAND_TYPE_REG32:
            case OPERAND_TYPE_IMM32:
            case OPERAND_TYPE_ADDR32: {
                u32 value;
                RETURN_IF_ERROR(buffer_reader_read_u32(&bytecode_reader, &value));
                operand_values[i] = value;
                break;
            }
            
            default:
                break;
        }
        
        operand_count++;
    }
    
    /* Store operand values in instruction */
    if (operand_count >= 1) out_instruction->arg1 = operand_values[0];
    if (operand_count >= 2) out_instruction->arg2 = operand_values[1];
    if (operand_count >= 3) out_instruction->arg3 = operand_values[2];
    if (operand_count >= 4) out_instruction->arg4 = operand_values[3];
    if (operand_count >= 5) out_instruction->arg5 = operand_values[4];
    if (operand_count >= 6) out_instruction->arg6 = operand_values[5];
    
    /* Handle special cases for specific instructions */
    if (opcode == OP_SwitchImm) {
        /* SwitchImm has a jump table following the immediate operands */
        u32 jump_table_size = out_instruction->arg2;
        
        /* Allocate jump table */
        out_instruction->switch_jump_table = (u32*)malloc(jump_table_size * sizeof(u32));
        if (!out_instruction->switch_jump_table) {
            return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate switch jump table");
        }
        
        out_instruction->switch_jump_table_size = jump_table_size;
        
        /* Read jump table entries */
        for (u32 i = 0; i < jump_table_size; i++) {
            u32 jump_offset;
            RETURN_IF_ERROR(buffer_reader_read_u32(&bytecode_reader, &jump_offset));
            out_instruction->switch_jump_table[i] = jump_offset;
        }
    }
    
    /* Store next position */
    out_instruction->next_pos = bytecode_reader.position;
    
    return SUCCESS_RESULT();
}

/* Parse all bytecode instructions in a function */
Result parse_function_bytecode(HBCReader* reader, u32 function_id, 
                             ParsedInstructionList* out_instructions) {
    if (!reader || !out_instructions) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, 
                          "Invalid arguments for parse_function_bytecode");
    }
    
    /* Check function ID */
    if (function_id >= reader->header.functionCount) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid function ID");
    }
    
    FunctionHeader* function_header = &reader->function_headers[function_id];
    if (!function_header->bytecode) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Function has no bytecode");
    }
    
    /* Initialize instruction list */
    RETURN_IF_ERROR(parsed_instruction_list_init(out_instructions, 32));  /* Start with space for 32 instructions */
    
    /* Parse instructions */
    u32 offset = 0;
    while (offset < function_header->bytecodeSizeInBytes) {
        /* Parse instruction at current offset */
        ParsedInstruction instruction;
        Result result = parse_instruction(reader, function_header, offset, &instruction);
        
        if (result.code != RESULT_SUCCESS) {
            /* Log the error but try to continue with the next instruction */
            fprintf(stderr, "Error parsing instruction at offset 0x%08x: %s\n", 
                   offset, result.error_message);
            
            /* Skip to the next byte and try again */
            offset++;
            continue;
        }
        
        /* Add instruction to list */
        RETURN_IF_ERROR(parsed_instruction_list_add(out_instructions, &instruction));
        
        /* Move to next instruction */
        offset = instruction.next_pos;
    }
    
    return SUCCESS_RESULT();
}

/* Convert instruction to string */
Result instruction_to_string(ParsedInstruction* instruction, StringBuffer* out_string) {
    if (!instruction || !out_string || !instruction->inst) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, 
                          "Invalid arguments for instruction_to_string");
    }
    
    /* Format offset */
    char offset_str[16];
    snprintf(offset_str, sizeof(offset_str), "%08x", instruction->original_pos);
    
    /* Add address */
    RETURN_IF_ERROR(string_buffer_append(out_string, offset_str));
    RETURN_IF_ERROR(string_buffer_append(out_string, ": "));
    
    /* Add opcode name */
    RETURN_IF_ERROR(string_buffer_append(out_string, instruction->inst->name));
    
    /* Add operands if any */
    bool has_operands = false;
    for (int i = 0; i < 6; i++) {
        if (instruction->inst->operands[i].operand_type != OPERAND_TYPE_NONE) {
            has_operands = true;
            break;
        }
    }
    
    if (has_operands) {
        RETURN_IF_ERROR(string_buffer_append(out_string, " "));
        
        /* Format each operand */
        bool first = true;
        for (int i = 0; i < 6; i++) {
            if (instruction->inst->operands[i].operand_type == OPERAND_TYPE_NONE) {
                continue;
            }
            
            if (!first) {
                RETURN_IF_ERROR(string_buffer_append(out_string, ", "));
            }
            first = false;
            
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
            
            /* Format based on operand type */
            switch (instruction->inst->operands[i].operand_type) {
                case OPERAND_TYPE_REG8:
                case OPERAND_TYPE_REG32:
                    RETURN_IF_ERROR(string_buffer_append(out_string, "r"));
                    RETURN_IF_ERROR(string_buffer_append_int(out_string, value));
                    break;
                    
                case OPERAND_TYPE_IMM8:
                case OPERAND_TYPE_IMM16:
                case OPERAND_TYPE_IMM32: {
                    char imm_str[16];
                    snprintf(imm_str, sizeof(imm_str), "%u", value);
                    RETURN_IF_ERROR(string_buffer_append(out_string, imm_str));
                    break;
                }
                
                case OPERAND_TYPE_ADDR8:
                case OPERAND_TYPE_ADDR32: {
                    char addr_str[16];
                    snprintf(addr_str, sizeof(addr_str), "0x%x", value);
                    RETURN_IF_ERROR(string_buffer_append(out_string, addr_str));
                    break;
                }
                
                default:
                    break;
            }
        }
    }
    
    /* Add comments for special operands like strings, bigints, function IDs */
    HBCReader* reader = instruction->hbc_reader;
    if (reader) {
        for (int i = 0; i < 6; i++) {
            if (instruction->inst->operands[i].operand_meaning == OPERAND_MEANING_NONE) {
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
            
            switch (instruction->inst->operands[i].operand_meaning) {
                case OPERAND_MEANING_STRING_ID:
                    if (value < reader->header.stringCount) {
                        RETURN_IF_ERROR(string_buffer_append(out_string, " # \""));
                        RETURN_IF_ERROR(string_buffer_append(out_string, reader->strings[value]));
                        RETURN_IF_ERROR(string_buffer_append(out_string, "\""));
                    }
                    break;
                    
                case OPERAND_MEANING_FUNCTION_ID:
                    if (value < reader->header.functionCount) {
                        FunctionHeader* func = &reader->function_headers[value];
                        if (func->functionName < reader->header.stringCount) {
                            RETURN_IF_ERROR(string_buffer_append(out_string, " # function \""));
                            RETURN_IF_ERROR(string_buffer_append(out_string, reader->strings[func->functionName]));
                            RETURN_IF_ERROR(string_buffer_append(out_string, "\""));
                        } else {
                            RETURN_IF_ERROR(string_buffer_append(out_string, " # function"));
                        }
                    }
                    break;
                    
                default:
                    break;
            }
        }
        
        /* For jump instructions, add target address */
        if (is_jump_instruction(instruction->inst->opcode)) {
            u32 target_offset = 0;
            /* Find the address operand */
            for (int i = 0; i < 6; i++) {
                if (instruction->inst->operands[i].operand_type == OPERAND_TYPE_ADDR8 ||
                    instruction->inst->operands[i].operand_type == OPERAND_TYPE_ADDR32) {
                    
                    switch (i) {
                        case 0: target_offset = instruction->arg1; break;
                        case 1: target_offset = instruction->arg2; break;
                        case 2: target_offset = instruction->arg3; break;
                        case 3: target_offset = instruction->arg4; break;
                        case 4: target_offset = instruction->arg5; break;
                        case 5: target_offset = instruction->arg6; break;
                        default: break;
                    }
                    
                    /* For relative jumps, calculate absolute target */
                    u32 absolute_target = instruction->original_pos + instruction->inst->binary_size + target_offset;
                    char target_str[32];
                    snprintf(target_str, sizeof(target_str), " # target: 0x%08x", absolute_target);
                    RETURN_IF_ERROR(string_buffer_append(out_string, target_str));
                    break;
                }
            }
        }
    }
    
    return SUCCESS_RESULT();
}

/* Helper function - check if an opcode is a jump instruction */
bool is_jump_instruction(u8 opcode) {
    switch (opcode) {
        case OP_Jmp:
        case OP_JmpTrue:
        case OP_JmpFalse:
        case OP_JmpUndefined:
        case OP_JmpLong:
        case OP_JmpTrueLong:
        case OP_JmpFalseLong:
        case OP_JmpUndefinedLong:
            return true;
        default:
            return false;
    }
}

/* Helper function - check if an opcode is a call instruction */
bool is_call_instruction(u8 opcode) {
    switch (opcode) {
        case OP_Call:
        case OP_CallLong:
        case OP_Construct:
        case OP_ConstructLong:
        case OP_CallN:
        case OP_ConstructN:
        case OP_CallDirect:
        case OP_CallDirectLongIndex:
        case OP_CallBuiltin:
            return true;
        default:
            return false;
    }
}

