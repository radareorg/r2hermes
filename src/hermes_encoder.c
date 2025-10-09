#include "../include/hermes_encoder.h"
#include "../include/opcodes/hermes_opcodes.h"
#include "../include/parsers/hbc_bytecode_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

/* Initialize encoder */
Result hermes_encoder_init(HermesEncoder* encoder, u32 bytecode_version) {
    if (!encoder) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Encoder is NULL");
    }

    encoder->bytecode_version = bytecode_version;
    encoder->instruction_set = NULL;
    encoder->instruction_count = 0;

    /* Initialize instruction set */
    if (bytecode_version == 95 || bytecode_version == 96) {
        encoder->instruction_set = get_instruction_set_v96(&encoder->instruction_count);
    } else if (bytecode_version == 92 || bytecode_version == 94) {
        encoder->instruction_set = get_instruction_set_v92(&encoder->instruction_count);
    } else {
        return ERROR_RESULT(RESULT_ERROR_UNSUPPORTED_VERSION,
                          "Unsupported bytecode version for encoding");
    }

    if (!encoder->instruction_set) {
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION,
                          "Failed to initialize instruction set");
    }

    return SUCCESS_RESULT();
}

/* Clean up encoder */
void hermes_encoder_cleanup(HermesEncoder* encoder) {
    if (!encoder) {
        return;
    }

    /* Instruction set is managed globally, don't free it here */
    encoder->instruction_set = NULL;
    encoder->instruction_count = 0;
}

/* Find instruction by mnemonic */
static u8 find_opcode_by_name(const char* mnemonic, u32 bytecode_version) {
    (void)bytecode_version; /* currently unused */
    if (!mnemonic) {
        return 0xFF; /* Invalid opcode */
    }

    /* For now, implement a simple lookup table for common instructions */
    /* This should be expanded to cover all instructions */
    if (strcasecmp(mnemonic, "Mov") == 0) return 8;
    if (strcasecmp(mnemonic, "MovLong") == 0) return 9;
    if (strcasecmp(mnemonic, "LoadConstZero") == 0) return 122;
    if (strcasecmp(mnemonic, "LoadConstUndefined") == 0) return 118;
    if (strcasecmp(mnemonic, "LoadConstNull") == 0) return 119;
    if (strcasecmp(mnemonic, "LoadConstTrue") == 0) return 120;
    if (strcasecmp(mnemonic, "LoadConstFalse") == 0) return 121;
    if (strcasecmp(mnemonic, "Ret") == 0) return 92;
    if (strcasecmp(mnemonic, "Add") == 0) return 22;
    if (strcasecmp(mnemonic, "Sub") == 0) return 29;
    if (strcasecmp(mnemonic, "Mul") == 0) return 24;
    if (strcasecmp(mnemonic, "Div") == 0) return 26;
    if (strcasecmp(mnemonic, "Jmp") == 0) return 142;
    if (strcasecmp(mnemonic, "JmpLong") == 0) return 143;

    return 0xFF; /* Unknown */
}

/* Get instruction size by opcode */
static u32 get_instruction_size(u8 opcode) {
    /* This is a simplified version - should be expanded */
    switch (opcode) {
        case 8: return 3;   /* Mov */
        case 9: return 9;   /* MovLong */
        case 122: return 2; /* LoadConstZero */
        case 118: return 2; /* LoadConstUndefined */
        case 119: return 2; /* LoadConstNull */
        case 120: return 2; /* LoadConstTrue */
        case 121: return 2; /* LoadConstFalse */
        case 92: return 2;  /* Ret */
        case 22: return 4;  /* Add */
        case 29: return 4;  /* Sub */
        case 24: return 4;  /* Mul */
        case 26: return 4;  /* Div */
        case 142: return 2; /* Jmp */
        case 143: return 5; /* JmpLong */
        default: return 1;  /* Unknown, assume 1 byte */
    }
}

/* Note: a more detailed operand parser existed but was unused.
   It was removed to satisfy -Werror; add back when needed. */

/* Parse instruction line in asm format */
Result hermes_encoder_parse_instruction(HermesEncoder* encoder, const char* asm_line,
                                       EncodedInstruction* out_instruction) {
    if (!encoder || !asm_line || !out_instruction) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    /* Initialize output */
    memset(out_instruction, 0, sizeof(EncodedInstruction));

    /* Skip address prefix if present (format: "0xADDR: mnemonic ..." ) */
    const char* line = asm_line;
    if (line[0] == '0' && (line[1] == 'x' || line[1] == 'X')) {
        /* Skip address */
        while (*line && *line != ':') {
            line++;
        }
        if (*line == ':') {
            line++; /* Skip colon */
        }
        /* Skip whitespace */
        while (*line && isspace(*line)) {
            line++;
        }
    }

    /* Extract mnemonic */
    char mnemonic[64] = {0};
    size_t mnemonic_len = 0;
    while (*line && !isspace(*line) && mnemonic_len < sizeof(mnemonic) - 1) {
        mnemonic[mnemonic_len++] = *line++;
    }
    mnemonic[mnemonic_len] = '\0';

    if (mnemonic_len == 0) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "No mnemonic found");
    }

    /* Find instruction by mnemonic */
    u8 opcode = find_opcode_by_name(mnemonic, encoder->bytecode_version);
    if (opcode == 0xFF) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Unknown mnemonic");
    }

    out_instruction->opcode = opcode;
    out_instruction->size = get_instruction_size(opcode);

    /* Parse operands */
    u32 operand_values[6] = {0};
    int operand_count = 0;

    /* Skip whitespace after mnemonic */
    while (*line && isspace(*line)) {
        line++;
    }

    /* Parse operands separated by commas */
    while (*line && operand_count < 6) {
        /* Skip whitespace */
        while (*line && isspace(*line)) {
            line++;
        }

        if (*line == '\0' || *line == '\n' || *line == '\r') {
            break;
        }

        /* Find end of operand (comma or end) */
        const char* operand_end = line;
        int paren_depth = 0;
        while (*operand_end && (*operand_end != ',' || paren_depth > 0)) {
            if (*operand_end == '(') paren_depth++;
            else if (*operand_end == ')') paren_depth--;
            operand_end++;
        }

        /* Extract operand string */
        size_t operand_len = operand_end - line;
        if (operand_len == 0) {
            break;
        }

        char operand_str[64] = {0};
        if (operand_len >= sizeof(operand_str)) {
            return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Operand too long");
        }
        memcpy(operand_str, line, operand_len);
        operand_str[operand_len] = '\0';

        /* Trim whitespace */
        char* trim_start = operand_str;
        while (*trim_start && isspace(*trim_start)) {
            trim_start++;
        }
        char* trim_end = trim_start + strlen(trim_start) - 1;
        while (trim_end > trim_start && isspace(*trim_end)) {
            *trim_end-- = '\0';
        }

        /* Parse operand - simplified for now */
        if (operand_count < 6) {
            /* For now, assume all operands are either registers (rN) or immediates */
            if (trim_start[0] == 'r' || trim_start[0] == 'R') {
                /* Register */
                char* endptr;
                operand_values[operand_count] = (u32)strtoul(trim_start + 1, &endptr, 10);
            } else {
                /* Immediate or address */
                char* endptr;
                if (trim_start[0] == '0' && (trim_start[1] == 'x' || trim_start[1] == 'X')) {
                    /* Hex */
                    operand_values[operand_count] = (u32)strtoul(trim_start, &endptr, 16);
                } else {
                    /* Decimal */
                    operand_values[operand_count] = (u32)strtoul(trim_start, &endptr, 10);
                }
            }
        }

        operand_count++;

        /* Move to next operand */
        line = operand_end;
        if (*line == ',') {
            line++;
        }
    }

    /* Parse operands separated by commas */
    while (*line && operand_count < 6) {
        /* Skip whitespace */
        while (*line && isspace(*line)) {
            line++;
        }

        if (*line == '\0' || *line == '\n' || *line == '\r') {
            break;
        }

        /* Find end of operand (comma or end) */
        const char* operand_end = line;
        int paren_depth = 0;
        while (*operand_end && (*operand_end != ',' || paren_depth > 0)) {
            if (*operand_end == '(') paren_depth++;
            else if (*operand_end == ')') paren_depth--;
            operand_end++;
        }

        /* Extract operand string */
        size_t operand_len = operand_end - line;
        char operand_str[64] = {0};
        if (operand_len >= sizeof(operand_str)) {
            return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Operand too long");
        }
        memcpy(operand_str, line, operand_len);
        operand_str[operand_len] = '\0';

        /* Trim whitespace */
        char* trim_start = operand_str;
        while (*trim_start && isspace(*trim_start)) {
            trim_start++;
        }
        char* trim_end = trim_start + strlen(trim_start) - 1;
        while (trim_end > trim_start && isspace(*trim_end)) {
            *trim_end-- = '\0';
        }

        /* Parse operand - simplified */
        if (operand_count < 6) {
            /* For now, assume all operands are either registers (rN) or immediates */
            if (trim_start[0] == 'r' || trim_start[0] == 'R') {
                /* Register */
                char* endptr;
                operand_values[operand_count] = (u32)strtoul(trim_start + 1, &endptr, 10);
            } else {
                /* Immediate or address */
                char* endptr;
                if (trim_start[0] == '0' && (trim_start[1] == 'x' || trim_start[1] == 'X')) {
                    /* Hex */
                    operand_values[operand_count] = (u32)strtoul(trim_start, &endptr, 16);
                } else {
                    /* Decimal */
                    operand_values[operand_count] = (u32)strtoul(trim_start, &endptr, 10);
                }
            }
        }

        operand_count++;

        /* Move to next operand */
        line = operand_end;
        if (*line == ',') {
            line++;
        }
    }

    /* Store operand values */
    out_instruction->arg1 = operand_values[0];
    out_instruction->arg2 = operand_values[1];
    out_instruction->arg3 = operand_values[2];
    out_instruction->arg4 = operand_values[3];
    out_instruction->arg5 = operand_values[4];
    out_instruction->arg6 = operand_values[5];

    return SUCCESS_RESULT();
}

/* Encode instruction to bytecode */
Result hermes_encoder_encode_instruction(HermesEncoder* encoder, const EncodedInstruction* instruction,
                                        u8* out_buffer, size_t buffer_size, size_t* out_bytes_written) {
    if (!encoder || !instruction || !out_buffer || !out_bytes_written) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    if (buffer_size < instruction->size) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer too small");
    }

    size_t offset = 0;

    /* Write opcode */
    out_buffer[offset++] = instruction->opcode;

    /* Write operands - simplified encoding based on instruction size */
    u32 operand_values[6] = {
        instruction->arg1, instruction->arg2, instruction->arg3,
        instruction->arg4, instruction->arg5, instruction->arg6
    };

    /* For now, use a simple encoding scheme based on opcode */
    /* This should be expanded to handle all instruction types properly */
    switch (instruction->opcode) {
        case 8: /* Mov: opcode + reg8 + reg8 */
            if (offset + 2 > buffer_size) {
                return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
            }
            out_buffer[offset++] = (u8)operand_values[0];
            out_buffer[offset++] = (u8)operand_values[1];
            break;

        case 9: /* MovLong: opcode + reg32 + reg32 */
            if (offset + 8 > buffer_size) {
                return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
            }
            out_buffer[offset++] = (u8)(operand_values[0] & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[0] >> 8) & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[0] >> 16) & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[0] >> 24) & 0xFF);
            out_buffer[offset++] = (u8)(operand_values[1] & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[1] >> 8) & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[1] >> 16) & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[1] >> 24) & 0xFF);
            break;

        case 122: /* LoadConstZero: opcode + reg8 */
        case 118: /* LoadConstUndefined: opcode + reg8 */
        case 119: /* LoadConstNull: opcode + reg8 */
        case 120: /* LoadConstTrue: opcode + reg8 */
        case 121: /* LoadConstFalse: opcode + reg8 */
        case 92:  /* Ret: opcode + reg8 */
            if (offset + 1 > buffer_size) {
                return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
            }
            out_buffer[offset++] = (u8)operand_values[0];
            break;

        case 22: /* Add: opcode + reg8 + reg8 + reg8 */
        case 29: /* Sub: opcode + reg8 + reg8 + reg8 */
        case 24: /* Mul: opcode + reg8 + reg8 + reg8 */
        case 26: /* Div: opcode + reg8 + reg8 + reg8 */
            if (offset + 3 > buffer_size) {
                return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
            }
            out_buffer[offset++] = (u8)operand_values[0];
            out_buffer[offset++] = (u8)operand_values[1];
            out_buffer[offset++] = (u8)operand_values[2];
            break;

        case 142: /* Jmp: opcode + addr8 */
            if (offset + 1 > buffer_size) {
                return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
            }
            out_buffer[offset++] = (u8)operand_values[0];
            break;

        case 143: /* JmpLong: opcode + addr32 */
            if (offset + 4 > buffer_size) {
                return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer overflow");
            }
            out_buffer[offset++] = (u8)(operand_values[0] & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[0] >> 8) & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[0] >> 16) & 0xFF);
            out_buffer[offset++] = (u8)((operand_values[0] >> 24) & 0xFF);
            break;

        default:
            /* For unknown opcodes, just write the opcode */
            break;
    }

    *out_bytes_written = offset;
    return SUCCESS_RESULT();
}

/* Encode multiple instructions */
Result hermes_encoder_encode_instructions(HermesEncoder* encoder, const char* asm_text,
                                         u8* out_buffer, size_t buffer_size, size_t* out_bytes_written) {
    if (!encoder || !asm_text || !out_buffer || !out_bytes_written) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    size_t total_written = 0;
    const char* line_start = asm_text;

    while (*line_start) {
        /* Find end of line */
        const char* line_end = line_start;
        while (*line_end && *line_end != '\n' && *line_end != '\r') {
            line_end++;
        }

        /* Extract line */
        size_t line_len = line_end - line_start;
        if (line_len == 0) {
            line_start = line_end;
            if (*line_start) line_start++;
            continue;
        }

        char line[256] = {0};
        if (line_len >= sizeof(line)) {
            return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Line too long");
        }
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Skip empty lines or comments */
        const char* trim = line;
        while (*trim && isspace(*trim)) trim++;
        if (*trim == '\0' || *trim == '#') {
            line_start = line_end;
            if (*line_start) line_start++;
            continue;
        }

        /* Parse and encode instruction */
        EncodedInstruction instruction;
        RETURN_IF_ERROR(hermes_encoder_parse_instruction(encoder, line, &instruction));

        if (total_written + instruction.size > buffer_size) {
            return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer too small for all instructions");
        }

        size_t bytes_written;
        RETURN_IF_ERROR(hermes_encoder_encode_instruction(encoder, &instruction,
                                                         out_buffer + total_written,
                                                         buffer_size - total_written,
                                                         &bytes_written));

        total_written += bytes_written;

        /* Move to next line */
        line_start = line_end;
        if (*line_start) line_start++;
    }

    *out_bytes_written = total_written;
    return SUCCESS_RESULT();
}
