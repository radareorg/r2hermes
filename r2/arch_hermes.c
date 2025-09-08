/* radare2 - LGPL - Copyright 2024 - hermes-dec */

#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>

// Include hermesdec headers
#include "../include/hermesdec/hermesdec.h"
#include "../include/opcodes/hermes_opcodes.h"
#include "../include/parsers/hbc_bytecode_parser.h"

#define MAX_OP_SIZE 16

typedef struct {
    HermesDec *hd;
    u32 current_function_id;
    u32 function_offset;
    u32 function_size;
} HermesArchSession;

static bool hermes_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
    R_RETURN_VAL_IF_FAIL (s && op, false);

    if (op->size < 1 || !op->bytes) {
        return false;
    }

    HermesArchSession *hs = (HermesArchSession *)s->data;
    if (!hs || !hs->hd) {
        return false;
    }

    // Check if we're within the current function bounds
    if (op->addr < hs->function_offset || op->addr >= hs->function_offset + hs->function_size) {
        // Try to find the function containing this address
        u32 func_count = hermesdec_function_count(hs->hd);
        for (u32 i = 0; i < func_count; i++) {
            const char *name;
            u32 offset, size, param_count;
            Result result = hermesdec_get_function_info(hs->hd, i, &name, &offset, &size, &param_count);
            if (result.code == RESULT_SUCCESS) {
                if (op->addr >= offset && op->addr < offset + size) {
                    hs->current_function_id = i;
                    hs->function_offset = offset;
                    hs->function_size = size;
                    break;
                }
            }
        }
    }

    // Get function bytecode
    const u8 *bytecode;
    u32 bytecode_size;
    Result bc_result = hermesdec_get_function_bytecode(hs->hd, hs->current_function_id, &bytecode, &bytecode_size);
    if (bc_result.code != RESULT_SUCCESS) {
        return false;
    }

    // Calculate relative offset within function
    u32 rel_addr = op->addr - hs->function_offset;
    if (rel_addr >= bytecode_size) {
        return false;
    }

    // Get the opcode
    u8 opcode = bytecode[rel_addr];
    op->nopcode = 1;
    op->family = R_ANAL_OP_FAMILY_CPU;
    op->type = R_ANAL_OP_TYPE_UNK;

    // Parse operands based on opcode
    const char *mnemonic = "invalid";
    u32 operand_count = 0;
    u32 operands[6] = {0};

    // This is a simplified implementation - in practice you'd need to parse
    // the full instruction format based on the opcode
    switch (opcode) {
    case OP_Mov:
        mnemonic = "mov";
        op->type = R_ANAL_OP_TYPE_MOV;
        operand_count = 2;
        if (rel_addr + 2 < bytecode_size) {
            operands[0] = bytecode[rel_addr + 1];
            operands[1] = bytecode[rel_addr + 2];
            op->size = 3;
        }
        break;
    case OP_Add:
        mnemonic = "add";
        op->type = R_ANAL_OP_TYPE_ADD;
        operand_count = 3;
        if (rel_addr + 3 < bytecode_size) {
            operands[0] = bytecode[rel_addr + 1];
            operands[1] = bytecode[rel_addr + 2];
            operands[2] = bytecode[rel_addr + 3];
            op->size = 4;
        }
        break;
    case OP_Ret:
        mnemonic = "ret";
        op->type = R_ANAL_OP_TYPE_RET;
        op->size = 1;
        break;
    case OP_Jmp:
        mnemonic = "jmp";
        op->type = R_ANAL_OP_TYPE_JMP;
        if (rel_addr + 2 < bytecode_size) {
            i16 offset = (i16)((bytecode[rel_addr + 1] << 8) | bytecode[rel_addr + 2]);
            operands[0] = op->addr + 3 + offset;
            op->jump = operands[0];
            op->size = 3;
        }
        break;
    case OP_Call:
        mnemonic = "call";
        op->type = R_ANAL_OP_TYPE_CALL;
        if (rel_addr + 2 < bytecode_size) {
            operands[0] = bytecode[rel_addr + 1];
            operands[1] = bytecode[rel_addr + 2];
            op->size = 3;
        }
        break;
    default:
        // For unknown opcodes, just set size to 1
        op->size = 1;
        break;
    }

    // Build mnemonic string
    if (operand_count > 0) {
        char mnem_buf[256];
        snprintf(mnem_buf, sizeof(mnem_buf), "%s", mnemonic);
        for (u32 i = 0; i < operand_count; i++) {
            if (i == 0) {
                char temp[32];
                snprintf(temp, sizeof(temp), " r%d", operands[i]);
                strncat(mnem_buf, temp, sizeof(mnem_buf) - strlen(mnem_buf) - 1);
            } else {
                char temp[32];
                snprintf(temp, sizeof(temp), ", r%d", operands[i]);
                strncat(mnem_buf, temp, sizeof(mnem_buf) - strlen(mnem_buf) - 1);
            }
        }
        op->mnemonic = strdup(mnem_buf);
    } else {
        op->mnemonic = strdup(mnemonic);
    }

    return true;
}

static int hermes_info(RArchSession *s, ut32 q) {
    switch (q) {
    case R_ARCH_INFO_CODE_ALIGN:
        return 1;
    case R_ARCH_INFO_MAXOP_SIZE:
        return MAX_OP_SIZE;
    case R_ARCH_INFO_INVOP_SIZE:
        return 1;
    case R_ARCH_INFO_MINOP_SIZE:
        return 1;
    }
    return 0;
}

static char *hermes_mnemonics(RArchSession *s, int id, bool json) {
    // This would need to be implemented to return mnemonic names
    // For now, return NULL
    return NULL;
}

static bool hermes_init(RArchSession *s) {
    R_RETURN_VAL_IF_FAIL (s, false);
    s->data = R_NEW0(HermesArchSession);
    if (!s->data) {
        return false;
    }
    HermesArchSession *hs = (HermesArchSession *)s->data;
    hs->hd = NULL;
    hs->current_function_id = 0;
    hs->function_offset = 0;
    hs->function_size = 0;
    return true;
}

static bool hermes_fini(RArchSession *s) {
    R_RETURN_VAL_IF_FAIL (s, false);
    HermesArchSession *hs = (HermesArchSession *)s->data;
    if (hs) {
        if (hs->hd) {
            hermesdec_close(hs->hd);
        }
        free(hs);
        s->data = NULL;
    }
    return true;
}



const RArchPlugin r_arch_plugin_hermes = {
    .meta = {
        .name = "hermes",
        .author = "hermes-dec",
        .desc = "Hermes bytecode disassembler",
        .license = "LGPL-3.0-only",
    },
    .arch = "hermes",
    .bits = R_SYS_BITS_PACK1(8),
    .decode = &hermes_decode,
    .info = hermes_info,
    .mnemonics = hermes_mnemonics,
    .init = hermes_init,
    .fini = hermes_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_hermes,
    .version = R2_VERSION
};
#endif