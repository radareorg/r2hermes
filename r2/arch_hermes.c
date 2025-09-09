/* radare2 - LGPL - Copyright 2024 - hermes-dec */

#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>

// Include hermesdec headers
#include "../include/hermesdec/hermesdec.h"

#define MAX_OP_SIZE 16

typedef struct {
    HermesDec *hd;
    HermesInstruction *instructions;
    u32 instruction_count;
    u32 current_instruction_index;
    ut64 base_addr;
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

    // Find the instruction at this address
    for (u32 i = 0; i < hs->instruction_count; i++) {
        if (hs->instructions[i].abs_addr == op->addr) {
            HermesInstruction *hi = &hs->instructions[i];

            op->size = 1; // Default size
            op->type = R_ANAL_OP_TYPE_UNK;
            op->family = R_ANAL_OP_FAMILY_CPU;

            // Set operation type based on instruction properties
            if (hi->is_jump) {
                op->type = R_ANAL_OP_TYPE_JMP;
                if (hi->code_targets_count > 0) {
                    op->jump = hs->base_addr + hi->code_targets[0];
                }
            } else if (hi->is_call) {
                op->type = R_ANAL_OP_TYPE_CALL;
                if (hi->code_targets_count > 0) {
                    op->jump = hs->base_addr + hi->code_targets[0];
                }
            } else if (strcmp(hi->mnemonic, "Ret") == 0) {
                op->type = R_ANAL_OP_TYPE_RET;
            } else if (strcmp(hi->mnemonic, "Mov") == 0) {
                op->type = R_ANAL_OP_TYPE_MOV;
            } else if (strcmp(hi->mnemonic, "Add") == 0 || strcmp(hi->mnemonic, "Sub") == 0) {
                op->type = R_ANAL_OP_TYPE_ADD;
            }

            // Set mnemonic
            if (hi->text) {
                op->mnemonic = strdup(hi->text);
            } else {
                op->mnemonic = strdup(hi->mnemonic ? hi->mnemonic : "unk");
            }

            // Calculate instruction size from next instruction
            if (i + 1 < hs->instruction_count) {
                op->size = hs->instructions[i + 1].abs_addr - hi->abs_addr;
            } else {
                op->size = 1; // Last instruction
            }

            return true;
        }
    }

    return false;
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
    hs->instructions = NULL;
    hs->instruction_count = 0;
    hs->current_instruction_index = 0;
    hs->base_addr = 0;
    return true;
}

static bool hermes_fini(RArchSession *s) {
    if (!s) {
        return false;
    }
    HermesArchSession *hs = (HermesArchSession *)s->data;
    if (hs) {
        if (hs->hd) {
            hermesdec_close(hs->hd);
        }
        if (hs->instructions) {
            hermesdec_free_instructions(hs->instructions, hs->instruction_count);
        }
        free(hs);
        s->data = NULL;
    }
    return true;
}

// Load instructions for all functions
static bool hermes_load_instructions(HermesArchSession *hs, const char *file_path) {
    if (!hs || !file_path) {
        return false;
    }

    // Open the file
    Result result = hermesdec_open(file_path, &hs->hd);
    if (result.code != RESULT_SUCCESS) {
        return false;
    }

    // Get function count
    u32 func_count = hermesdec_function_count(hs->hd);
    if (func_count == 0) {
        return false;
    }

    // For now, load instructions from the first function (global code)
    // In a full implementation, we'd need to handle multiple functions
    u32 function_id = 0; // Global code function

    HermesInstruction *instructions = NULL;
    u32 count = 0;
    result = hermesdec_decode_function_instructions(hs->hd, function_id, &instructions, &count);
    if (result.code != RESULT_SUCCESS) {
        hermesdec_close(hs->hd);
        hs->hd = NULL;
        return false;
    }

    hs->instructions = instructions;
    hs->instruction_count = count;
    hs->current_instruction_index = 0;

    // Get function offset for address calculation
    const char *name;
    u32 offset, size, param_count;
    result = hermesdec_get_function_info(hs->hd, function_id, &name, &offset, &size, &param_count);
    if (result.code == RESULT_SUCCESS) {
        hs->base_addr = offset;
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