/* radare2 - LGPL - Copyright 2024 - hermes-dec */

#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>

// Include hermesdec headers
#include "../include/hermesdec/hermesdec.h"
#include "../include/opcodes/hermes_opcodes.h"

#define MAX_OP_SIZE 16

typedef struct {
    ut32 bytecode_version; /* cached from RBinInfo->cpu if available */
} HermesArchSession;

// Forward declarations
static ut32 hermes_detect_version_from_bin(RArchSession *s) {
    if (!s || !s->arch || !s->arch->binb.bin) {
        return 96; /* sane default */
    }
    RBin *bin = s->arch->binb.bin;
    RBinInfo *bi = r_bin_get_info(bin);
    if (bi && bi->cpu && *bi->cpu) {
        const char *p = bi->cpu;
        /* cpu holds the version string set by bin plugin */
        ut32 v = (ut32)strtoul(p, NULL, 10);
        if (v > 0) return v;
    }
    return 96;
}

static bool hermes_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
    R_RETURN_VAL_IF_FAIL (s && op, false);
    (void)mask;

    if (!op->bytes) {
        return false;
    }

    HermesArchSession *hs = (HermesArchSession *)s->data;
    if (!hs) {
        return false;
    }

    if (!hs->bytecode_version) {
        hs->bytecode_version = hermes_detect_version_from_bin(s);
    }

    /* Decode from the provided bytes directly (no preloading/scanning). */
    char *text = NULL;
    u32 size = 0;
    u8 opcode = 0;
    bool is_jump = false, is_call = false;
    u64 jmp = 0;
    size_t buflen = MAX_OP_SIZE; /* Radare2 provides at least this in op->bytes */
    Result rr = hermesdec_decode_single_instruction(
        op->bytes,
        buflen,
        hs->bytecode_version,
        op->addr,
        true /* asm syntax */,
        &text,
        &size,
        &opcode,
        &is_jump,
        &is_call,
        &jmp
    );
    if (rr.code != RESULT_SUCCESS) {
        return false;
    }

    op->mnemonic = text ? text : strdup("unk");
    op->size = size ? size : 1;
    op->type = R_ANAL_OP_TYPE_UNK;
    op->family = R_ANAL_OP_FAMILY_CPU;
    if (is_jump) {
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = jmp;
    } else if (is_call) {
        op->type = R_ANAL_OP_TYPE_CALL;
        op->jump = jmp;
    } else if (opcode == OP_Ret) {
        op->type = R_ANAL_OP_TYPE_RET;
    } else if (opcode == OP_Mov || opcode == OP_MovLong) {
        op->type = R_ANAL_OP_TYPE_MOV;
    } else if (opcode == OP_Add || opcode == OP_AddN || opcode == OP_Add32) {
        op->type = R_ANAL_OP_TYPE_ADD;
    } else if (opcode == OP_Sub || opcode == OP_SubN || opcode == OP_Sub32) {
        op->type = R_ANAL_OP_TYPE_SUB;
    }
    return true;
}

static int hermes_info(RArchSession *s, ut32 q) {
    (void)s;
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
    (void)s;
    (void)id;
    (void)json;
    // This would need to be implemented to return mnemonic names
    // For now, return NULL
    return NULL;
}

static bool hermes_init(RArchSession *s) {
    R_RETURN_VAL_IF_FAIL (s, false);
    s->data = R_NEW0(HermesArchSession);
    HermesArchSession *hs = (HermesArchSession *)s->data;
    hs->bytecode_version = 0;
    return true;
}

static bool hermes_fini(RArchSession *s) {
    if (!s) {
        return false;
    }
    HermesArchSession *hs = (HermesArchSession *)s->data;
    if (hs) {
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
    .bits = R_SYS_BITS_PACK1(64),
    .decode = &hermes_decode,
    .info = hermes_info,
    .mnemonics = hermes_mnemonics,
    .init = hermes_init,
    .fini = hermes_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = (void *)&r_arch_plugin_hermes,
    .version = R2_VERSION
};
#endif
