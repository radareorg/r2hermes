/* radare2 - LGPL - Copyright 2024 - hermes-dec */

#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>

#ifndef R2_VERSION
#define R2_VERSION "6.0.3"
#endif

// Include hermesdec headers
#include "../include/hermesdec/hermesdec.h"
#include "../include/opcodes/hermes_opcodes.h"
#include "../include/parsers/hbc_bytecode_parser.h"
#include "../include/parsers/hbc_file_parser.h"

#define MAX_OP_SIZE 16

typedef struct {
    ut32 bytecode_version; /* cached from RBinInfo->cpu if available */
    HermesDec* hd; /* Hermes file handle for string table access */
    u32 string_count;
    const void* small_string_table;
    const void* overflow_string_table;
    u64 string_storage_offset;
} HermesArchSession;

// Forward declarations
static ut32 hermes_detect_version_from_bin(RArchSession *s);
static bool hermes_load_string_tables(HermesArchSession *hs, RArchSession *s);

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



static bool hermes_load_string_tables(HermesArchSession *hs, RArchSession *s) {
    if (!hs || !s || !s->arch || !s->arch->binb.bin) {
        return false;
    }

    RBin *bin = s->arch->binb.bin;
    RBinInfo *bi = r_bin_get_info(bin);
    if (!bi || !bi->file) {
        return false;
    }

    /* Try to open the file with hermesdec */
    if (hs->hd) {
        hermesdec_close(hs->hd);
        hs->hd = NULL;
    }

    Result res = hermesdec_open(bi->file, &hs->hd);
    if (res.code != RESULT_SUCCESS) {
        return false;
    }

    /* Get string count */
    hs->string_count = hermesdec_string_count(hs->hd);

    /* Extract string tables using the API */
    Result table_res = hermesdec_get_string_tables(hs->hd, &hs->string_count,
                                                   &hs->small_string_table,
                                                   &hs->overflow_string_table,
                                                   &hs->string_storage_offset);
    if (table_res.code != RESULT_SUCCESS) {
        return false;
    }

    return true;
}

static bool hermes_opcode_is_conditional(u8 opcode) {
    switch (opcode) {
    case OP_JmpTrue:
    case OP_JmpTrueLong:
    case OP_JmpFalse:
    case OP_JmpFalseLong:
    case OP_JmpUndefined:
    case OP_JmpUndefinedLong:
        return true;
    default:
        break;
    }
    /* Relational and equality conditional jumps occupy 152..191 */
    if (opcode >= OP_JLess && opcode <= OP_JStrictNotEqualLong) {
        return true;
    }
    return false;
}

static void hermes_parse_operands_and_set_ptr(RAnalOp *op, const ut8* bytes, ut32 size, ut8 opcode, HermesArchSession *hs) {
    // Get instruction set
    ut32 count;
    Instruction* inst_set = get_instruction_set_v96(&count);
    if (!inst_set || opcode >= count) {
        return;
    }

    const Instruction* inst = &inst_set[opcode];
    if (!inst) {
        return;
    }

    // Parse operands
    ut32 operand_values[6] = {0};
    size_t pos = 1; // Skip opcode byte

    for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
        if (pos >= size) break;

        switch (inst->operands[i].operand_type) {
            case OPERAND_TYPE_REG8:
            case OPERAND_TYPE_UINT8:
            case OPERAND_TYPE_ADDR8:
                if (pos < size) {
                    operand_values[i] = bytes[pos];
                    pos += 1;
                }
                break;
            case OPERAND_TYPE_UINT16:
                if (pos + 1 < size) {
                    operand_values[i] = (bytes[pos + 1] << 8) | bytes[pos];
                    pos += 2;
                }
                break;
            case OPERAND_TYPE_REG32:
            case OPERAND_TYPE_UINT32:
            case OPERAND_TYPE_ADDR32:
                if (pos + 3 < size) {
                    operand_values[i] = (bytes[pos + 3] << 24) | (bytes[pos + 2] << 16) |
                                       (bytes[pos + 1] << 8) | bytes[pos];
                    pos += 4;
                }
                break;
            default:
                break;
        }

        // Check if this operand is a string ID
        if (inst->operands[i].operand_meaning == OPERAND_MEANING_STRING_ID) {
            ut32 string_id = operand_values[i];
            if (string_id < hs->string_count && hs->hd) {
                HermesStringMeta meta;
                Result meta_result = hermesdec_get_string_meta(hs->hd, string_id, &meta);
                if (meta_result.code == RESULT_SUCCESS) {
                    // Set op->ptr to the string address
                    op->ptr = (st64)(hs->string_storage_offset + meta.offset);
                }
            }
        }
        // Check if this operand is a function ID
        else if (inst->operands[i].operand_meaning == OPERAND_MEANING_FUNCTION_ID) {
            ut32 function_id = operand_values[i];
            if (hs->hd) {
                const char* name = NULL;
                ut32 offset = 0, sz = 0, param_count = 0;
                Result func_result = hermesdec_get_function_info(hs->hd, function_id, &name, &offset, &sz, &param_count);
                if (func_result.code == RESULT_SUCCESS) {
                    // Set op->ptr to the function address
                    op->ptr = (st64)offset;
                }
            }
        }
    }
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

    /* Load string tables if not already loaded */
    if (!hs->hd) {
        hermes_load_string_tables(hs, s);
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
        true /* resolve_string_ids */,
        hs->string_count,
        hs->small_string_table,
        hs->overflow_string_table,
        hs->string_storage_offset,
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

    // Parse operands and set ptr for string/function references
    hermes_parse_operands_and_set_ptr(op, op->bytes, op->size, opcode, hs);

    if (opcode == OP_Ret) {
        op->type = R_ANAL_OP_TYPE_RET;
        return true;
    }

    if (hermes_opcode_is_conditional(opcode)) {
        op->type = R_ANAL_OP_TYPE_CJMP;
        op->jump = jmp;                 /* taken */
        op->fail = op->addr + op->size; /* fall-through */
        return true;
    }

    if (opcode == OP_Jmp || opcode == OP_JmpLong) {
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = jmp;
        return true;
    }

    if (is_call) {
        op->type = R_ANAL_OP_TYPE_CALL;
        op->jump = jmp;                 /* if resolvable */
        op->fail = op->addr + op->size; /* returns here */
        return true;
    }

    // Arithmetic operations
    if (opcode == OP_Add || opcode == OP_AddN || opcode == OP_Add32 ||
        opcode == OP_AddEmptyString) {
        op->type = R_ANAL_OP_TYPE_ADD;
    } else if (opcode == OP_Sub || opcode == OP_SubN || opcode == OP_Sub32) {
        op->type = R_ANAL_OP_TYPE_SUB;
    } else if (opcode == OP_Mul || opcode == OP_MulN || opcode == OP_Mul32) {
        op->type = R_ANAL_OP_TYPE_MUL;
    } else if (opcode == OP_Div || opcode == OP_DivN || opcode == OP_Divi32 || opcode == OP_Divu32) {
        op->type = R_ANAL_OP_TYPE_DIV;
    } else if (opcode == OP_Mod) {
        op->type = R_ANAL_OP_TYPE_MOD;
    }
    // Bitwise operations
    else if (opcode == OP_BitAnd) {
        op->type = R_ANAL_OP_TYPE_AND;
    } else if (opcode == OP_BitOr) {
        op->type = R_ANAL_OP_TYPE_OR;
    } else if (opcode == OP_BitXor) {
        op->type = R_ANAL_OP_TYPE_XOR;
    } else if (opcode == OP_BitNot || opcode == OP_Not) {
        op->type = R_ANAL_OP_TYPE_NOT;
    } else if (opcode == OP_LShift) {
        op->type = R_ANAL_OP_TYPE_SHL;
    } else if (opcode == OP_RShift) {
        op->type = R_ANAL_OP_TYPE_SHR;
    } else if (opcode == OP_URshift) {
        op->type = R_ANAL_OP_TYPE_SHR;
    }
    // Move operations
    else if (opcode == OP_Mov || opcode == OP_MovLong) {
        op->type = R_ANAL_OP_TYPE_MOV;
    }
    // Increment/Decrement
    else if (opcode == OP_Inc) {
        op->type = R_ANAL_OP_TYPE_ADD;
    } else if (opcode == OP_Dec) {
        op->type = R_ANAL_OP_TYPE_SUB;
    }
    // Unary operations
    else if (opcode == OP_Negate) {
        op->type = R_ANAL_OP_TYPE_NOT;
    }
    // Load operations
    else if (opcode == OP_Loadi8 || opcode == OP_Loadu8 || opcode == OP_Loadi16 ||
             opcode == OP_Loadu16 || opcode == OP_Loadi32 || opcode == OP_Loadu32 ||
             opcode == OP_GetById || opcode == OP_GetByIdLong || opcode == OP_GetByIdShort ||
             opcode == OP_GetByVal || opcode == OP_TryGetById || opcode == OP_TryGetByIdLong ||
             opcode == OP_LoadFromEnvironment || opcode == OP_LoadFromEnvironmentL ||
             opcode == OP_GetEnvironment || opcode == OP_LoadParam || opcode == OP_LoadParamLong ||
             opcode == OP_LoadConstUInt8 || opcode == OP_LoadConstInt ||
             opcode == OP_LoadConstDouble || opcode == OP_LoadConstBigInt ||
             opcode == OP_LoadConstBigIntLongIndex || opcode == OP_LoadConstString ||
             opcode == OP_LoadConstStringLongIndex || opcode == OP_LoadConstEmpty ||
             opcode == OP_LoadConstUndefined || opcode == OP_LoadConstNull ||
             opcode == OP_LoadConstTrue || opcode == OP_LoadConstFalse ||
             opcode == OP_LoadConstZero || opcode == OP_LoadThisNS ||
             opcode == OP_GetBuiltinClosure || opcode == OP_GetGlobalObject ||
             opcode == OP_GetNewTarget || opcode == OP_GetArgumentsPropByVal ||
             opcode == OP_GetArgumentsLength || opcode == OP_GetPNameList ||
             opcode == OP_GetNextPName) {
        op->type = R_ANAL_OP_TYPE_LOAD;
    }
    // Store operations
    else if (opcode == OP_Store8 || opcode == OP_Store16 || opcode == OP_Store32 ||
             opcode == OP_PutById || opcode == OP_PutByIdLong ||
             opcode == OP_PutByVal || opcode == OP_TryPutById || opcode == OP_TryPutByIdLong ||
             opcode == OP_PutNewOwnById || opcode == OP_PutNewOwnByIdLong ||
             opcode == OP_PutNewOwnByIdShort || opcode == OP_PutNewOwnNEById ||
             opcode == OP_PutNewOwnNEByIdLong || opcode == OP_PutOwnByIndex ||
             opcode == OP_PutOwnByIndexL || opcode == OP_PutOwnByVal ||
             opcode == OP_PutOwnGetterSetterByVal ||
             opcode == OP_StoreToEnvironment || opcode == OP_StoreToEnvironmentL ||
             opcode == OP_StoreNPToEnvironment || opcode == OP_StoreNPToEnvironmentL) {
        op->type = R_ANAL_OP_TYPE_STORE;
    }
    // Comparison operations
    else if (opcode == OP_Eq || opcode == OP_StrictEq || opcode == OP_Neq ||
             opcode == OP_StrictNeq || opcode == OP_Less || opcode == OP_Greater ||
             opcode == OP_LessEq || opcode == OP_GreaterEq || opcode == OP_IsIn ||
             opcode == OP_InstanceOf || opcode == OP_TypeOf) {
        op->type = R_ANAL_OP_TYPE_CMP;
    }
    // Object/Array creation
    else if (opcode == OP_NewObject || opcode == OP_NewObjectWithParent ||
             opcode == OP_NewObjectWithBuffer || opcode == OP_NewObjectWithBufferLong ||
             opcode == OP_NewArray || opcode == OP_NewArrayWithBuffer ||
             opcode == OP_NewArrayWithBufferLong || opcode == OP_CreateClosure ||
             opcode == OP_CreateClosureLongIndex || opcode == OP_CreateGeneratorClosure ||
             opcode == OP_CreateGeneratorClosureLongIndex || opcode == OP_CreateAsyncClosure ||
             opcode == OP_CreateAsyncClosureLongIndex || opcode == OP_CreateGenerator ||
             opcode == OP_CreateGeneratorLongIndex || opcode == OP_CreateThis ||
             opcode == OP_CreateRegExp) {
        op->type = R_ANAL_OP_TYPE_NEW;
    }
    // Type conversion operations
    else if (opcode == OP_ToNumber || opcode == OP_ToNumeric || opcode == OP_ToInt32 ||
             opcode == OP_CoerceThisNS) {
        op->type = R_ANAL_OP_TYPE_CAST;
    }
    // Switch operations
    else if (opcode == OP_SwitchImm) {
        op->type = R_ANAL_OP_TYPE_SWITCH;
    }
    // Iterator operations
    else if (opcode == OP_IteratorBegin || opcode == OP_IteratorNext || opcode == OP_IteratorClose) {
        op->type = R_ANAL_OP_TYPE_LOAD; // Iterator operations involve loading values
    }
    // Environment operations
    else if (opcode == OP_CreateEnvironment || opcode == OP_CreateInnerEnvironment ||
             opcode == OP_DeclareGlobalVar || opcode == OP_ThrowIfHasRestrictedGlobalProperty) {
        op->type = R_ANAL_OP_TYPE_STORE; // Environment setup involves storing
    }
    // Special operations
    else if (opcode == OP_Unreachable) {
        op->type = R_ANAL_OP_TYPE_ILL;
    } else if (opcode == OP_Throw || opcode == OP_ThrowIfEmpty) {
        op->type = R_ANAL_OP_TYPE_TRAP;
    } else if (opcode == OP_Catch) {
        op->type = R_ANAL_OP_TYPE_TRAP; // Exception handling
    } else if (opcode == OP_Debugger) {
        op->type = R_ANAL_OP_TYPE_DEBUG;
    } else if (opcode == OP_AsyncBreakCheck || opcode == OP_ProfilePoint) {
        op->type = R_ANAL_OP_TYPE_NOP;
    } else if (opcode == OP_SelectObject) {
        op->type = R_ANAL_OP_TYPE_MOV; // Object selection is like a move
    } else if (opcode == OP_DelById || opcode == OP_DelByIdLong || opcode == OP_DelByVal) {
        op->type = R_ANAL_OP_TYPE_STORE; // Delete operations modify storage
    } else if (opcode == OP_ReifyArguments) {
        op->type = R_ANAL_OP_TYPE_LOAD; // Reifying arguments loads them
    } else if (opcode == OP_StartGenerator || opcode == OP_ResumeGenerator ||
               opcode == OP_CompleteGenerator || opcode == OP_SaveGenerator ||
               opcode == OP_SaveGeneratorLong) {
        op->type = R_ANAL_OP_TYPE_CALL; // Generator operations are like function calls
    } else if (opcode == OP_DirectEval) {
        op->type = R_ANAL_OP_TYPE_CALL; // Eval is like a function call
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

static bool hermes_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
    (void)mask;
    R_RETURN_VAL_IF_FAIL (s && op, false);

    HermesArchSession *hs = (HermesArchSession *)s->data;
    if (!hs || !op->mnemonic) {
        return false;
    }

    if (!hs->bytecode_version) {
        hs->bytecode_version = hermes_detect_version_from_bin(s);
        if (!hs->bytecode_version) {
            hs->bytecode_version = 96;
        }
    }

    const char *asm_line = op->mnemonic;

    /* Conservative buffer for a single instruction */
    ut8 tmp[MAX_OP_SIZE];
    size_t written = 0;

    Result res = hermesdec_encode_instruction(
        asm_line,
        hs->bytecode_version,
        tmp,
        sizeof(tmp),
        &written
    );
    if (res.code != RESULT_SUCCESS || written == 0 || written > sizeof(tmp)) {
        return false;
    }

    /* Store into op */
    free(op->bytes);
    op->bytes = (ut8*)malloc(written);
    if (!op->bytes) {
        op->size = 0;
        return false;
    }
    memcpy(op->bytes, tmp, written);
    op->size = (int)written;
    return true;
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
        if (hs->hd) {
            hermesdec_close(hs->hd);
            hs->hd = NULL;
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
    .bits = R_SYS_BITS_PACK1(64),
    .decode = &hermes_decode,
    .encode = &hermes_encode,
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
