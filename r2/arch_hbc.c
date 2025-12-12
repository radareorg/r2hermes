/* radare2 - LGPL - Copyright 2025 - libhbc */

#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>

#ifndef R2_VERSION
#define R2_VERSION "6.0.3"
#endif

// Include hermesdec headers
#include <hbc/hbc.h>
#include <hbc/opcodes/hermes_opcodes.h>
#include <hbc/parsers/hbc_bytecode_parser.h>
#include <hbc/parsers/hbc_file_parser.h>

#define MAX_OP_SIZE 16

typedef struct {
	ut32 bytecode_version; /* cached from RBinInfo->cpu if available */
	HBCState *hd; /* Hermes file handle for string table access */
	u32 string_count;
	const void *small_string_table;
	const void *overflow_string_table;
	u64 string_storage_offset;
} HermesArchSession;

/* Forward declarations */
static ut32 detect_version_from_bin(RArchSession *s);
static bool load_string_tables(HermesArchSession *hs, RArchSession *s);
static Instruction *get_instruction_set_by_version(ut32 version, ut32 *out_count);

static ut32 detect_version_from_bin(RArchSession *s) {
	if (!s || !s->arch || !s->arch->binb.bin) {
		return 96; /* sane default */
	}
	RBin *bin = s->arch->binb.bin;
	RBinInfo *bi = r_bin_get_info (bin);
	if (bi && bi->cpu && *bi->cpu) {
		const char *p = bi->cpu;
		/* Accept optional leading 'v' or 'V' (e.g., "v76") */
		if (p[0] == 'v' || p[0] == 'V') {
			p++;
		}
		/* cpu holds the version string set by bin plugin */
		ut32 v = (ut32)strtoul (p, NULL, 10);
		if (v > 0) {
			return v;
		}
	}
	return 96;
}

static bool load_string_tables(HermesArchSession *hs, RArchSession *s) {
	if (!hs || !s || !s->arch || !s->arch->binb.bin) {
		return false;
	}

	RBin *bin = s->arch->binb.bin;
	RBinInfo *bi = r_bin_get_info (bin);
	if (!bi || !bi->file) {
		return false;
	}

	/* Try to open the file with hermesdec */
	if (hs->hd) {
		hbc_close (hs->hd);
		hs->hd = NULL;
	}

	Result res = hbc_open (bi->file, &hs->hd);
	if (res.code != RESULT_SUCCESS) {
		return false;
	}

	/* If we can, get the file header to determine exact bytecode version */
	HBCHeader hh;
	if (hbc_get_header (hs->hd, &hh).code == RESULT_SUCCESS) {
		/* Cache version for instruction set selection */
		hs->bytecode_version = hh.version;
	}

	/* Get string count */
	hs->string_count = hbc_string_count (hs->hd);

	/* Extract string tables using the API */
	HBCStringTables tables;
	Result table_res = hbc_get_string_tables (hs->hd, &tables);
	if (table_res.code != RESULT_SUCCESS) {
		return false;
	}
	hs->string_count = tables.string_count;
	hs->small_string_table = tables.small_string_table;
	hs->overflow_string_table = tables.overflow_string_table;
	hs->string_storage_offset = tables.string_storage_offset;

	return true;
}

static Instruction *get_instruction_set_by_version(ut32 version, ut32 *out_count) {
	HBCISA isa = hbc_isa_getv (version);
	if (out_count) {
		*out_count = isa.count;
	}
	return isa.instructions;
}

static bool opcode_is_conditional(u8 opcode) {
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

static void parse_operands_and_set_ptr(RAnalOp *op, const ut8 *bytes, ut32 size, ut8 opcode, HermesArchSession *hs) {
	ut32 count;
	Instruction *inst_set = get_instruction_set_by_version (hs->bytecode_version, &count);
	if (!inst_set || opcode >= count) {
		return;
	}

	const Instruction *inst = &inst_set[opcode];
	if (!inst) {
		return;
	}

	// Parse operands
	ut32 operand_values[6] = { 0 };
	size_t pos = 1; // Skip opcode byte

	for (int i = 0; i < 6 && inst->operands[i].operand_type != OPERAND_TYPE_NONE; i++) {
		if (pos >= size) {
			break;
		}

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
				HBCStringMeta meta;
				Result meta_result = hbc_get_string_meta (hs->hd, string_id, &meta);
				if (meta_result.code == RESULT_SUCCESS) {
					// Set op->ptr to the string address
					op->ptr = (st64) (hs->string_storage_offset + meta.offset);
				}
			}
		}
		// Check if this operand is a function ID
		else if (inst->operands[i].operand_meaning == OPERAND_MEANING_FUNCTION_ID) {
			ut32 function_id = operand_values[i];
			if (hs->hd) {
				ut32 offset = 0, sz = 0, param_count = 0;
				HBCFunctionInfo fi;
				Result func_result = hbc_get_function_info (hs->hd, function_id, &fi);
				if (func_result.code == RESULT_SUCCESS) {
					// name = fi.name;
					offset = fi.offset;
					sz = fi.size;
					param_count = fi.param_count;
					// Set op->ptr to the function address
					op->ptr = (st64)offset;
				}
			}
		}
	}
}

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
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
		hs->bytecode_version = detect_version_from_bin (s);
	}

	/* Load string tables if not already loaded */
	if (!hs->hd) {
		load_string_tables (hs, s);
	}

	/* Build decode context */
	HBCStringTables string_tables = {
		.string_count = hs->string_count,
		.small_string_table = hs->small_string_table,
		.overflow_string_table = hs->overflow_string_table,
		.string_storage_offset = hs->string_storage_offset
	};
	HBCDecodeContext ctx = {
		.bytes = op->bytes,
		.len = MAX_OP_SIZE,
		.pc = op->addr,
		.bytecode_version = hs->bytecode_version,
		.asm_syntax = true,
		.resolve_string_ids = true,
		.string_tables = &string_tables
	};

	HBCSingleInstructionInfo sinfo;
	if (hbc_decode (&ctx, &sinfo).code != RESULT_SUCCESS) {
		return false;
	}

	op->mnemonic = sinfo.text? sinfo.text: strdup ("unk");
	op->size = sinfo.size? sinfo.size: 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;

	/* Parse operands and set ptr for string/function references */
	parse_operands_and_set_ptr (op, op->bytes, op->size, sinfo.opcode, hs);

	if (sinfo.opcode == OP_Ret) {
		op->type = R_ANAL_OP_TYPE_RET;
		return true;
	}

	if (opcode_is_conditional (sinfo.opcode)) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = sinfo.jump_target;
		op->fail = op->addr + op->size;
		return true;
	}

	if (sinfo.is_jump) {
		op->type = R_ANAL_OP_TYPE_JMP;
	}

	if (sinfo.opcode == OP_Jmp || sinfo.opcode == OP_JmpLong) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = sinfo.jump_target;
		return true;
	}

	if (sinfo.is_call) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = sinfo.jump_target;
		op->fail = op->addr + op->size;
		return true;
	}

	/* Classify opcode type */
	u8 opc = sinfo.opcode;

	switch (opc) {
	/* Arithmetic operations */
	case OP_Add:
	case OP_AddN:
	case OP_Add32:
	case OP_AddEmptyString:
	case OP_Inc:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case OP_Sub:
	case OP_SubN:
	case OP_Sub32:
	case OP_Dec:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case OP_Mul:
	case OP_MulN:
	case OP_Mul32:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case OP_Div:
	case OP_DivN:
	case OP_Divi32:
	case OP_Divu32:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case OP_Mod:
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	/* Bitwise operations */
	case OP_BitAnd:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case OP_BitOr:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case OP_BitXor:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case OP_BitNot:
	case OP_Not:
	case OP_Negate:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case OP_LShift:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case OP_RShift:
	case OP_URshift:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	/* Move operations */
	case OP_Mov:
	case OP_MovLong:
	case OP_Catch:
	case OP_SelectObject:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	/* Load operations */
	case OP_Loadi8:
	case OP_Loadu8:
	case OP_Loadi16:
	case OP_Loadu16:
	case OP_Loadi32:
	case OP_Loadu32:
	case OP_GetById:
	case OP_GetByIdLong:
	case OP_GetByIdShort:
	case OP_GetByVal:
	case OP_TryGetById:
	case OP_TryGetByIdLong:
	case OP_LoadFromEnvironment:
	case OP_LoadFromEnvironmentL:
	case OP_GetEnvironment:
	case OP_LoadParam:
	case OP_LoadParamLong:
	case OP_LoadConstUInt8:
	case OP_LoadConstInt:
	case OP_LoadConstDouble:
	case OP_LoadConstBigInt:
	case OP_LoadConstBigIntLongIndex:
	case OP_LoadConstString:
	case OP_LoadConstStringLongIndex:
	case OP_LoadConstEmpty:
	case OP_LoadConstUndefined:
	case OP_LoadConstNull:
	case OP_LoadConstTrue:
	case OP_LoadConstFalse:
	case OP_LoadConstZero:
	case OP_LoadThisNS:
	case OP_GetBuiltinClosure:
	case OP_GetGlobalObject:
	case OP_GetNewTarget:
	case OP_GetArgumentsPropByVal:
	case OP_GetArgumentsLength:
	case OP_GetPNameList:
	case OP_GetNextPName:
	case OP_IteratorBegin:
	case OP_IteratorNext:
	case OP_IteratorClose:
	case OP_ReifyArguments:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	/* Store operations */
	case OP_Store8:
	case OP_Store16:
	case OP_Store32:
	case OP_PutById:
	case OP_PutByIdLong:
	case OP_PutByVal:
	case OP_TryPutById:
	case OP_TryPutByIdLong:
	case OP_PutNewOwnById:
	case OP_PutNewOwnByIdLong:
	case OP_PutNewOwnByIdShort:
	case OP_PutNewOwnNEById:
	case OP_PutNewOwnNEByIdLong:
	case OP_PutOwnByIndex:
	case OP_PutOwnByIndexL:
	case OP_PutOwnByVal:
	case OP_PutOwnGetterSetterByVal:
	case OP_StoreToEnvironment:
	case OP_StoreToEnvironmentL:
	case OP_StoreNPToEnvironment:
	case OP_StoreNPToEnvironmentL:
	case OP_CreateEnvironment:
	case OP_CreateInnerEnvironment:
	case OP_DeclareGlobalVar:
	case OP_ThrowIfHasRestrictedGlobalProperty:
	case OP_DelById:
	case OP_DelByIdLong:
	case OP_DelByVal:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	/* Comparison operations */
	case OP_Eq:
	case OP_StrictEq:
	case OP_Neq:
	case OP_StrictNeq:
	case OP_Less:
	case OP_Greater:
	case OP_LessEq:
	case OP_GreaterEq:
	case OP_IsIn:
	case OP_InstanceOf:
	case OP_TypeOf:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	/* Object/Array creation */
	case OP_NewObject:
	case OP_NewObjectWithParent:
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
	case OP_NewArray:
	case OP_NewArrayWithBuffer:
	case OP_NewArrayWithBufferLong:
	case OP_CreateClosure:
	case OP_CreateClosureLongIndex:
	case OP_CreateGeneratorClosure:
	case OP_CreateGeneratorClosureLongIndex:
	case OP_CreateAsyncClosure:
	case OP_CreateAsyncClosureLongIndex:
	case OP_CreateGenerator:
	case OP_CreateGeneratorLongIndex:
	case OP_CreateThis:
	case OP_CreateRegExp:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	/* Type conversion operations */
	case OP_ToNumber:
	case OP_ToNumeric:
	case OP_ToInt32:
	case OP_CoerceThisNS:
		op->type = R_ANAL_OP_TYPE_CAST;
		break;
	/* Switch operations */
	case OP_SwitchImm:
		op->type = R_ANAL_OP_TYPE_SWITCH;
		break;
	/* Special operations */
	case OP_Unreachable:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case OP_Throw:
	case OP_ThrowIfEmpty:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case OP_Debugger:
		op->type = R_ANAL_OP_TYPE_DEBUG;
		break;
	case OP_AsyncBreakCheck:
	case OP_ProfilePoint:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case OP_StartGenerator:
	case OP_ResumeGenerator:
	case OP_CompleteGenerator:
	case OP_SaveGenerator:
	case OP_SaveGeneratorLong:
	case OP_DirectEval:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	default:
		break;
	}
	return true;
}

static int info(RArchSession *s, ut32 q) {
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

static char *mnemonics(RArchSession *s, int id, bool json) {
	(void)s;
	(void)id;
	(void)json;
	return NULL;
}

static bool encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	(void)mask;
	R_RETURN_VAL_IF_FAIL (s && op, false);

	HermesArchSession *hs = (HermesArchSession *)s->data;
	if (!hs || !op->mnemonic) {
		return false;
	}

	if (!hs->bytecode_version) {
		hs->bytecode_version = detect_version_from_bin (s);
		if (!hs->bytecode_version) {
			hs->bytecode_version = 96;
		}
	}

	const char *asm_line = op->mnemonic;

	/* Conservative buffer for a single instruction */
	ut8 tmp[MAX_OP_SIZE];
	size_t written = 0;

	HBCEncodeBuffer outbuf = { .buffer = tmp, .buffer_size = sizeof (tmp), .bytes_written = 0 };
	Result res = hbc_encode_instruction (
		asm_line,
		hs->bytecode_version,
		&outbuf);
	written = outbuf.bytes_written;
	if (res.code != RESULT_SUCCESS || written == 0 || written > sizeof (tmp)) {
		return false;
	}

	/* Store into op */
	free (op->bytes);
	op->bytes = (ut8 *)malloc (written);
	if (!op->bytes) {
		op->size = 0;
		return false;
	}
	memcpy (op->bytes, tmp, written);
	op->size = (int)written;
	return true;
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	s->data = R_NEW0 (HermesArchSession);
	HermesArchSession *hs = (HermesArchSession *)s->data;
	hs->bytecode_version = 0;
	return true;
}

static bool fini(RArchSession *s) {
	if (!s) {
		return false;
	}
	HermesArchSession *hs = (HermesArchSession *)s->data;
	if (hs) {
		if (hs->hd) {
			hbc_close (hs->hd);
			hs->hd = NULL;
		}
		free (hs);
		s->data = NULL;
	}
	return true;
}

const RArchPlugin r_arch_plugin_hermes = {
	.meta = {
		.name = "hermes",
		.author = "pancake",
		.desc = "Hermes bytecode disassembler",
		.license = "LGPL-3.0-only",
	},
	.arch = "hermes",
	.bits = R_SYS_BITS_PACK1 (64),
	.cpus = "v76,v90,v91,v92,v93,v94,v95,v96",
	.decode = &decode,
	.encode = &encode,
	.info = info,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = (void *)&r_arch_plugin_hermes,
	.version = R2_VERSION
};
#endif
