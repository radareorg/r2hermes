/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_anal.h>
#include <hbc/hbc.h>
#include <hbc/opcodes.h>
#include <hbc/bytecode.h>
#include <hbc/parser.h>

#define MAX_OP_SIZE 16

typedef struct {
	ut32 bytecode_version; /* cached from RBinInfo->cpu if available */
	HBC *hbc; /* Hermes data provider for query access */
	u32 string_count;
	const void *small_string_table;
	const void *overflow_string_table;
	u64 string_storage_offset;
	ut8 *tmp_buffer; /* temporary buffer for string operations */
	size_t tmp_buffer_size; /* size of tmp_buffer */
	ut64 tmp_buffer_offset; /* current offset in tmp_buffer */
} HermesArchSession;

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

#define READ_REG8(b, pos) ((u8) (b)[(pos)])
#define READ_UINT8(b, pos) ((u8) (b)[(pos)])
#define READ_UINT16(b, pos) ((u16) ((b)[(pos)] | ((b)[(pos) + 1] << 8)))
#define READ_UINT32(b, pos) ((u32) ((b)[(pos)] | ((b)[(pos) + 1] << 8) | ((b)[(pos) + 2] << 16) | ((b)[(pos) + 3] << 24)))
#define READ_INT8(b, pos) ((i8) (b)[(pos)])
#define READ_INT32(b, pos) ((i32)READ_UINT32 (b, pos))

#include "esil.inc.c"

static bool load_string_tables(HermesArchSession *hs, RArchSession *s) {
	if (!hs || !s || !s->arch || !s->arch->binb.bin) {
		return false;
	}

	RBin *bin = s->arch->binb.bin;
	RBinInfo *bi = r_bin_get_info (bin);
	if (!bi || !bi->file) {
		return false;
	}

	/* Try to open the file with hermesdec file provider (properly parses all tables) */
	hbc_free (hs->hbc);
	hs->hbc = hbc_new_file (bi->file);
	if (!hs->hbc) {
		return false;
	}

	/* If we can, get the file header to determine exact bytecode version */
	HBCHeader hh;
	if (hbc_hdr (hs->hbc, &hh).code == RESULT_SUCCESS) {
		/* Cache version for instruction set selection */
		hs->bytecode_version = hh.version;
	}

	/* Get string count */
	u32 string_count;
	Result count_res = hbc_str_count (hs->hbc, &string_count);
	if (count_res.code == RESULT_SUCCESS) {
		hs->string_count = string_count;
	}

	/* Extract string tables using the API */
	HBCStrs tables;
	Result table_res = hbc_str_tbl (hs->hbc, &tables);
	if (table_res.code != RESULT_SUCCESS) {
		return false;
	}
	hs->string_count = tables.string_count;
	hs->small_string_table = tables.small_string_table;
	hs->overflow_string_table = tables.overflow_string_table;
	hs->string_storage_offset = tables.string_storage_offset;

	return true;
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
		/* Relational and equality conditional jumps occupy 152..191 */
		if (opcode >= OP_JLess && opcode <= OP_JStrictNotEqualLong) {
			return true;
		}
		break;
	}
	return false;
}

static void parse_operands_and_set_ptr(RAnalOp *op, const ut8 *bytes, ut32 size, ut8 opcode, HermesArchSession *hs) {
	HBCISA isa = hbc_isa_getv (hs->bytecode_version);
	const Instruction *inst_set = isa.instructions;
	if (!inst_set || opcode >= isa.count) {
		return;
	}

	const Instruction *inst = &inst_set[opcode];

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
		case OPERAND_TYPE_IMM32:
			if (pos + 3 < size) {
				operand_values[i] = (bytes[pos + 3] << 24) | (bytes[pos + 2] << 16) |
					(bytes[pos + 1] << 8) | bytes[pos];
				pos += 4;
			}
			break;
		case OPERAND_TYPE_DOUBLE:
			/* Double is 8 bytes - just advance position, value not used for ptr setting */
			if (pos + 7 < size) {
				pos += 8;
			}
			break;
		case OPERAND_TYPE_NONE:
		default:
			/* OPERAND_TYPE_NONE is never reached due to loop condition */
			break;
		}

		HBCStringMeta meta; // Declare meta variable for string metadata
		// Check if this operand is a string ID
		if (inst->operands[i].operand_meaning == OPERAND_MEANING_STRING_ID) {
			ut32 string_id = operand_values[i];
			// Use my updated string resolution function that handles offset-based lookup
			const char *string_value;
			Result str_result = hbc_str (hs->hbc, string_id, &string_value);
			if (str_result.code == RESULT_SUCCESS) {
				// Store string in tmp buffer
				ut64 string_len = strlen (string_value);
				if (string_len + 1 > hs->tmp_buffer_size) {
					ut8 *new_buf = (ut8 *)realloc (hs->tmp_buffer, string_len + 1);
					if (new_buf) {
						hs->tmp_buffer = new_buf;
						hs->tmp_buffer_size = string_len + 1;
						hs->tmp_buffer_offset = 0;
					}
				}
				// Copy the string to tmp buffer
				if (hs->tmp_buffer) {
					memcpy (hs->tmp_buffer, string_value, string_len);
					hs->tmp_buffer_offset = (ut64)string_len + 1;
				}
				// Set op->ptr to the virtual address
				op->ptr = (st64) (0x10000000 + string_id);
				// Update string storage offset temporarily for this context
				hbc_str_meta (hs->hbc, string_id, &meta); // Keep for consistency
			}
		}
		// Check if this operand is a function ID
		else if (inst->operands[i].operand_meaning == OPERAND_MEANING_FUNCTION_ID) {
			ut32 function_id = operand_values[i];
			if (hs->hbc) {
				ut32 offset = 0;
				HBCFunc fi;
				Result func_result = hbc_func_info (hs->hbc, function_id, &fi);
				if (func_result.code == RESULT_SUCCESS) {
					// name = fi.name;
					offset = fi.offset;
					(void)fi.size;
					(void)fi.param_count;
					// Set op->ptr to the function address as a file offset
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
	if (!hs->hbc) {
		load_string_tables (hs, s);
	}

	/* Build decode context */
	HBCStrs string_tables = {
		.string_count = hs->string_count,
		.small_string_table = hs->small_string_table,
		.overflow_string_table = hs->overflow_string_table,
		.string_storage_offset = hs->string_storage_offset
	};
	HBCDecodeCtx ctx = {
		.bytes = op->bytes,
		.len = MAX_OP_SIZE,
		.pc = op->addr,
		.bytecode_version = hs->bytecode_version,
		.asm_syntax = true,
		.resolve_string_ids = true,
		.string_tables = &string_tables
	};

	HBCInsnInfo sinfo;
	if (hbc_dec (&ctx, &sinfo).code != RESULT_SUCCESS) {
		return false;
	}

	op->mnemonic = sinfo.text? strdup (sinfo.text): strdup ("unk");
	op->size = sinfo.size? sinfo.size: 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;

	/* Parse operands and set ptr for string/function references */
	parse_operands_and_set_ptr (op, op->bytes, op->size, sinfo.opcode, hs);

	if (sinfo.text) {
		char mnemonic_raw[64];
		const char *end = sinfo.text;
		while (*end && *end != ' ' && *end != '\t') {
			end++;
		}
		size_t len = end - sinfo.text;
		if (len > 0 && len < sizeof (mnemonic_raw)) {
			memcpy (mnemonic_raw, sinfo.text, len);
			mnemonic_raw[len] = '\0';
			char mnemonic[64];
			hbc_snake_to_camel (mnemonic_raw, mnemonic, sizeof (mnemonic));
			set_esil (op, mnemonic, op->bytes, op->addr);
		}
	}

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
	case R_ARCH_INFO_ISVM:
		return R_ARCH_INFO_ISVM;
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
	// TODO: not implemented
	return NULL;
}

static bool encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	(void)mask;
	R_RETURN_VAL_IF_FAIL (s && op, false);

	HermesArchSession *hs = (HermesArchSession *)s->data;
	if (!hs || !op->mnemonic) {
		return false;
	}

	// Initialize tmp_buffer if not already done
	if (!hs->tmp_buffer) {
		hs->tmp_buffer = (ut8 *)malloc (MAX_OP_SIZE + 1);
		hs->tmp_buffer_size = MAX_OP_SIZE + 1;
		hs->tmp_buffer_offset = 0;
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

	HBCEncBuf outbuf = { .buffer = tmp, .buffer_size = sizeof (tmp), .bytes_written = 0 };
	Result res = hbc_enc (
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
		if (hs->hbc) {
			hbc_free (hs->hbc);
			hs->hbc = NULL;
		}
		free (hs);
			s->data = NULL;
		if (hs->tmp_buffer) {
			free (hs->tmp_buffer);
			hs->tmp_buffer = NULL;
			hs->tmp_buffer_size = 0;
		}
	}
	return true;
}

/* Register profile for ESIL emulation */
static char *regs(RArchSession *s) {
	(void)s;
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}

	/* Define special registers */
	r_strbuf_append (sb, "=PC\tpc\n");
	r_strbuf_append (sb, "=SP\tr0\n");
	r_strbuf_append (sb, "=BP\tr1\n");
	r_strbuf_append (sb, "=A0\tr2\n");
	r_strbuf_append (sb, "=A1\tr3\n");
	r_strbuf_append (sb, "=A2\tr4\n");
	r_strbuf_append (sb, "=A3\tr5\n");

	/* Program counter - 64 bits at offset 0 */
	r_strbuf_append (sb, "gpr\tpc\t.64\t0\t0\n");

	/* Hermes VM has r0-r255 registers (256 total) */
	for (int i = 0; i < 256; i++) {
		r_strbuf_appendf (sb, "gpr\tr%d\t.64\t%d\t0\n", i, 8 + (i * 8));
	}

	return r_strbuf_drain (sb);
}

const RArchPlugin r_arch_plugin_r2hermes = {
	.meta = {
		.name = "hbc.arch",
		.author = "pancake",
		.desc = "Hermes bytecode disassembler",
		.license = "BSD",
	},
	.arch = "hbc",
	.bits = R_SYS_BITS_PACK1 (64),
	.cpus = "v76,v90,v91,v92,v93,v94,v95,v96",
	.decode = &decode,
	.encode = &encode,
	.regs = regs,
	.info = info,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = (void *)&r_arch_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
