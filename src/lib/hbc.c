#include <hbc/hbc.h>
#include <hbc/common.h>
#include <hbc/hbc.h>
#include <hbc/disassembly/hbc_disassembler.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/hermes_encoder.h>
#include <hbc/parsers/hbc_file_parser.h>
#include "hbc_internal.h"
#include <hbc/opcodes/hermes_opcodes.h>

/* Open and fully parse a Hermes bytecode file */
Result hbc_open(const char *path, HBC **out) {
	if (!path || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_open");
	}

	HBC *hd = (HBC *)calloc (1, sizeof (HBC));
	if (!hd) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HBC");
	}

	Result res = hbc_reader_init (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hd);
		return res;
	}

	res = hbc_reader_read_whole_file (&hd->reader, path);
	if (res.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&hd->reader);
		free (hd);
		return res;
	}

	*out = hd;
	return SUCCESS_RESULT ();
}

/* Open and parse from an in-memory buffer */
Result hbc_open_from_memory(const u8 *data, size_t size, HBC **out) {
	if (!data || size == 0 || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_open_from_memory");
	}

	HBC *hd = (HBC *)calloc (1, sizeof (HBC));
	if (!hd) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate HBC");
	}

	Result res = hbc_reader_init (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		free (hd);
		return res;
	}

	res = buffer_reader_init_from_memory (&hd->reader.file_buffer, data, size);
	if (res.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&hd->reader);
		free (hd);
		return res;
	}

	/* Parse header and all sections */
	res = hbc_reader_read_header (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_functions_robust (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_string_kinds (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_identifier_hashes (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_string_tables (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_arrays (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_bigints (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_regexp (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_cjs_modules (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	res = hbc_reader_read_function_sources (&hd->reader);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hd);
		return res;
	}
	(void)hbc_reader_read_debug_info; /* Debug info optional; callers can request if needed */

	*out = hd;
	return SUCCESS_RESULT ();
}

void hbc_close(HBC *hd) {
	if (!hd) {
		return;
	}
	hbc_reader_cleanup (&hd->reader);
	free (hd);
}

u32 hbc_function_count(HBC *hd) {
	if (!hd) {
		return 0;
	}
	return hd->reader.header.functionCount;
}

u32 hbc_string_count(HBC *hd) {
	if (!hd) {
		return 0;
	}
	return hd->reader.header.stringCount;
}

Result hbc_get_header(HBC *hd, HBCHeader *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_get_header");
	}
	HBCHeader *h = &hd->reader.header;
	out->magic = h->magic;
	out->version = h->version;
	memcpy (out->sourceHash, h->sourceHash, sizeof (out->sourceHash));
	out->fileLength = h->fileLength;
	out->globalCodeIndex = h->globalCodeIndex;
	out->functionCount = h->functionCount;
	out->stringKindCount = h->stringKindCount;
	out->identifierCount = h->identifierCount;
	out->stringCount = h->stringCount;
	out->overflowStringCount = h->overflowStringCount;
	out->stringStorageSize = h->stringStorageSize;
	out->bigIntCount = h->bigIntCount;
	out->bigIntStorageSize = h->bigIntStorageSize;
	out->regExpCount = h->regExpCount;
	out->regExpStorageSize = h->regExpStorageSize;
	out->arrayBufferSize = h->arrayBufferSize;
	out->objKeyBufferSize = h->objKeyBufferSize;
	out->objValueBufferSize = h->objValueBufferSize;
	out->segmentID = h->segmentID;
	out->cjsModuleCount = h->cjsModuleCount;
	out->functionSourceCount = h->functionSourceCount;
	out->debugInfoOffset = h->debugInfoOffset;
	out->staticBuiltins = h->staticBuiltins;
	out->cjsModulesStaticallyResolved = h->cjsModulesStaticallyResolved;
	out->hasAsync = h->hasAsync;
	return SUCCESS_RESULT ();
}

Result hbc_get_function_info(HBCState *hd, u32 function_id, HBCFunctionInfo *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	HBCReader *r = &hd->reader;
	if (function_id >= r->header.functionCount || !r->function_headers) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id");
	}
	FunctionHeader *fh = &r->function_headers[function_id];
	const char *fn = NULL;
	if (fh->functionName < r->header.stringCount && r->strings) {
		fn = r->strings[fh->functionName];
	}
	out->name = fn? fn: "unknown";
	out->offset = fh->offset;
	out->size = fh->bytecodeSizeInBytes;
	out->param_count = fh->paramCount;
	return SUCCESS_RESULT ();
}

Result hbc_get_string(HBC *hd, u32 index, const char **out_str) {
	if (!hd || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_get_string");
	}
	HBCReader *r = &hd->reader;
	if (!r->strings || index >= r->header.stringCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid string index");
	}
	*out_str = r->strings[index];
	return SUCCESS_RESULT ();
}

Result hbc_get_function_source(HBC *hd, u32 function_id, const char **out_str) {
	if (!hd || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_get_function_source");
	}
	*out_str = NULL;
	HBCReader *r = &hd->reader;
	if (!r->function_sources || r->function_source_count == 0) {
		return SUCCESS_RESULT ();
	}
	for (size_t i = 0; i < r->function_source_count; i++) {
		if (r->function_sources[i].function_id == function_id) {
			u32 sid = r->function_sources[i].string_id;
			if (sid < r->header.stringCount && r->strings) {
				*out_str = r->strings[sid];
			}
			break;
		}
	}
	return SUCCESS_RESULT ();
}

Result hbc_get_string_meta(HBC *hd, u32 index, HBCStringMeta *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_get_string_meta");
	}
	HBCReader *r = &hd->reader;
	if (index >= r->header.stringCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid string index");
	}
	u32 is_utf16 = r->small_string_table[index].isUTF16;
	u32 length = r->small_string_table[index].length;
	u32 off = r->small_string_table[index].offset;
	if (length == 0xFF) {
		u32 oi = off;
		off = r->overflow_string_table[oi].offset;
		length = r->overflow_string_table[oi].length;
	}
	out->isUTF16 = is_utf16 != 0;
	out->offset = r->string_storage_file_offset + off; // Return absolute file offset
	out->length = length;
	out->kind = (HBCStringKind) (r->string_kinds? r->string_kinds[index]: 0);
	return SUCCESS_RESULT ();
}

Result hbc_get_string_tables(HBCState *hd, HBCStringTables *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	HBCReader *r = &hd->reader;
	out->string_count = r->header.stringCount;
	out->small_string_table = r->small_string_table;
	out->overflow_string_table = r->overflow_string_table;
	out->string_storage_offset = r->string_storage_file_offset;
	return SUCCESS_RESULT ();
}

Result hbc_get_function_bytecode(HBC *hd, u32 function_id, const u8 **out_ptr, u32 *out_size) {
	if (!hd || !out_ptr || !out_size) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_get_function_bytecode");
	}
	HBCReader *r = &hd->reader;
	if (function_id >= r->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id");
	}
	FunctionHeader *fh = &r->function_headers[function_id];
	if (!fh) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No function header");
	}
	if (!fh->bytecode && fh->bytecodeSizeInBytes > 0) {
		/* Load bytecode slice from file buffer */
		if (fh->offset + fh->bytecodeSizeInBytes <= r->file_buffer.size) {
			fh->bytecode = (u8 *)malloc (fh->bytecodeSizeInBytes);
			if (!fh->bytecode) {
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM allocating bytecode buffer");
			}
			size_t saved = r->file_buffer.position;
			Result sr = buffer_reader_seek (&r->file_buffer, fh->offset);
			if (sr.code != RESULT_SUCCESS) {
				free (fh->bytecode);
				fh->bytecode = NULL;
				return sr;
			}
			sr = buffer_reader_read_bytes (&r->file_buffer, fh->bytecode, fh->bytecodeSizeInBytes);
			r->file_buffer.position = saved;
			if (sr.code != RESULT_SUCCESS) {
				free (fh->bytecode);
				fh->bytecode = NULL;
				return sr;
			}
		} else {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Bytecode slice out of bounds");
		}
	}
	*out_ptr = fh->bytecode;
	if (out_size) {
		*out_size = fh->bytecodeSizeInBytes;
	}
	return SUCCESS_RESULT ();
}

typedef Result(*DisasmWorkFn)(Disassembler *, void *);

static Result disassemble_into(StringBuffer *out, HBCDisassemblyOptions options, HBCReader *r, DisasmWorkFn work, void *ctx) {
	Disassembler d;
	if (options.asm_syntax) {
		fprintf (stderr, "[hermesdec] passing asm_syntax=1 to disassembler\n");
	}
	Result res = disassembler_init (&d, r, options);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}
	res = work (&d, ctx);
	if (res.code == RESULT_SUCCESS) {
		/* Append the disassembler output into provided buffer */
		res = string_buffer_append (out, d.output.data? d.output.data: "");
	}
	disassembler_cleanup (&d);
	return res;
}

static Result work_disassemble_all(Disassembler *d, void *ctx) {
	(void)ctx;
	return disassemble_all_functions (d);
}

typedef struct {
	u32 function_id;
} WorkFnCtx;

static Result work_disassemble_one(Disassembler *d, void *ctx) {
	WorkFnCtx *c = (WorkFnCtx *)ctx;
	return disassemble_function (d, c->function_id);
}

Result hbc_disassemble_function_to_buffer(
	HBCState *hd,
	HBCDisassemblyOptions options,
	u32 function_id,
	StringBuffer *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	HBCReader *r = &hd->reader;
	WorkFnCtx c = { .function_id = function_id };
	return disassemble_into (out, options, r, work_disassemble_one, &c);
}

Result hbc_disassemble_all_to_buffer(
	HBC *hd,
	HBCDisassemblyOptions options,
	StringBuffer *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_disassemble_all_to_buffer");
	}
	HBCReader *r = &hd->reader;
	return disassemble_into (out, options, r, work_disassemble_all, NULL);
}

Result hbc_decompile_all_to_buffer(HBCState *hd, HBCDecompileOptions options, StringBuffer *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	return decompile_all_to_buffer (&hd->reader, options, out);
}

Result hbc_decompile_function_to_buffer(HBCState *hd, u32 function_id, HBCDecompileOptions options, StringBuffer *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	return decompile_function_to_buffer (&hd->reader, function_id, options, out);
}

Result hbc_decompile_file(const char *input_file, const char *output_file) {
	return decompile_file (input_file, output_file);
}

Result hbc_validate_basic(HBC *hd, StringBuffer *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_validate_basic");
	}
	HBCReader *r = &hd->reader;
	Result res = string_buffer_append (out, "Validation report:\n");
	if (res.code != RESULT_SUCCESS) {
		return res;
	}
	char buf[256];
	snprintf (buf, sizeof (buf), "Functions count: %u\n", r->header.functionCount);
	RETURN_IF_ERROR (string_buffer_append (out, buf));
	size_t min_bytes = (size_t)r->header.functionCount * 16;
	size_t remaining = (r->file_buffer.size > sizeof (HBCHeader))? (r->file_buffer.size - sizeof (HBCHeader)): 0;
	snprintf (buf, sizeof (buf), "Bytes available after header: %zu (need >= %zu for function headers)\n", remaining, min_bytes);
	RETURN_IF_ERROR (string_buffer_append (out, buf));
	if (remaining < min_bytes) {
		RETURN_IF_ERROR (string_buffer_append (out, "Warning: file may be too small for declared function headers\n"));
	} else {
		RETURN_IF_ERROR (string_buffer_append (out, "Function headers fit in file size.\n"));
	}
	/* Dump first 16 bytes at current function data position as a hint */
	size_t saved_pos = r->file_buffer.position;
	r->file_buffer.position = sizeof (HBCHeader);
	/* Skip function headers area */
	r->file_buffer.position += (size_t)r->header.functionCount * 16;
	if (r->file_buffer.position + 16 <= r->file_buffer.size) {
		RETURN_IF_ERROR (string_buffer_append (out, "First 16 bytes at function data position: "));
		for (int i = 0; i < 16; i++) {
			snprintf (buf, sizeof (buf), "%02x ", r->file_buffer.data[r->file_buffer.position + i]);
			RETURN_IF_ERROR (string_buffer_append (out, buf));
		}
		RETURN_IF_ERROR (string_buffer_append (out, "\n"));
	}
	r->file_buffer.position = saved_pos;
	return SUCCESS_RESULT ();
}

/* Build per-instruction details for a function */
Result hbc_decode_function_instructions(
	HBCState *hd,
	u32 function_id,
	HBCDecodedInstructions *out) {
	if (!hd || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	HBCReader *r = &hd->reader;
	if (function_id >= r->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id");
	}
	/* Ensure bytecode is loaded */
	const u8 *bc = NULL;
	u32 bc_sz = 0;
	Result rr = hbc_get_function_bytecode (hd, function_id, &bc, &bc_sz);
	if (rr.code != RESULT_SUCCESS) {
		return rr;
	}

	ParsedInstructionList list;
	HBCISA isa = hbc_isa_getv (r->header.version);
	Result pr = parse_function_bytecode (r, function_id, &list, isa);
	if (pr.code != RESULT_SUCCESS) {
		return pr;
	}

	HBCInstruction *arr = (HBCInstruction *)calloc (list.count, sizeof (HBCInstruction));
	if (!arr) {
		parsed_instruction_list_free (&list);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM allocating HBCInstruction array");
	}

	FunctionHeader *fh = &r->function_headers[function_id];

	for (u32 i = 0; i < list.count; i++) {
		ParsedInstruction *ins = &list.instructions[i];
		HBCInstruction *hi = &arr[i];
		hi->rel_addr = ins->original_pos;
		hi->abs_addr = fh->offset + ins->original_pos;
		hi->opcode = ins->inst->opcode;
		hi->mnemonic = ins->inst->name;
		hi->is_jump = is_jump_instruction (ins->inst->opcode);
		hi->is_call = is_call_instruction (ins->inst->opcode);

		/* Operands */
		hi->operand_count = 0;
		for (u32 j = 0; j < 6; j++) {
			if (ins->inst->operands[j].operand_type == OPERAND_TYPE_NONE) {
				continue;
			}
			u32 v = 0;
			switch (j) {
			case 0: v = ins->arg1; break;
			case 1: v = ins->arg2; break;
			case 2: v = ins->arg3; break;
			case 3: v = ins->arg4; break;
			case 4: v = ins->arg5; break;
			case 5: v = ins->arg6; break;
			}
			if (hi->operand_count < 6) {
				hi->operands[hi->operand_count++] = v;
			}
		}

		/* Registers accessed */
		hi->regs_count = 0;
		for (u32 j = 0; j < 6; j++) {
			OperandType t = ins->inst->operands[j].operand_type;
			if (t == OPERAND_TYPE_REG8 || t == OPERAND_TYPE_REG32) {
				u32 v = (j == 0)? ins->arg1: (j == 1)? ins->arg2
					: (j == 2)? ins->arg3
					: (j == 3)? ins->arg4
					: (j == 4)? ins->arg5
									: ins->arg6;
				if (hi->regs_count < 6) {
					hi->regs[hi->regs_count++] = v;
				}
			}
		}

		/* References */
		hi->code_targets_count = 0;
		hi->function_ids_count = 0;
		hi->string_ids_count = 0;

		for (u32 j = 0; j < 6; j++) {
			OperandType t = ins->inst->operands[j].operand_type;
			OperandMeaning m = ins->inst->operands[j].operand_meaning;
			u32 v = (j == 0)? ins->arg1: (j == 1)? ins->arg2
				: (j == 2)? ins->arg3
				: (j == 3)? ins->arg4
				: (j == 4)? ins->arg5
								: ins->arg6;

			/* Hermes short/long address operands are relative to the current
			 * instruction start (original_pos), not to the end of the instruction. */
			if ((t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32) && hi->code_targets_count < 8) {
				u32 rel = ins->original_pos + v;
				hi->code_targets[hi->code_targets_count++] = fh->offset + rel;
			}
			if (m == OPERAND_MEANING_FUNCTION_ID && hi->function_ids_count < 4) {
				hi->function_ids[hi->function_ids_count++] = v;
			}
			if (m == OPERAND_MEANING_STRING_ID && hi->string_ids_count < 4) {
				hi->string_ids[hi->string_ids_count++] = v;
			}
		}
		/* Switch tables as extra code targets */
		if (ins->switch_jump_table && ins->switch_jump_table_size > 0) {
			for (u32 k = 0; k < ins->switch_jump_table_size && hi->code_targets_count < 8; k++) {
				hi->code_targets[hi->code_targets_count++] = fh->offset + ins->switch_jump_table[k];
			}
		}

		/* Full decoded string */
		StringBuffer sb;
		Result sr = string_buffer_init (&sb, 256);
		if (sr.code == RESULT_SUCCESS) {
			sr = instruction_to_string (ins, &sb);
			if (sr.code == RESULT_SUCCESS && sb.data) {
				size_t len = sb.length;
				hi->text = (char *)malloc (len + 1);
				if (hi->text) {
					memcpy (hi->text, sb.data, len);
					hi->text[len] = '\0';
				}
			}
			string_buffer_free (&sb);
		}
	}

	parsed_instruction_list_free (&list);
	out->instructions = arr;
	out->count = (u32) (arr? list.count: 0);
	return SUCCESS_RESULT ();
}

void hbc_free_instructions(HBCInstruction *insns, u32 count) {
	if (!insns) {
		return;
	}
	for (u32 i = 0; i < count; i++) {
		free (insns[i].text);
	}
	free (insns);
}

/* --- Single-instruction decode (no file context) --- */

static Instruction *select_instruction_set(u32 ver, u32 *out_count) {
	if (!ver) {
		fprintf (stderr, "[hbc] Warning: bytecode_version not specified, defaulting to v96\n");
		ver = 96;
	}
	/* Use the public API for version-specific instruction sets. */
	HBCISA isa = hbc_isa_getv (ver);
	if (out_count) {
		*out_count = isa.count;
	}
	return isa.instructions;
}

static const Instruction *find_instruction(Instruction *set, u32 count, u8 opcode) {
	if (!set) {
		return NULL;
	}
	/* Prefer direct index lookup when possible (tables are 256-entry arrays) */
	if (count >= 256) {
		return &set[opcode];
	}
	/* Fallback: linear search */
	for (u32 i = 0; i < count; i++) {
		if (set[i].opcode == opcode) {
			return &set[i];
		}
	}
	return NULL;
}

static void to_snake_lower(const char *in, char *out, size_t outsz) {
	size_t j = 0;
	for (size_t i = 0; in && in[i] && j + 1 < outsz; i++) {
		char c = in[i];
		if (c >= 'A' && c <= 'Z') {
			if (j && out[j - 1] != '_') {
				out[j++] = '_';
			}
			c = (char) (c - 'A' + 'a');
		}
		out[j++] = c;
	}
	if (outsz > 0) {
		out[j < outsz? j: outsz - 1] = '\0';
	}
}

/* New preferred API: decode using context struct */
Result hbc_decode(const HBCDecodeContext *ctx, HBCSingleInstructionInfo *out) {
	if (!ctx || !ctx->bytes || ctx->len == 0 || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	out->text = NULL;
	out->size = 0;
	out->opcode = 0;
	out->is_jump = false;
	out->is_call = false;
	out->jump_target = 0;

	/* Fetch instruction set */
	u32 set_count = 0;
	Instruction *set = select_instruction_set (ctx->bytecode_version, &set_count);
	if (!set) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "No opcode table available");
	}

	u8 opc = ctx->bytes[0];
	const Instruction *inst = find_instruction (set, set_count, opc);
	if (!inst) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Unknown opcode");
	}

	u32 isz = inst->binary_size;
	if (ctx->len < isz) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Truncated instruction");
	}

	/* Read operands from the provided bytes */
	u32 ops[6] = { 0 };
	size_t pos = 1;
	for (int i = 0; i < 6; i++) {
		OperandType t = inst->operands[i].operand_type;
		if (t == OPERAND_TYPE_NONE) {
			continue;
		}
		switch (t) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_UINT8:
		case OPERAND_TYPE_ADDR8:
			ops[i] = (pos + 1 <= ctx->len)? ctx->bytes[pos]: 0;
			pos += 1;
			break;
		case OPERAND_TYPE_UINT16:
			if (pos + 2 <= ctx->len) {
				ops[i] = (u16) (ctx->bytes[pos] | ((u16)ctx->bytes[pos + 1] << 8));
			}
			pos += 2;
			break;
		case OPERAND_TYPE_REG32:
		case OPERAND_TYPE_UINT32:
		case OPERAND_TYPE_ADDR32:
			if (pos + 4 <= ctx->len) {
				ops[i] = (u32) (ctx->bytes[pos] | ((u32)ctx->bytes[pos + 1] << 8) |
					((u32)ctx->bytes[pos + 2] << 16) | ((u32)ctx->bytes[pos + 3] << 24));
			}
			pos += 4;
			break;
		default:
			break;
		}
	}

	/* Populate output */
	out->is_jump = is_jump_instruction (opc);
	out->is_call = is_call_instruction (opc);
	out->opcode = opc;
	out->size = isz;

	/* Compute primary jump target (Hermes uses offsets relative to instruction start) */
	for (int i = 0; i < 6; i++) {
		OperandType t = inst->operands[i].operand_type;
		if (t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32) {
			out->jump_target = ctx->pc + (u64)ops[i];
			break;
		}
	}

	/* Render text */
	StringBuffer sb;
	Result sr = string_buffer_init (&sb, 128);
	if (sr.code != RESULT_SUCCESS) {
		return sr;
	}

	char mnem[64];
	if (ctx->asm_syntax) {
		to_snake_lower (inst->name, mnem, sizeof (mnem));
	} else {
		snprintf (mnem, sizeof (mnem), "%s", inst->name? inst->name: "unk");
	}
	RETURN_IF_ERROR (string_buffer_append (&sb, mnem));

	bool first = true;
	for (int i = 0; i < 6; i++) {
		OperandType t = inst->operands[i].operand_type;
		if (t == OPERAND_TYPE_NONE) {
			continue;
		}
		RETURN_IF_ERROR (string_buffer_append (&sb, first? " ": ", "));
		first = false;

		char buf[64];
		switch (t) {
		case OPERAND_TYPE_REG8:
		case OPERAND_TYPE_REG32:
			snprintf (buf, sizeof (buf), "r%u", ops[i]);
			break;
		case OPERAND_TYPE_ADDR8:
		case OPERAND_TYPE_ADDR32:
			snprintf (buf, sizeof (buf), "0x%llx", (unsigned long long) (ctx->pc + (u64)ops[i]));
			break;
		default:
			/* Check if this is a string ID that should be resolved */
			if (ctx->resolve_string_ids && ctx->string_tables &&
				inst->operands[i].operand_meaning == OPERAND_MEANING_STRING_ID) {
				u32 string_id = ops[i];
				u64 resolved_addr = 0;

				if (string_id < ctx->string_tables->string_count &&
					ctx->string_tables->small_string_table) {
					const StringTableEntry *entry =
						(const StringTableEntry *)ctx->string_tables->small_string_table + string_id;
					if (entry->length == 0xFF && ctx->string_tables->overflow_string_table) {
						const OffsetLengthPair *overflow_entry =
							(const OffsetLengthPair *)ctx->string_tables->overflow_string_table + entry->offset;
						resolved_addr = ctx->string_tables->string_storage_offset + overflow_entry->offset;
					} else {
						resolved_addr = ctx->string_tables->string_storage_offset + entry->offset;
					}
				}

				if (resolved_addr != 0) {
					snprintf (buf, sizeof (buf), "0x%llx", (unsigned long long)resolved_addr);
				} else {
					snprintf (buf, sizeof (buf), "%u", ops[i]);
				}
			} else {
				snprintf (buf, sizeof (buf), "%u", ops[i]);
			}
			break;
		}
		RETURN_IF_ERROR (string_buffer_append (&sb, buf));
	}

	/* Materialize buffer */
	out->text = (char *)malloc (sb.length + 1);
	if (!out->text) {
		string_buffer_free (&sb);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM for output text");
	}
	memcpy (out->text, sb.data, sb.length);
	out->text[sb.length] = '\0';
	string_buffer_free (&sb);

	return SUCCESS_RESULT ();
}

/* Legacy API: delegates to hbc_decode */
Result hbc_decode_single_instruction(
	const u8 *bytes,
	size_t len,
	u32 bytecode_version,
	u64 pc,
	bool asm_syntax,
	bool resolve_string_ids,
	const HBCStringTables *string_ctx,
	HBCSingleInstructionInfo *out) {
	HBCDecodeContext ctx = {
		.bytes = bytes,
		.len = len,
		.pc = pc,
		.bytecode_version = bytecode_version,
		.asm_syntax = asm_syntax,
		.resolve_string_ids = resolve_string_ids,
		.string_tables = string_ctx
	};
	return hbc_decode (&ctx, out);
}

/* Encoding functions - TODO: implement */

Result hbc_encode_instruction(
	const char *asm_line,
	u32 bytecode_version,
	HBCEncodeBuffer *out) {
	(void)asm_line;
	(void)bytecode_version;
	(void)out;
	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Encoding not implemented");
}

Result hbc_encode_instructions(
	const char *asm_text,
	u32 bytecode_version,
	HBCEncodeBuffer *out) {
	(void)asm_text;
	(void)bytecode_version;
	(void)out;
	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED, "Encoding not implemented");
}
