#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/decompilation/token.h>
#include <hbc/parsers/hbc_file_parser.h>
#include <hbc/parsers/hbc_bytecode_parser.h>
#include <hbc/disassembly/hbc_disassembler.h>
#include <hbc/decompilation/translator.h>
#include <hbc/opcodes.h>
#include <hbc/decompilation/literals.h>

/* Ensure that the function's bytecode buffer is loaded into memory. */
static Result ensure_function_bytecode_loaded(HBCReader *reader, u32 function_id) {
	if (!reader) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "ensure: reader NULL");
	}
	if (function_id >= reader->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "ensure: bad fid");
	}
	FunctionHeader *function_header = &reader->function_headers[function_id];
	if (function_header->bytecode) {
		return SUCCESS_RESULT ();
	}

	/* Skip invalid offsets */
	if (function_header->offset == 0) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Bytecode offset is zero");
	}
	if (function_header->offset >= reader->file_buffer.size) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Bytecode offset beyond file size");
	}
	if (function_header->offset + function_header->bytecodeSizeInBytes > reader->file_buffer.size) {
		/* Truncate to file size */
		function_header->bytecodeSizeInBytes = reader->file_buffer.size - function_header->offset;
	}

	function_header->bytecode = (u8 *)malloc (function_header->bytecodeSizeInBytes);
	if (!function_header->bytecode) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate bytecode buffer");
	}
	size_t saved = reader->file_buffer.position;
	Result sr = buffer_reader_seek (&reader->file_buffer, function_header->offset);
	if (sr.code != RESULT_SUCCESS) {
		free (function_header->bytecode);
		function_header->bytecode = NULL;
		reader->file_buffer.position = saved;
		return sr;
	}
	sr = buffer_reader_read_bytes (&reader->file_buffer, function_header->bytecode, function_header->bytecodeSizeInBytes);
	reader->file_buffer.position = saved;
	if (sr.code != RESULT_SUCCESS) {
		free (function_header->bytecode);
		function_header->bytecode = NULL;
		return sr;
	}
	return SUCCESS_RESULT ();
}

/* Helpers to work with ParsedInstruction and operands */
static inline u32 insn_get_operand_value(const ParsedInstruction *insn, int idx) {
	switch (idx) {
	case 0: return insn->arg1;
	case 1: return insn->arg2;
	case 2: return insn->arg3;
	case 3: return insn->arg4;
	case 4: return insn->arg5;
	default: return insn->arg6;
	}
}

static inline bool operand_is_addr(const Instruction *inst, int idx) {
	OperandType t = inst->operands[idx].operand_type;
	return t == OPERAND_TYPE_ADDR8 || t == OPERAND_TYPE_ADDR32;
}

static u32 compute_target_address(const ParsedInstruction *insn, int op_index) {
	u32 v = insn_get_operand_value (insn, op_index);
	u32 base = insn->original_pos;
	if (is_jump_instruction (insn->opcode)) {
		base += insn->inst->binary_size;
	}
	return base + v;
}

/* Small dynamic set of u32, optimized with bitmap for addresses */
typedef struct {
	u32 *data;
	u32 count;
	u32 cap;
	u8 *bitmap; /* bitmap for fast lookup, size = max_addr / 8 + 1 */
	u32 bitmap_size; /* in bytes */
} U32Set;
static Result u32set_init(U32Set *s, u32 max_addr) {
	if (!s) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "u32set init");
	}
	s->bitmap_size = (max_addr + 7) / 8;
	s->bitmap = (u8 *)calloc (s->bitmap_size, 1);
	if (!s->bitmap) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "u32set bitmap");
	}
	return SUCCESS_RESULT ();
}

static void u32set_free(U32Set *s) {
	if (!s) {
		return;
	}
	free (s->data);
	free (s->bitmap);
	s->data = NULL;
	s->bitmap = NULL;
	s->count = s->cap = 0;
	s->bitmap_size = 0;
}
static bool u32set_contains(const U32Set *s, u32 v) {
	if (!s || !s->bitmap || v / 8 >= s->bitmap_size) {
		return false;
	}
	return (s->bitmap[v / 8] &(1 << (v % 8))) != 0;
}
static Result u32set_add(U32Set *s, u32 v) {
	if (!s) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "u32set");
	}
	if (u32set_contains (s, v)) {
		return SUCCESS_RESULT ();
	}
	/* Set the bit in bitmap */
	if (s->bitmap && v / 8 < s->bitmap_size) {
		s->bitmap[v / 8] |= (1 << (v % 8));
	}
	if (s->count == s->cap) {
		u32 nc = s->cap? s->cap * 2: 16;
		u32 *nd = (u32 *)realloc (s->data, nc * sizeof (u32));
		if (!nd) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
		}
		s->data = nd;
		s->cap = nc;
	}
	s->data[s->count++] = v;
	return SUCCESS_RESULT ();
}
static void label_name(char *buf, size_t bufsz, u32 addr) {
	snprintf (buf, bufsz, "L_%08x", addr);
}
static Result append_indent(StringBuffer *sb, int level) {
	for (int i = 0; i < level; i++) {
		RETURN_IF_ERROR (string_buffer_append (sb, "  "));
	}
	return SUCCESS_RESULT ();
}
static int find_index_by_addr(ParsedInstructionList *list, u32 addr) {
	for (u32 i = 0; i < list->count; i++) {
		if (list->instructions[i].original_pos == addr) {
			return (int)i;
		}
	}
	return -1;
}

static const char *cmp_op_for_jump(u8 op) {
	switch (op) {
	case OP_JEqual:
	case OP_JEqualLong: return "==";
	case OP_JNotEqual:
	case OP_JNotEqualLong: return "!=";
	case OP_JStrictEqual:
	case OP_JStrictEqualLong: return "===";
	case OP_JStrictNotEqual:
	case OP_JStrictNotEqualLong: return "!==";
	case OP_JLess:
	case OP_JLessLong:
	case OP_JLessN:
	case OP_JLessNLong: return "<";
	case OP_JNotLess:
	case OP_JNotLessLong:
	case OP_JNotLessN:
	case OP_JNotLessNLong: return ">=";
	case OP_JLessEqual:
	case OP_JLessEqualLong:
	case OP_JLessEqualN:
	case OP_JLessEqualNLong: return "<=";
	case OP_JNotLessEqual:
	case OP_JNotLessEqualLong:
	case OP_JNotLessEqualN:
	case OP_JNotLessEqualNLong: return ">";
	case OP_JGreater:
	case OP_JGreaterLong:
	case OP_JGreaterN:
	case OP_JGreaterNLong: return ">";
	case OP_JNotGreater:
	case OP_JNotGreaterLong:
	case OP_JNotGreaterN:
	case OP_JNotGreaterNLong: return "<=";
	case OP_JGreaterEqual:
	case OP_JGreaterEqualLong:
	case OP_JGreaterEqualN:
	case OP_JGreaterEqualNLong: return ">=";
	case OP_JNotGreaterEqual:
	case OP_JNotGreaterEqualLong:
	case OP_JNotGreaterEqualN:
	case OP_JNotGreaterEqualNLong: return "<";
	default: return NULL;
	}
}

/* Register naming helpers */
static Result append_regname(StringBuffer *sb, int r, char **names, u32 cap) {
	if (r >= 0 && (u32)r < cap && names && names[r]) {
		return string_buffer_append (sb, names[r]);
	}
	char buf[16];
	snprintf (buf, sizeof (buf), "r%d", r);
	return string_buffer_append (sb, buf);
}

static void apply_register_naming(TokenString *ts, char **names, u32 cap) {
	if (!ts || !names) {
		return;
	}
	Token *cur = ts->head;
	Token *prev = NULL;
	while (cur) {
		bool repl = false;
		int rn = -1;
		if (cur->type == TOKEN_TYPE_LEFT_HAND_REG) {
			rn = ((LeftHandRegToken *)cur)->reg_num;
			repl = true;
		} else if (cur->type == TOKEN_TYPE_RIGHT_HAND_REG) {
			rn = ((RightHandRegToken *)cur)->reg_num;
			repl = true;
		}
		if (repl && rn >= 0 && (u32)rn < cap && names[rn]) {
			Token *rt = create_raw_token (names[rn]);
			if (rt) {
				Token *nxt = cur->next;
				if (prev) {
					prev->next = rt;
				} else {
					ts->head = rt;
				}
				if (ts->tail == cur) {
					ts->tail = rt;
				}
				rt->next = nxt;
				token_free (cur);
				cur = rt;
			}
		}
		prev = cur;
		cur = cur->next;
	}
}

/* ============= CFG construction ============= */
static Result bbvec_push(BasicBlock ***arr, u32 *count, u32 *cap, BasicBlock *bb) {
	if (*count >= *cap) {
		u32 nc = *cap? (*cap * 2): 8;
		BasicBlock **na = (BasicBlock **)realloc (*arr, nc * sizeof (BasicBlock *));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom bbvec");
		}
		*arr = na;
		*cap = nc;
	}
	(*arr)[(*count)++] = bb;
	return SUCCESS_RESULT ();
}

static BasicBlock *find_block_by_start(DecompiledFunctionBody *fb, u32 start) {
	for (u32 i = 0; i < fb->basic_blocks_count; i++) {
		if (fb->basic_blocks[i].start_address == start) {
			return &fb->basic_blocks[i];
		}
	}
	return NULL;
}

Result function_body_init(DecompiledFunctionBody *body, u32 function_id, FunctionHeader *function_object, bool is_global) {
	if (!body || !function_object) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "fb_init args");
	}
	memset (body, 0, sizeof (*body));
	body->is_global = is_global;
	body->function_id = function_id;
	body->function_object = function_object;
	body->statements = NULL;
	body->statements_count = body->statements_capacity = 0;
	body->basic_blocks = NULL;
	body->basic_blocks_count = body->basic_blocks_capacity = 0;
	body->jump_targets = NULL;
	body->jump_targets_count = body->jump_targets_capacity = 0;
	body->instructions.instructions = NULL;
	body->instructions.count = body->instructions.capacity = 0;
	/* Exception handlers */
	return SUCCESS_RESULT ();
}

void function_body_cleanup(DecompiledFunctionBody *body) {
	if (!body) {
		return;
	}
	free (body->jump_targets);
	free (body->basic_blocks);
	/* statements and token strings cleanup would go here if allocated */
	memset (body, 0, sizeof (*body));
}

Result add_jump_target(DecompiledFunctionBody *body, u32 address) {
	if (!body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "add_jump_target: body");
	}
	for (u32 i = 0; i < body->jump_targets_count; i++) {
		if (body->jump_targets[i] == address) {
			return SUCCESS_RESULT ();
		}
	}
	if (body->jump_targets_count >= body->jump_targets_capacity) {
		u32 nc = body->jump_targets_capacity? body->jump_targets_capacity * 2: 16;
		u32 *na = (u32 *)realloc (body->jump_targets, nc * sizeof (u32));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom add_jump_target");
		}
		body->jump_targets = na;
		body->jump_targets_capacity = nc;
	}
	body->jump_targets[body->jump_targets_count++] = address;
	return SUCCESS_RESULT ();
}

Result create_basic_block(DecompiledFunctionBody *body, u32 start_address, u32 end_address) {
	if (!body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "create_bb body");
	}
	if (body->basic_blocks_count >= body->basic_blocks_capacity) {
		u32 nc = body->basic_blocks_capacity? body->basic_blocks_capacity * 2: 16;
		BasicBlock *na = (BasicBlock *)realloc (body->basic_blocks, nc * sizeof (BasicBlock));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom create_bb");
		}
		body->basic_blocks = na;
		body->basic_blocks_capacity = nc;
	}
	BasicBlock *bb = &body->basic_blocks[body->basic_blocks_count++];
	memset (bb, 0, sizeof (*bb));
	bb->start_address = start_address;
	bb->end_address = end_address;
	bb->stay_visible = true;
	return SUCCESS_RESULT ();
}

/* Build a control-flow graph using simple leader splitting and edge wiring */
Result build_control_flow_graph(HBCReader *reader, u32 function_id, ParsedInstructionList *list, DecompiledFunctionBody *out_body) {
	if (!reader || !list || !out_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "build_cfg args");
	}
	FunctionHeader *fh = &reader->function_headers[function_id];
	RETURN_IF_ERROR (function_body_init (out_body, function_id, fh, function_id == reader->header.globalCodeIndex));
	/* Leaders: entry, jump targets, fallthrough after terminators */
	U32Set leaders = { 0 };
	u32 func_sz = fh->bytecodeSizeInBytes;
	RETURN_IF_ERROR (u32set_init (&leaders, func_sz));
	u32set_add (&leaders, 0);
	for (u32 i = 0; i < list->count; i++) {
		ParsedInstruction *ins = &list->instructions[i];
		if (ins->switch_jump_table && ins->switch_jump_table_size) {
			for (u32 k = 0; k < ins->switch_jump_table_size; k++) {
				if (ins->switch_jump_table[k] < func_sz) {
					u32set_add (&leaders, ins->switch_jump_table[k]);
				}
			}
		}
		for (int j = 0; j < 6; j++) {
			if (!operand_is_addr (ins->inst, j)) {
				continue;
			}
			u32 tgt = compute_target_address (ins, j);
			if (tgt < func_sz) {
				u32set_add (&leaders, tgt);
			}
			bool term = is_jump_instruction (ins->opcode) || ins->opcode == OP_Ret || ins->opcode == OP_Throw;
			if (term && ins->next_pos < func_sz) {
				u32set_add (&leaders, ins->next_pos);
			}
		}
	}
	/* Create blocks by scanning instructions and cutting at leaders */
	for (u32 i = 0; i < list->count; i++) {
		ParsedInstruction *ins = &list->instructions[i];
		u32 start = ins->original_pos;
		if (!u32set_contains (&leaders, start)) {
			continue;
		}
		/* find end = next leader or function end */
		u32 end = fh->bytecodeSizeInBytes; /* default */
		for (u32 j = i + 1; j < list->count; j++) {
			if (u32set_contains (&leaders, list->instructions[j].original_pos)) {
				end = list->instructions[j].original_pos;
				break;
			}
		}
		RETURN_IF_ERROR (create_basic_block (out_body, start, end));
	}
	/* Anchor and wire edges */
	for (u32 i = 0; i < out_body->basic_blocks_count; i++) {
		BasicBlock *bb = &out_body->basic_blocks[i];
		/* find last instruction in this block */
		ParsedInstruction *last = NULL;
		ParsedInstruction *first = NULL;
		for (u32 k = 0; k < list->count; k++) {
			ParsedInstruction *ins = &list->instructions[k];
			if (ins->original_pos >= bb->start_address && ins->original_pos < bb->end_address) {
				if (!first) {
					first = ins;
				}
				last = ins;
			}
		}
		bb->anchor_instruction = first; /* store start insn */
		if (!last) {
			continue;
		}
		u8 op = last->opcode;
		if (op == OP_Ret) {
			bb->is_unconditional_return_end = true;
			continue;
		}
		if (op == OP_Throw) {
			bb->is_unconditional_throw_anchor = true;
			continue;
		}
		if (is_jump_instruction (op)) {
			/* compute targets */
			for (int j = 0; j < 6; j++) {
				if (!operand_is_addr (last->inst, j)) {
					continue;
				}
				u32 tgt = compute_target_address (last, j);
				BasicBlock *child = find_block_by_start (out_body, tgt);
				if (child) {
					RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->error_handling_child_nodes_count /*cap reused*/, child));
				}
			}
			/* conditional: also add fallthrough */
			bool is_uncond = (op == OP_Jmp || op == OP_JmpLong);
			if (!is_uncond && last->next_pos < fh->bytecodeSizeInBytes) {
				BasicBlock *fall = find_block_by_start (out_body, last->next_pos);
				if (fall) {
					RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->error_handling_child_nodes_count, fall));
				}
			} else if (is_uncond) {
				bb->is_unconditional_jump_anchor = true;
			}
		} else {
			/* normal fallthrough */
			if (last->next_pos < fh->bytecodeSizeInBytes) {
				BasicBlock *fall = find_block_by_start (out_body, last->next_pos);
				if (fall) {
					RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->error_handling_child_nodes_count, fall));
				}
			}
		}
	}
	u32set_free (&leaders);
	return SUCCESS_RESULT ();
}

Result decompiler_init(HermesDecompiler *decompiler) {
	if (!decompiler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler pointer");
	}

	decompiler->calldirect_function_ids = NULL;
	decompiler->calldirect_function_ids_count = 0;
	decompiler->calldirect_function_ids_capacity = 0;
	decompiler->indent_level = 0;

	// Initialize string buffer for output
	string_buffer_init (&decompiler->output, 4096); // Start with 4KB buffer

	return SUCCESS_RESULT ();
}

Result decompiler_cleanup(HermesDecompiler *decompiler) {
	if (!decompiler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler pointer");
	}

	// Free calldirect function ids array
	if (decompiler->calldirect_function_ids) {
		free (decompiler->calldirect_function_ids);
		decompiler->calldirect_function_ids = NULL;
	}

	// Cleanup string buffer
	string_buffer_free (&decompiler->output);

	return SUCCESS_RESULT ();
}

Result decompile_file(const char *input_file, const char *output_file) {
	Result result;
	HermesDecompiler decompiler;
	HBCReader reader;

	// Initialize structs
	result = decompiler_init (&decompiler);
	if (result.code != RESULT_SUCCESS) {
		return result;
	}

	result = hbc_reader_init (&reader);
	if (result.code != RESULT_SUCCESS) {
		decompiler_cleanup (&decompiler);
		return result;
	}

	// Store file paths
	decompiler.input_file = (char *)input_file;
	decompiler.output_file = (char *)output_file;
	decompiler.hbc_reader = &reader;

	// Read and parse the file
	result = hbc_reader_read_file (&reader, input_file);
	if (result.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&reader);
		decompiler_cleanup (&decompiler);
		return result;
	}

	// Read header
	result = hbc_reader_read_header (&reader);
	if (result.code != RESULT_SUCCESS) {
		hbc_reader_cleanup (&reader);
		decompiler_cleanup (&decompiler);
		return result;
	}

	// Produce decompilation into a temporary buffer, then write to file/stdout
	StringBuffer sb;
	string_buffer_init (&sb, 64 * 1024);
	HBCDecompileOptions options = { .pretty_literals = LITERALS_PRETTY_AUTO, .suppress_comments = false };
	result = decompile_all_to_buffer (&reader, options, &sb);
	if (result.code != RESULT_SUCCESS) {
		string_buffer_free (&sb);
		hbc_reader_cleanup (&reader);
		decompiler_cleanup (&decompiler);
		return result;
	}

	FILE *out = stdout;
	if (output_file) {
		out = fopen (output_file, "w");
		if (!out) {
			string_buffer_free (&sb);
			hbc_reader_cleanup (&reader);
			decompiler_cleanup (&decompiler);
			return ERROR_RESULT (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file for writing");
		}
	}
	fputs (sb.data? sb.data: "", out);
	if (output_file && out != stdout) {
		fclose (out);
	}
	string_buffer_free (&sb);

	// Cleanup
	hbc_reader_cleanup (&reader);
	decompiler_cleanup (&decompiler);

	return SUCCESS_RESULT ();
}

/* Internal helper to emit a minimal decompiled body with per-instruction statements.
 * Also appends disassembly as comments for debugging. */
static Result emit_minimal_decompiled_function(HBCReader *reader, u32 function_id, HBCDecompileOptions options, StringBuffer *out) {
	if (!reader || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for emit_function_stub_with_disassembly");
	}
	if (function_id >= reader->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function id out of range");
	}

	FunctionHeader *fh = &reader->function_headers[function_id];
	const char *name = NULL;
	if (reader->strings && fh->functionName < reader->header.stringCount) {
		name = reader->strings[fh->functionName];
	}
	if (!name || !*name) {
		name = "anonymous";
	}

	// Emit function signature
	RETURN_IF_ERROR (string_buffer_append (out, "function "));
	RETURN_IF_ERROR (string_buffer_append (out, name));
	RETURN_IF_ERROR (string_buffer_append (out, "("));
	for (u32 i = 0; i < fh->paramCount; i++) {
		if (i) {
			RETURN_IF_ERROR (string_buffer_append (out, ", "));
		}
		char pbuf[32];
		snprintf (pbuf, sizeof (pbuf), "a%u", i);
		RETURN_IF_ERROR (string_buffer_append (out, pbuf));
	}
	RETURN_IF_ERROR (string_buffer_append (out, ") {\n"));

	// Emit simple header summary
	RETURN_IF_ERROR (string_buffer_append (out, "  // id: "));
	char nbuf[64];
	snprintf (nbuf, sizeof (nbuf), "%u", function_id);
	RETURN_IF_ERROR (string_buffer_append (out, nbuf));
	RETURN_IF_ERROR (string_buffer_append (out, ", offset: 0x"));
	char off[32];
	snprintf (off, sizeof (off), "%x", fh->offset);
	RETURN_IF_ERROR (string_buffer_append (out, off));
	RETURN_IF_ERROR (string_buffer_append (out, ", size: "));
	char sz[32];
	snprintf (sz, sizeof (sz), "%u", fh->bytecodeSizeInBytes);
	RETURN_IF_ERROR (string_buffer_append (out, sz));
	RETURN_IF_ERROR (string_buffer_append (out, " bytes\n"));

	/* Ensure bytecode is available */
	RETURN_IF_ERROR (ensure_function_bytecode_loaded (reader, function_id));

	/* Parse function into instructions */
	ParsedInstructionList list;
	HBCISA isa = hbc_isa_getv (reader->header.version);
	RETURN_IF_ERROR (parse_function_bytecode (reader, function_id, &list, isa));

	/* Build CFG (anchors, blocks, edges) to prepare future structuring */
	DecompiledFunctionBody fbody;
	Result cfg_res = build_control_flow_graph (reader, function_id, &list, &fbody);
	if (cfg_res.code == RESULT_SUCCESS) {
		/* Currently unused in emission, but keeps analysis ready */
		function_body_cleanup (&fbody);
	}

	/* Collect label targets */
	U32Set labels = { 0 };
	u32 func_end = fh->bytecodeSizeInBytes;
	RETURN_IF_ERROR (u32set_init (&labels, func_end));
	u32set_add (&labels, 0);
	for (u32 i = 0; i < list.count; i++) {
		ParsedInstruction *ins = &list.instructions[i];
		if (ins->switch_jump_table && ins->switch_jump_table_size) {
			for (u32 k = 0; k < ins->switch_jump_table_size; k++) {
				if (ins->switch_jump_table[k] < func_end) {
					u32set_add (&labels, ins->switch_jump_table[k]);
				}
			}
		}
		for (int j = 0; j < 6; j++) {
			if (!operand_is_addr (ins->inst, j)) {
				continue;
			}
			u32 taddr = compute_target_address (ins, j);
			if (taddr < func_end) {
				u32set_add (&labels, taddr);
			}
			bool ends = is_jump_instruction (ins->opcode) || ins->opcode == OP_Ret || ins->opcode == OP_Throw;
			if (ends && ins->next_pos < func_end) {
				u32set_add (&labels, ins->next_pos);
			}
		}
	}

	/* For each instruction, translate to tokens and print one statement.
	Recognize simple forward if / if-else and emit structured blocks. */
	bool *skip = (bool *)calloc (list.count, sizeof (bool));
	if (!skip) {
		parsed_instruction_list_free (&list);
		u32set_free (&labels);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom skip");
	}
	int base_indent = 1; /* inside function */
	/* Try/catch handling: track a single active handler region for now */
	ExceptionHandlerList *ehlist = (reader->function_id_to_exc_handlers && function_id < reader->header.functionCount)
		? &reader->function_id_to_exc_handlers[function_id]
		: NULL;
	bool try_active = false;
	u32 try_start_addr = 0;
	u32 try_end_addr = 0;
	u32 catch_target_addr = 0;
	/* Build simple register naming table (params -> aN) */
	u32 max_regs = reader->function_headers[function_id].frameSize + 64;
	if (max_regs < 64) {
		max_regs = 64;
	}
	char **reg_names = (char **)calloc (max_regs, sizeof (char *));
	if (!reg_names) {
		free (skip);
		parsed_instruction_list_free (&list);
		u32set_free (&labels);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom regnames");
	}

	for (u32 i = 0; i < list.count; i++) {
		if (skip[i]) {
			continue;
		}
		ParsedInstruction *ins = &list.instructions[i];

		/* Open try if this address matches a handler start */
		if (!try_active && ehlist && ehlist->handlers) {
			for (u32 hi = 0; hi < ehlist->count; hi++) {
				ExceptionHandlerInfo *h = &ehlist->handlers[hi];
				if (h->start == ins->original_pos) {
					try_active = true;
					try_start_addr = h->start;
					try_end_addr = h->end;
					catch_target_addr = h->target;
					RETURN_IF_ERROR (append_indent (out, base_indent));
					RETURN_IF_ERROR (string_buffer_append (out, "try {\n"));
					break;
				}
			}
		}

		/* Close try and emit catch body when we reach try end */
		if (try_active && ins->original_pos == try_end_addr) {
			RETURN_IF_ERROR (append_indent (out, base_indent));
			RETURN_IF_ERROR (string_buffer_append (out, "}\n"));

			int tindex = find_index_by_addr (&list, catch_target_addr);
			int catch_reg = -1;
			if (tindex >= 0) {
				ParsedInstruction *ci = &list.instructions[tindex];
				if (ci->inst && ci->opcode == OP_Catch) {
					catch_reg = (int)ci->arg1;
				}
			}

			/* Find join label beyond try */
			u32 join_addr = 0;
			int join_index = -1;
			for (u32 si = 0; si < list.count; si++) {
				ParsedInstruction *ti = &list.instructions[si];
				if (ti->original_pos < try_start_addr || ti->original_pos >= try_end_addr) {
					continue;
				}
				if (ti->inst && (ti->opcode == OP_Jmp || ti->opcode == OP_JmpLong)) {
					int aidx = -1;
					for (int j = 0; j < 6; j++) {
						if (operand_is_addr (ti->inst, j)) {
							aidx = j;
							break;
						}
					}
					if (aidx >= 0) {
						u32 ta = compute_target_address (ti, aidx);
						if (ta > try_end_addr) {
							join_addr = ta;
							break;
						}
					}
				}
			}
			if (join_addr) {
				join_index = find_index_by_addr (&list, join_addr);
			}
			if (join_index < 0) {
				for (u32 si = 0; si < list.count; si++) {
					if (list.instructions[si].original_pos <= catch_target_addr) {
						continue;
					}
					if (u32set_contains (&labels, list.instructions[si].original_pos)) {
						join_index = (int)si;
						break;
					}
				}
			}

			/* Emit catch header */
			RETURN_IF_ERROR (append_indent (out, base_indent));
			if (catch_reg >= 0) {
				RETURN_IF_ERROR (string_buffer_append (out, "catch (r"));
				RETURN_IF_ERROR (string_buffer_append_int (out, catch_reg));
				RETURN_IF_ERROR (string_buffer_append (out, ") {\n"));
			} else {
				RETURN_IF_ERROR (string_buffer_append (out, "catch (e) {\n"));
			}

			if (tindex >= 0) {
				u32 body_start = (catch_reg >= 0)? (u32) (tindex + 1): (u32)tindex;
				u32 body_end = (join_index >= 0)? (u32)join_index: body_start;
				/* Do not emit the OP_Catch marker itself later */
				skip[tindex] = true;
				if (body_end > body_start) {
					for (u32 k = body_start; k < body_end; k++) {
						skip[k] = true;
						ParsedInstruction *ci2 = &list.instructions[k];
						TokenString ts2;
						RETURN_IF_ERROR (translate_instruction_to_tokens (ci2, &ts2));
						StringBuffer line;
						RETURN_IF_ERROR (string_buffer_init (&line, 128));
						RETURN_IF_ERROR (append_indent (&line, base_indent + 1));
						RETURN_IF_ERROR (token_string_to_string (&ts2, &line));
						RETURN_IF_ERROR (string_buffer_append (&line, ";"));
						StringBuffer dline;
						string_buffer_init (&dline, 64);
						Result sr2 = instruction_to_string (ci2, &dline);
						if (sr2.code == RESULT_SUCCESS && dline.length > 0) {
							string_buffer_append (&line, "  // ");
							string_buffer_append (&line, dline.data);
						}
						string_buffer_free (&dline);
						string_buffer_append (&line, "\n");
						string_buffer_append (out, line.data);
						string_buffer_free (&line);
						token_string_cleanup (&ts2);
					}
				} else {
					/* Fallback */
					RETURN_IF_ERROR (append_indent (out, base_indent + 1));
					char clab[32];
					label_name (clab, sizeof (clab), catch_target_addr);
					RETURN_IF_ERROR (string_buffer_append (out, "goto "));
					RETURN_IF_ERROR (string_buffer_append (out, clab));
					RETURN_IF_ERROR (string_buffer_append (out, ";\n"));
				}
			}
			RETURN_IF_ERROR (append_indent (out, base_indent));
			RETURN_IF_ERROR (string_buffer_append (out, "}\n"));
			try_active = false;
		}

		/* Emit label if leader and not suppressed by a structured region */
		if (u32set_contains (&labels, ins->original_pos)) {
			char lbuf[32];
			label_name (lbuf, sizeof (lbuf), ins->original_pos);
			RETURN_IF_ERROR (string_buffer_append (out, lbuf));
			RETURN_IF_ERROR (string_buffer_append (out, ":\n"));
		}

		/* Do-while loop detection: find a later conditional jump back to this header */
		{
			int back_idx = -1;
			u8 bop = 0;
			int b_addr_idx = -1;
			for (u32 k = i + 1; k < list.count; k++) {
				ParsedInstruction *ji = &list.instructions[k];
				if (!is_jump_instruction (ji->opcode)) {
					continue;
				}
				int aidx = -1;
				for (int j = 0; j < 6; j++) {
					if (operand_is_addr (ji->inst, j)) {
						aidx = j;
						break;
					}
				}
				if (aidx < 0) {
					continue;
				}
				u32 taddr = compute_target_address (ji, aidx);
				if (taddr == ins->original_pos) {
					back_idx = (int)k;
					bop = ji->opcode;
					b_addr_idx = aidx;
					break;
				}
				/* Stop if we hit another leader label (new block) far ahead */
				if (u32set_contains (&labels, ji->original_pos) && ji->original_pos != ins->original_pos && k > i + 1) {
					break;
				}
			}
			if (back_idx > (int)i) {
				/* Only accept compare or boolean cond for do-while */
				const char *bcmp = cmp_op_for_jump (bop);
				bool is_bool = (bop == OP_JmpTrue || bop == OP_JmpTrueLong || bop == OP_JmpFalse || bop == OP_JmpFalseLong);
				if (bcmp || is_bool) {
					/* Emit do header */
					RETURN_IF_ERROR (append_indent (out, base_indent));
					RETURN_IF_ERROR (string_buffer_append (out, "do {\n"));
					/* Emit body from i to back_idx-1 */
					for (u32 k = i; k < (u32)back_idx; k++) {
						skip[k] = true;
						ParsedInstruction *bi = &list.instructions[k];
						TokenString ts2;
						RETURN_IF_ERROR (translate_instruction_to_tokens (bi, &ts2));
						apply_register_naming (&ts2, reg_names, max_regs);
						StringBuffer line;
						string_buffer_init (&line, 128);
						RETURN_IF_ERROR (append_indent (&line, base_indent + 1));
						RETURN_IF_ERROR (token_string_to_string (&ts2, &line));
						RETURN_IF_ERROR (string_buffer_append (&line, ";"));
						StringBuffer dline;
						string_buffer_init (&dline, 64);
						Result sr2 = instruction_to_string (bi, &dline);
						if (sr2.code == RESULT_SUCCESS && dline.length > 0) {
							string_buffer_append (&line, "  // ");
							string_buffer_append (&line, dline.data);
						}
						string_buffer_free (&dline);
						string_buffer_append (&line, "\n");
						string_buffer_append (out, line.data);
						string_buffer_free (&line);
						token_string_cleanup (&ts2);
					}
					/* Emit while tail */
					RETURN_IF_ERROR (append_indent (out, base_indent));
					RETURN_IF_ERROR (string_buffer_append (out, "} while ("));
					if (bcmp) {
						int r1 = -1, r2 = -1;
						for (int j = 0; j < 6; j++) {
							if (j == b_addr_idx) {
								continue;
							}
							OperandType tp = list.instructions[back_idx].inst->operands[j].operand_type;
							if (tp == OPERAND_TYPE_REG8 || tp == OPERAND_TYPE_REG32) {
								if (r1 < 0) {
									r1 = (int)insn_get_operand_value (&list.instructions[back_idx], j);
								} else if (r2 < 0) {
									r2 = (int)insn_get_operand_value (&list.instructions[back_idx], j);
								}
							}
						}
						/* Jump back on true => continue on cond */
						RETURN_IF_ERROR (append_regname (out, r1, reg_names, max_regs));
						RETURN_IF_ERROR (string_buffer_append (out, " "));
						RETURN_IF_ERROR (string_buffer_append (out, bcmp));
						RETURN_IF_ERROR (string_buffer_append (out, " "));
						RETURN_IF_ERROR (append_regname (out, r2, reg_names, max_regs));
					} else {
						int ridx = -1;
						for (int j = 0; j < 6; j++) {
							if (j == b_addr_idx) {
								continue;
							}
							OperandType tp = list.instructions[back_idx].inst->operands[j].operand_type;
							if (tp == OPERAND_TYPE_REG8 || tp == OPERAND_TYPE_REG32) {
								ridx = j;
								break;
							}
						}
						int rr = (ridx >= 0)? (int)insn_get_operand_value (&list.instructions[back_idx], ridx): 0;
						bool is_true = (bop == OP_JmpTrue || bop == OP_JmpTrueLong);
						if (!is_true) {
							RETURN_IF_ERROR (string_buffer_append (out, "!"));
						}
						RETURN_IF_ERROR (append_regname (out, rr, reg_names, max_regs));
					}
					RETURN_IF_ERROR (string_buffer_append (out, ");\n"));
					/* Skip the back-edge jmp */
					skip[back_idx] = true;
					continue;
				}
			}
		}

		/* Learn parameter names on the fly */
		if (ins->opcode == OP_LoadParam || ins->opcode == OP_LoadParamLong) {
			/* handled later by reg_names mapping */
		}

		/* Try to recognize while-loop pattern: JmpFalse/JmpTrue to forward exit, body ends with Jmp back to header */
		int addr_idx = -1;
		if (is_jump_instruction (ins->opcode)) {
			for (int j = 0; j < 6; j++) {
				if (operand_is_addr (ins->inst, j)) {
					addr_idx = j;
					break;
				}
			}
		}
		if (addr_idx >= 0) {
			u8 opw = ins->opcode;
			bool is_simple_bool = (opw == OP_JmpFalse || opw == OP_JmpFalseLong || opw == OP_JmpTrue || opw == OP_JmpTrueLong);
			if (is_simple_bool) {
				u32 exit_addr = compute_target_address (ins, addr_idx);
				int exit_index = find_index_by_addr (&list, exit_addr);
				if (exit_index > (int)i) {
					/* Check that instruction before exit is an unconditional jump back to header */
					int back_idx = exit_index - 1;
					if (back_idx > (int)i) {
						ParsedInstruction *back = &list.instructions[back_idx];
						if (back->inst && (back->opcode == OP_Jmp || back->opcode == OP_JmpLong)) {
							int bj = -1;
							for (int j = 0; j < 6; j++) {
								if (operand_is_addr (back->inst, j)) {
									bj = j;
									break;
								}
							}
							if (bj >= 0) {
								u32 back_addr = compute_target_address (back, bj);
								if (back_addr == ins->original_pos) {
									/* Emit while header */
									StringBuffer hdr;
									RETURN_IF_ERROR (string_buffer_init (&hdr, 64));
									RETURN_IF_ERROR (append_indent (&hdr, base_indent));
									RETURN_IF_ERROR (string_buffer_append (&hdr, "while ("));
									/* build boolean condition from ins */
									int reg_idx = -1;
									for (int j = 0; j < 6; j++) {
										OperandType tp = ins->inst->operands[j].operand_type;
										if ((tp == OPERAND_TYPE_REG8 || tp == OPERAND_TYPE_REG32) && j != addr_idx) {
											reg_idx = j;
											break;
										}
									}
									int r = (reg_idx >= 0)? (int)insn_get_operand_value (ins, reg_idx): 0;
									bool neg = (opw == OP_JmpTrue || opw == OP_JmpTrueLong); /* jump on true to exit => loop while !r */
									if (neg) {
										RETURN_IF_ERROR (string_buffer_append (&hdr, "!"));
									}
									RETURN_IF_ERROR (append_regname (&hdr, r, reg_names, max_regs));
									RETURN_IF_ERROR (string_buffer_append (&hdr, ") {\n"));
									RETURN_IF_ERROR (string_buffer_append (out, hdr.data));
									string_buffer_free (&hdr);

									/* Emit loop body lines from i+1 to back_idx-1 */
									for (u32 k = i + 1; k < (u32)back_idx; k++) {
										skip[k] = true;
										ParsedInstruction *bi = &list.instructions[k];
										TokenString ts2;
										RETURN_IF_ERROR (translate_instruction_to_tokens (bi, &ts2));
										StringBuffer line;
										RETURN_IF_ERROR (string_buffer_init (&line, 128));
										RETURN_IF_ERROR (append_indent (&line, base_indent + 1));
										RETURN_IF_ERROR (token_string_to_string (&ts2, &line));
										RETURN_IF_ERROR (string_buffer_append (&line, ";"));
										StringBuffer dline;
										string_buffer_init (&dline, 64);
										Result sr2 = instruction_to_string (bi, &dline);
										if (sr2.code == RESULT_SUCCESS && dline.length > 0) {
											string_buffer_append (&line, "  // ");
											string_buffer_append (&line, dline.data);
										}
										string_buffer_free (&dline);
										string_buffer_append (&line, "\n");
										string_buffer_append (out, line.data);
										string_buffer_free (&line);
										token_string_cleanup (&ts2);
									}

									/* Close while */
									RETURN_IF_ERROR (append_indent (out, base_indent));
									RETURN_IF_ERROR (string_buffer_append (out, "}\n"));
									/* Skip header, body, back jump */
									skip[i] = true;
									skip[back_idx] = true;
									continue;
								}
							}
						}
					}
				}
			}
		}

		/* Try to recognize simple if / if-else */
		if (addr_idx >= 0) {
			u8 op = ins->opcode;
			bool is_simple_cond = (op == OP_JmpTrue || op == OP_JmpTrueLong || op == OP_JmpFalse || op == OP_JmpFalseLong || cmp_op_for_jump (op) != NULL);
			if (is_simple_cond) {
				u32 taddr = compute_target_address (ins, addr_idx);
				int tindex = find_index_by_addr (&list, taddr);
				if (tindex > (int)i) {
					/* Check for optional else: last insn of then-region is unconditional jump to end */
					int then_begin = (int)i + 1;
					int then_end = tindex; /* exclusive */
					int else_begin = -1, else_end = -1;
					if (then_end - 1 > (int)i) {
						ParsedInstruction *last_then = &list.instructions[then_end - 1];
						if (last_then->inst && (last_then->opcode == OP_Jmp || last_then->opcode == OP_JmpLong)) {
							int jaddr_idx = -1;
							for (int j = 0; j < 6; j++) {
								if (operand_is_addr (last_then->inst, j)) {
									jaddr_idx = j;
									break;
								}
							}
							if (jaddr_idx >= 0) {
								u32 end_addr = compute_target_address (last_then, jaddr_idx);
								int end_index = find_index_by_addr (&list, end_addr);
								if (end_index > tindex) {
									else_begin = tindex;
									else_end = end_index;
								}
							}
						}
					}

					/* Emit if header */
					StringBuffer hdr;
					RETURN_IF_ERROR (string_buffer_init (&hdr, 64));
					RETURN_IF_ERROR (append_indent (&hdr, base_indent));
					/* condition */
					RETURN_IF_ERROR (string_buffer_append (&hdr, "if ("));
					const char *cmp = cmp_op_for_jump (op);
					bool jump_on_true_hdr = (cmp != NULL) || (op == OP_JmpTrue || op == OP_JmpTrueLong) || (op == OP_JmpUndefined || op == OP_JmpUndefinedLong);
					bool invert_hdr = jump_on_true_hdr; /* then is fallthrough if jump taken */
					if (cmp) {
						int r1 = -1, r2 = -1;
						for (int j = 0; j < 6; j++) {
							if (j == addr_idx) {
								continue;
							}
							OperandType tp = ins->inst->operands[j].operand_type;
							if (tp == OPERAND_TYPE_REG8 || tp == OPERAND_TYPE_REG32) {
								if (r1 < 0) {
									r1 = (int)insn_get_operand_value (ins, j);
								} else if (r2 < 0) {
									r2 = (int)insn_get_operand_value (ins, j);
								}
							}
						}
						if (invert_hdr) {
							RETURN_IF_ERROR (string_buffer_append (&hdr, "!("));
						}
						RETURN_IF_ERROR (append_regname (&hdr, r1, reg_names, max_regs));
						RETURN_IF_ERROR (string_buffer_append (&hdr, " "));
						RETURN_IF_ERROR (string_buffer_append (&hdr, cmp));
						RETURN_IF_ERROR (string_buffer_append (&hdr, " "));
						RETURN_IF_ERROR (append_regname (&hdr, r2, reg_names, max_regs));
						if (invert_hdr) {
							RETURN_IF_ERROR (string_buffer_append (&hdr, ")"));
						}
					} else {
						int reg_idx = -1;
						for (int j = 0; j < 6; j++) {
							OperandType tp = ins->inst->operands[j].operand_type;
							if ((tp == OPERAND_TYPE_REG8 || tp == OPERAND_TYPE_REG32) && j != addr_idx) {
								reg_idx = j;
								break;
							}
						}
						int r = (reg_idx >= 0)? (int)insn_get_operand_value (ins, reg_idx): 0;
						if (invert_hdr || op == OP_JmpFalse || op == OP_JmpFalseLong) {
							RETURN_IF_ERROR (string_buffer_append (&hdr, "!"));
						}
						RETURN_IF_ERROR (append_regname (&hdr, r, reg_names, max_regs));
					}
					RETURN_IF_ERROR (string_buffer_append (&hdr, ") {\n"));
					RETURN_IF_ERROR (string_buffer_append (out, hdr.data));
					string_buffer_free (&hdr);

					/* Emit then-body */
					for (int k = then_begin; k < then_end; k++) {
						skip[k] = true; /* avoid re-emitting */
						ParsedInstruction *ti = &list.instructions[k];
						TokenString ts2;
						RETURN_IF_ERROR (translate_instruction_to_tokens (ti, &ts2));
						StringBuffer line;
						RETURN_IF_ERROR (string_buffer_init (&line, 128));
						RETURN_IF_ERROR (append_indent (&line, base_indent + 1));
						RETURN_IF_ERROR (token_string_to_string (&ts2, &line));
						RETURN_IF_ERROR (string_buffer_append (&line, ";"));
						StringBuffer dline;
						string_buffer_init (&dline, 64);
						Result sr2 = instruction_to_string (ti, &dline);
						if (sr2.code == RESULT_SUCCESS && dline.length > 0) {
							string_buffer_append (&line, "  // ");
							string_buffer_append (&line, dline.data);
						}
						string_buffer_free (&dline);
						string_buffer_append (&line, "\n");
						string_buffer_append (out, line.data);
						string_buffer_free (&line);
						token_string_cleanup (&ts2);
					}
					/* If there was an else, skip the trailing unconditional jmp */
					if (else_begin >= 0 && then_end - 1 > (int)i) {
						skip[then_end - 1] = true;
					}

					/* Close then */
					RETURN_IF_ERROR (append_indent (out, base_indent));
					RETURN_IF_ERROR (string_buffer_append (out, "}\n"));

					/* Else part */
					if (else_begin >= 0 && else_end > else_begin) {
						/* Emit else header */
						RETURN_IF_ERROR (append_indent (out, base_indent));
						RETURN_IF_ERROR (string_buffer_append (out, "else {\n"));
						for (int k = else_begin; k < else_end; k++) {
							skip[k] = true;
							ParsedInstruction *ei = &list.instructions[k];
							TokenString ts3;
							RETURN_IF_ERROR (translate_instruction_to_tokens (ei, &ts3));
							StringBuffer line;
							RETURN_IF_ERROR (string_buffer_init (&line, 128));
							RETURN_IF_ERROR (append_indent (&line, base_indent + 1));
							RETURN_IF_ERROR (token_string_to_string (&ts3, &line));
							RETURN_IF_ERROR (string_buffer_append (&line, ";"));
							StringBuffer dline;
							string_buffer_init (&dline, 64);
							Result sr3 = instruction_to_string (ei, &dline);
							if (sr3.code == RESULT_SUCCESS && dline.length > 0) {
								string_buffer_append (&line, "  // ");
								string_buffer_append (&line, dline.data);
							}
							string_buffer_free (&dline);
							string_buffer_append (&line, "\n");
							string_buffer_append (out, line.data);
							string_buffer_free (&line);
							token_string_cleanup (&ts3);
						}
						/* Close else */
						RETURN_IF_ERROR (append_indent (out, base_indent));
						RETURN_IF_ERROR (string_buffer_append (out, "}\n"));
					}
					/* Mark current conditional as handled */
					skip[i] = true;
					continue;
				}
			}
		}

		/* SwitchImm structuring */
		if (ins->opcode == OP_SwitchImm) {
			/* arg1: value reg, arg4: min, arg5: max, arg3: default (Addr32), switch_jump_table[] holds case targets (function-relative) */
			StringBuffer sbh;
			RETURN_IF_ERROR (string_buffer_init (&sbh, 64));
			RETURN_IF_ERROR (append_indent (&sbh, base_indent));
			RETURN_IF_ERROR (string_buffer_append (&sbh, "switch (r"));
			RETURN_IF_ERROR (string_buffer_append_int (&sbh, (int)ins->arg1));
			RETURN_IF_ERROR (string_buffer_append (&sbh, ") {\n"));
			RETURN_IF_ERROR (string_buffer_append (out, sbh.data));
			string_buffer_free (&sbh);
			u32 minv = ins->arg4, maxv = ins->arg5;
			for (u32 v = minv; v <= maxv && (v - minv) < ins->switch_jump_table_size; v++) {
				u32 tgt = ins->switch_jump_table[v - minv];
				char lab[32];
				label_name (lab, sizeof (lab), tgt);
				RETURN_IF_ERROR (append_indent (out, base_indent + 1));
				RETURN_IF_ERROR (string_buffer_append (out, "case "));
				char nbuf[32];
				snprintf (nbuf, sizeof (nbuf), "%u", v);
				RETURN_IF_ERROR (string_buffer_append (out, nbuf));
				RETURN_IF_ERROR (string_buffer_append (out, ": goto "));
				RETURN_IF_ERROR (string_buffer_append (out, lab));
				RETURN_IF_ERROR (string_buffer_append (out, ";\n"));
			}
			/* default */
			int def_idx = -1;
			for (int j = 0; j < 6; j++) {
				if (operand_is_addr (ins->inst, j)) {
					def_idx = j;
					break;
				}
			}
			if (def_idx >= 0) {
				u32 defaddr = compute_target_address (ins, def_idx);
				char dlab[32];
				label_name (dlab, sizeof (dlab), defaddr);
				RETURN_IF_ERROR (append_indent (out, base_indent + 1));
				RETURN_IF_ERROR (string_buffer_append (out, "default: goto "));
				RETURN_IF_ERROR (string_buffer_append (out, dlab));
				RETURN_IF_ERROR (string_buffer_append (out, ";\n"));
			}
			RETURN_IF_ERROR (append_indent (out, base_indent));
			RETURN_IF_ERROR (string_buffer_append (out, "}\n"));
			skip[i] = true;
			continue;
		}

		/* Default single-line printing path */
		/* Update naming map for params */
		if (ins->opcode == OP_LoadParam || ins->opcode == OP_LoadParamLong) {
			int dst = (int)ins->arg1;
			u32 pidx = ins->arg2;
			char tmp[32];
			snprintf (tmp, sizeof (tmp), "a%u", pidx);
			if (dst >= 0 && (u32)dst < max_regs) {
				free (reg_names[dst]);
				reg_names[dst] = strdup (tmp);
			}
		}

		TokenString ts;
		RETURN_IF_ERROR (translate_instruction_to_tokens (ins, &ts));
		apply_register_naming (&ts, reg_names, max_regs);
		StringBuffer line;
		RETURN_IF_ERROR (string_buffer_init (&line, 128));
		RETURN_IF_ERROR (append_indent (&line, base_indent));
		bool handled_cf = false;
		if (is_jump_instruction (ins->opcode)) {
			int aidx = -1;
			for (int j = 0; j < 6; j++) {
				if (operand_is_addr (ins->inst, j)) {
					aidx = j;
					break;
				}
			}
			if (aidx >= 0) {
				u32 taddr = compute_target_address (ins, aidx);
				char tlabel[32];
				label_name (tlabel, sizeof (tlabel), taddr);
				u8 op = ins->opcode;
				if (op == OP_Jmp || op == OP_JmpLong) {
					if (taddr != ins->next_pos) {
						string_buffer_append (&line, "goto ");
						string_buffer_append (&line, tlabel);
					}
					handled_cf = true;
				}
			}
		}
		if (!handled_cf) {
			/* Improve default CF printing for compare-and-jump and simple boolean/undefined jumps */
			if (is_jump_instruction (ins->opcode)) {
				int aidx = -1;
				for (int j = 0; j < 6; j++) {
					if (operand_is_addr (ins->inst, j)) {
						aidx = j;
						break;
					}
				}
				if (aidx >= 0) {
					u32 taddr = compute_target_address (ins, aidx);
					char tlabel[32];
					label_name (tlabel, sizeof (tlabel), taddr);
					const char *cmp = cmp_op_for_jump (ins->opcode);
					if (cmp) {
						int r1 = -1, r2 = -1;
						for (int j = 0; j < 6; j++) {
							if (j == aidx) {
								continue;
							}
							OperandType tp = ins->inst->operands[j].operand_type;
							if (tp == OPERAND_TYPE_REG8 || tp == OPERAND_TYPE_REG32) {
								if (r1 < 0) {
									r1 = (int)insn_get_operand_value (ins, j);
								} else if (r2 < 0) {
									r2 = (int)insn_get_operand_value (ins, j);
								}
							}
						}
						RETURN_IF_ERROR (string_buffer_append (&line, "if ("));
						RETURN_IF_ERROR (append_regname (&line, r1, reg_names, max_regs));
						RETURN_IF_ERROR (string_buffer_append (&line, " "));
						RETURN_IF_ERROR (string_buffer_append (&line, cmp));
						RETURN_IF_ERROR (string_buffer_append (&line, " "));
						RETURN_IF_ERROR (append_regname (&line, r2, reg_names, max_regs));
						RETURN_IF_ERROR (string_buffer_append (&line, ") goto "));
						RETURN_IF_ERROR (string_buffer_append (&line, tlabel));
						handled_cf = true;
					} else {
						/* Handle JmpTrue/JmpFalse/JmpUndefined (+ long) */
						u8 opj = ins->opcode;
						if (opj == OP_JmpTrue || opj == OP_JmpTrueLong || opj == OP_JmpFalse || opj == OP_JmpFalseLong || opj == OP_JmpUndefined || opj == OP_JmpUndefinedLong) {
							int ridx = -1;
							for (int j = 0; j < 6; j++) {
								if (j == aidx) {
									continue;
								}
								OperandType tp = ins->inst->operands[j].operand_type;
								if (tp == OPERAND_TYPE_REG8 || tp == OPERAND_TYPE_REG32) {
									ridx = j;
									break;
								}
							}
							int rr = (ridx >= 0)? (int)insn_get_operand_value (ins, ridx): 0;
							RETURN_IF_ERROR (string_buffer_append (&line, "if ("));
							if (opj == OP_JmpFalse || opj == OP_JmpFalseLong) {
								RETURN_IF_ERROR (string_buffer_append (&line, "!"));
								RETURN_IF_ERROR (append_regname (&line, rr, reg_names, max_regs));
							} else if (opj == OP_JmpUndefined || opj == OP_JmpUndefinedLong) {
								RETURN_IF_ERROR (append_regname (&line, rr, reg_names, max_regs));
								RETURN_IF_ERROR (string_buffer_append (&line, " === undefined"));
							} else {
								RETURN_IF_ERROR (append_regname (&line, rr, reg_names, max_regs));
							}
							RETURN_IF_ERROR (string_buffer_append (&line, ") goto "));
							RETURN_IF_ERROR (string_buffer_append (&line, tlabel));
							handled_cf = true;
						}
					}
				}
			}
			if (!handled_cf) {
				RETURN_IF_ERROR (token_string_to_string (&ts, &line));
			}
		}
		RETURN_IF_ERROR (string_buffer_append (&line, ";"));
		/* Append trailing disassembly as a comment unless disabled */
		if (!options.suppress_comments) {
			StringBuffer dline;
			string_buffer_init (&dline, 64);
			Result sr = instruction_to_string (ins, &dline);
			if (sr.code == RESULT_SUCCESS && dline.length > 0) {
				string_buffer_append (&line, "  // ");
				string_buffer_append (&line, dline.data);
			}
			string_buffer_free (&dline);
		}
		string_buffer_append (&line, "\n");
		string_buffer_append (out, line.data);
		string_buffer_free (&line);
		token_string_cleanup (&ts);
	}
	free (skip);
	for (u32 rn = 0; rn < max_regs; rn++) {
		free (reg_names[rn]);
	}
	free (reg_names);
	parsed_instruction_list_free (&list);
	u32set_free (&labels);

	// Close function body
	RETURN_IF_ERROR (string_buffer_append (out, "}\n\n"));
	return SUCCESS_RESULT ();
}

Result decompile_function_to_buffer(HBCReader *reader, u32 function_id, HBCDecompileOptions options, StringBuffer *out) {
	// Emit a JS function stub with minimal decompiled statements and disassembly comments per line
	return emit_minimal_decompiled_function (reader, function_id, options, out);
}

Result decompile_all_to_buffer(HBCReader *reader, HBCDecompileOptions options, StringBuffer *out) {
	if (!reader || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for decompile_all_to_buffer");
	}
	// File preamble (comment-only; skip if comments disabled)
	if (!options.suppress_comments) {
		RETURN_IF_ERROR (string_buffer_append (out, "// Decompiled Hermes bytecode\n"));
		RETURN_IF_ERROR (string_buffer_append (out, "// Version: "));
		char vbuf[32];
		snprintf (vbuf, sizeof (vbuf), "%u", reader->header.version);
		RETURN_IF_ERROR (string_buffer_append (out, vbuf));
		RETURN_IF_ERROR (string_buffer_append (out, "\n\n"));
	}

	for (u32 i = 0; i < reader->header.functionCount; i++) {
		RETURN_IF_ERROR (decompile_function_to_buffer (reader, i, options, out));
	}
	return SUCCESS_RESULT ();
}

// These functions can be implemented later as needed
Result pass1_set_metadata(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	// Stub implementation
	(void)state;
	(void)function_body;
	return SUCCESS_RESULT ();
}

Result pass2_transform_code(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	// Stub implementation
	(void)state;
	(void)function_body;
	return SUCCESS_RESULT ();
}

Result pass3_parse_forin_loops(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	// Stub implementation
	(void)state;
	(void)function_body;
	return SUCCESS_RESULT ();
}

Result pass4_name_closure_vars(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	// Stub implementation
	(void)state;
	(void)function_body;
	return SUCCESS_RESULT ();
}

Result output_code(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	// Stub implementation
	(void)state;
	(void)function_body;
	return SUCCESS_RESULT ();
}

Result decompile_function(HermesDecompiler *state, u32 function_id, Environment *parent_environment,
	int environment_id, bool is_closure, bool is_generator, bool is_async) {
	// Stub implementation
	(void)state;
	(void)function_id;
	(void)parent_environment;
	(void)environment_id;
	(void)is_closure;
	(void)is_generator;
	(void)is_async;
	return SUCCESS_RESULT ();
}

/* removed old stubs (replaced above with real implementations) */
