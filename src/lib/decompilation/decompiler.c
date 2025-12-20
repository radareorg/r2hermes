#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/decompilation/token.h>
#include <hbc/parser.h>
#include <hbc/bytecode.h>
#include <hbc/disasm.h>
#include <hbc/decompilation/translator.h>
#include <hbc/opcodes.h>
#include <hbc/decompilation/literals.h>

/* Ensure that the function's bytecode buffer is loaded into memory. */
/**
 * Load bytecode for a function using the data provider.
 * Used when decompiling with provider-based API.
 */
static Result ensure_function_bytecode_loaded_from_provider(HBCDataProvider *provider, FunctionHeader *function_header, u32 function_id) {
	if (!provider || !function_header) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "ensure: provider or header NULL");
	}
	if (function_header->bytecode) {
		return SUCCESS_RESULT ();
	}

	/* Get bytecode from provider */
	const u8 *bytecode_ptr = NULL;
	u32 bytecode_size = 0;
	Result res = hbc_data_provider_get_bytecode (provider, function_id, &bytecode_ptr, &bytecode_size);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	/* Allocate and copy bytecode */
	function_header->bytecode = (u8 *)malloc (bytecode_size);
	if (!function_header->bytecode) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate bytecode buffer");
	}
	memcpy (function_header->bytecode, bytecode_ptr, bytecode_size);
	function_header->bytecodeSizeInBytes = bytecode_size;

	return SUCCESS_RESULT ();
}

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
	/* Set the bit in bitmap with bounds check */
	if (s->bitmap) {
		if (v / 8 >= s->bitmap_size) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "u32set value out of bitmap bounds");
		}
		s->bitmap[v / 8] |= (1 << (v % 8));
	}
	if (s->count >= s->cap) {
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
#if 0
static void label_name(char *buf, size_t bufsz, u32 addr) {
	snprintf (buf, bufsz, "L_%08x", addr);
}
#endif
static Result append_indent(StringBuffer *sb, int level) {
	for (int i = 0; i < level; i++) {
		RETURN_IF_ERROR (string_buffer_append (sb, "  "));
	}
	return SUCCESS_RESULT ();
}
#if 0
static int find_index_by_addr(ParsedInstructionList *list, u32 addr) {
	for (u32 i = 0; i < list->count; i++) {
		if (list->instructions[i].original_pos == addr) {
			return (int)i;
		}
	}
	return -1;
}
#endif

#if 0
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
#endif

/* Register naming helpers */
#if 0
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
#endif

static Result token_string_clear_tokens(TokenString *ts) {
	if (!ts) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "token_string_clear_tokens: ts NULL");
	}
	ParsedInstruction *asm_ref = ts->assembly;
	token_string_cleanup (ts);
	ts->assembly = asm_ref;
	return SUCCESS_RESULT ();
}

static Result statements_push(DecompiledFunctionBody *fb, const TokenString *ts) {
	if (!fb || !ts) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "statements_push args");
	}
	if (fb->statements_count >= fb->statements_capacity) {
		u32 nc = fb->statements_capacity? (fb->statements_capacity * 2): 64;
		TokenString *na = (TokenString *)realloc (fb->statements, nc * sizeof (TokenString));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom statements");
		}
		fb->statements = na;
		fb->statements_capacity = nc;
	}
	fb->statements[fb->statements_count++] = *ts;
	return SUCCESS_RESULT ();
}

static int cmp_u32(const void *a, const void *b) {
	u32 aa = *(const u32 *)a;
	u32 bb = *(const u32 *)b;
	return (aa > bb) - (aa < bb);
}

static Result nested_frames_push(DecompiledFunctionBody *fb, u32 start, u32 end) {
	if (!fb) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "nested_frames_push: fb NULL");
	}
	if (fb->nested_frames_count >= fb->nested_frames_capacity) {
		u32 nc = fb->nested_frames_capacity? (fb->nested_frames_capacity * 2): 8;
		NestedFrame *na = (NestedFrame *)realloc (fb->nested_frames, nc * sizeof (NestedFrame));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom nested_frames");
		}
		fb->nested_frames = na;
		fb->nested_frames_capacity = nc;
	}
	fb->nested_frames[fb->nested_frames_count++] = (NestedFrame){ .start_address = start, .end_address = end };
	return SUCCESS_RESULT ();
}

static Environment *envmap_get(const DecompiledFunctionBody *fb, int reg) {
	if (!fb || reg < 0) {
		return NULL;
	}
	if ((u32)reg >= fb->local_items_count) {
		return NULL;
	}
	return fb->local_items[reg];
}

static Result envmap_set(DecompiledFunctionBody *fb, int reg, Environment *env) {
	if (!fb || reg < 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "envmap_set args");
	}
	u32 need = (u32)reg + 1;
	if (need > fb->local_items_capacity) {
		u32 nc = fb->local_items_capacity? fb->local_items_capacity: 8;
		while (nc < need) {
			nc *= 2;
		}
		Environment **na = (Environment **)realloc (fb->local_items, nc * sizeof (Environment *));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom envmap");
		}
		for (u32 i = fb->local_items_capacity; i < nc; i++) {
			na[i] = NULL;
		}
		fb->local_items = na;
		fb->local_items_capacity = nc;
	}
	if (need > fb->local_items_count) {
		for (u32 i = fb->local_items_count; i < need; i++) {
			fb->local_items[i] = NULL;
		}
		fb->local_items_count = need;
	}
	fb->local_items[reg] = env;
	return SUCCESS_RESULT ();
}

static Result owned_env_push(DecompiledFunctionBody *fb, Environment *env) {
	if (!fb || !env) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "owned_env_push args");
	}
	if (fb->owned_environments_count >= fb->owned_environments_capacity) {
		u32 nc = fb->owned_environments_capacity? (fb->owned_environments_capacity * 2): 8;
		Environment **na = (Environment **)realloc (fb->owned_environments, nc * sizeof (Environment *));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom owned_envs");
		}
		fb->owned_environments = na;
		fb->owned_environments_capacity = nc;
	}
	fb->owned_environments[fb->owned_environments_count++] = env;
	return SUCCESS_RESULT ();
}

static Result environment_slot_set(Environment *env, int slot_index, const char *name) {
	if (!env || slot_index < 0 || !name) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "environment_slot_set args");
	}
	if (slot_index >= env->slot_capacity) {
		int nc = env->slot_capacity? env->slot_capacity: 4;
		while (nc <= slot_index) {
			nc *= 2;
		}
		char **na = (char **)realloc (env->slot_index_to_varname, (size_t)nc * sizeof (char *));
		if (!na) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom env slots");
		}
		for (int i = env->slot_capacity; i < nc; i++) {
			na[i] = NULL;
		}
		env->slot_index_to_varname = na;
		env->slot_capacity = nc;
	}
	if (!env->slot_index_to_varname[slot_index]) {
		env->slot_index_to_varname[slot_index] = strdup (name);
		if (!env->slot_index_to_varname[slot_index]) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom strdup");
		}
	}
	if (slot_index + 1 > env->var_count) {
		env->var_count = slot_index + 1;
	}
	return SUCCESS_RESULT ();
}

static const char *environment_slot_get(Environment *env, int slot_index) {
	if (!env || slot_index < 0 || slot_index >= env->slot_capacity) {
		return NULL;
	}
	return env->slot_index_to_varname? env->slot_index_to_varname[slot_index]: NULL;
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
	if (!fb) {
		return NULL;
	}
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
	body->function_name = NULL;
	body->statements = NULL;
	body->statements_count = body->statements_capacity = 0;
	body->basic_blocks = NULL;
	body->basic_blocks_count = body->basic_blocks_capacity = 0;
	body->nested_frames = NULL;
	body->nested_frames_count = body->nested_frames_capacity = 0;
	body->jump_targets = NULL;
	body->jump_targets_count = body->jump_targets_capacity = 0;
	body->local_items = NULL;
	body->local_items_count = body->local_items_capacity = 0;
	body->owned_environments = NULL;
	body->owned_environments_count = body->owned_environments_capacity = 0;
	body->instructions.instructions = NULL;
	body->instructions.count = body->instructions.capacity = 0;
	/* Exception handlers */
	return SUCCESS_RESULT ();
}

void function_body_cleanup(DecompiledFunctionBody *body) {
	if (!body) {
		return;
	}
	free (body->function_name);
	if (body->try_starts) {
		for (u32 i = 0; i < body->try_starts_count; i++) {
			for (u32 k = 0; k < body->try_starts[i].label_count; k++) {
				free (body->try_starts[i].labels[k]);
			}
			free (body->try_starts[i].labels);
		}
		free (body->try_starts);
	}
	if (body->try_ends) {
		for (u32 i = 0; i < body->try_ends_count; i++) {
			for (u32 k = 0; k < body->try_ends[i].label_count; k++) {
				free (body->try_ends[i].labels[k]);
			}
			free (body->try_ends[i].labels);
		}
		free (body->try_ends);
	}
	if (body->catch_targets) {
		for (u32 i = 0; i < body->catch_targets_count; i++) {
			for (u32 k = 0; k < body->catch_targets[i].label_count; k++) {
				free (body->catch_targets[i].labels[k]);
			}
			free (body->catch_targets[i].labels);
		}
		free (body->catch_targets);
	}
	free (body->jump_anchors);
	free (body->ret_anchors);
	free (body->throw_anchors);
	free (body->jump_targets);
	if (body->basic_blocks) {
		for (u32 i = 0; i < body->basic_blocks_count; i++) {
			BasicBlock *bb = &body->basic_blocks[i];
			free (bb->jump_targets_for_anchor);
			free (bb->child_nodes);
			free (bb->parent_nodes);
			free (bb->error_handling_child_nodes);
			free (bb->error_handling_parent_nodes);
		}
	}
	free (body->basic_blocks);
	free (body->nested_frames);
	if (body->owned_environments) {
		for (u32 i = 0; i < body->owned_environments_count; i++) {
			Environment *env = body->owned_environments[i];
			if (!env) {
				continue;
			}
			if (env->slot_index_to_varname) {
				for (int si = 0; si < env->slot_capacity; si++) {
					free (env->slot_index_to_varname[si]);
				}
				free (env->slot_index_to_varname);
			}
			free (env);
		}
		free (body->owned_environments);
	}
	free (body->local_items);
	if (body->statements) {
		for (u32 i = 0; i < body->statements_count; i++) {
			token_string_cleanup (&body->statements[i]);
		}
		free (body->statements);
	}
	parsed_instruction_list_free (&body->instructions);
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
		/* Handle switch statements: add edges to all jump table targets */
		if (last->switch_jump_table && last->switch_jump_table_size) {
			for (u32 j = 0; j < last->switch_jump_table_size; j++) {
				u32 tgt = last->switch_jump_table[j];
				if (tgt < fh->bytecodeSizeInBytes) {
					BasicBlock *child = find_block_by_start (out_body, tgt);
					if (child) {
						RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->child_nodes_capacity, child));
					}
				}
			}
			/* switch is unconditional in the sense that one target must be taken */
			bb->is_unconditional_jump_anchor = true;
		}
		if (is_jump_instruction (op)) {
			/* compute targets */
			for (int j = 0; j < 6; j++) {
				if (!operand_is_addr (last->inst, j)) {
					continue;
				}
				u32 tgt = compute_target_address (last, j);
				if (tgt < fh->bytecodeSizeInBytes) {
					BasicBlock *child = find_block_by_start (out_body, tgt);
					if (child) {
						RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->child_nodes_capacity, child));
					}
				}
			}
			/* conditional: also add fallthrough */
			bool is_uncond = (op == OP_Jmp || op == OP_JmpLong);
			if (!is_uncond && last->next_pos < fh->bytecodeSizeInBytes) {
				BasicBlock *fall = find_block_by_start (out_body, last->next_pos);
				if (fall) {
					RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->child_nodes_capacity, fall));
				}
			} else if (is_uncond) {
				bb->is_unconditional_jump_anchor = true;
			}
		} else {
			/* normal fallthrough */
			if (last->next_pos < fh->bytecodeSizeInBytes) {
				BasicBlock *fall = find_block_by_start (out_body, last->next_pos);
				if (fall) {
					RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->child_nodes_capacity, fall));
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
	decompiler->decompiled_functions = NULL;
	decompiler->indent_level = 0;
	decompiler->inlining_function = false;
	decompiler->data_provider = NULL; /* Will be set if using provider-based API */
	decompiler->options.pretty_literals = true;
	decompiler->options.suppress_comments = false;

	// Initialize string buffer for output
	string_buffer_init (&decompiler->output, 4096); // Start with 4KB buffer

	return SUCCESS_RESULT ();
}

Result decompiler_init_with_provider(HermesDecompiler *decompiler, HBCDataProvider *provider) {
	if (!decompiler || !provider) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler or provider pointer");
	}

	/* Initialize common fields */
	Result res = decompiler_init (decompiler);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	/* Store provider reference */
	decompiler->data_provider = provider;

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

	// Free decompiled functions tracker
	if (decompiler->decompiled_functions) {
		free (decompiler->decompiled_functions);
		decompiler->decompiled_functions = NULL;
	}

	// Free data provider if owned by decompiler
	/* Note: We don't free the provider here because it may be owned by caller.
	 * The provider lifecycle is managed externally, not by decompiler. */
	decompiler->data_provider = NULL;

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

/* Internal helper kept for reference/debugging.
 * The main pipeline uses passes + `output_code ()`. */
#if 0
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
										Result sr_ts = translate_instruction_to_tokens (bi, &ts2);
										if (sr_ts.code != RESULT_SUCCESS) {
											token_string_cleanup (&ts2);
											RETURN_IF_ERROR (sr_ts);
										}
										StringBuffer line;
										Result sr_init = string_buffer_init (&line, 128);
										if (sr_init.code != RESULT_SUCCESS) {
											token_string_cleanup (&ts2);
											RETURN_IF_ERROR (sr_init);
										}
										Result sr_indent = append_indent (&line, base_indent + 1);
										if (sr_indent.code != RESULT_SUCCESS) {
											string_buffer_free (&line);
											token_string_cleanup (&ts2);
											RETURN_IF_ERROR (sr_indent);
										}
										Result sr_ts2str = token_string_to_string (&ts2, &line);
										if (sr_ts2str.code != RESULT_SUCCESS) {
											string_buffer_free (&line);
											token_string_cleanup (&ts2);
											RETURN_IF_ERROR (sr_ts2str);
										}
										string_buffer_append (&line, ";");
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
						Result sr_ts = translate_instruction_to_tokens (ti, &ts2);
						if (sr_ts.code != RESULT_SUCCESS) {
							token_string_cleanup (&ts2);
							RETURN_IF_ERROR (sr_ts);
						}
						StringBuffer line;
						Result sr_init = string_buffer_init (&line, 128);
						if (sr_init.code != RESULT_SUCCESS) {
							token_string_cleanup (&ts2);
							RETURN_IF_ERROR (sr_init);
						}
						Result sr_indent = append_indent (&line, base_indent + 1);
						if (sr_indent.code != RESULT_SUCCESS) {
							string_buffer_free (&line);
							token_string_cleanup (&ts2);
							RETURN_IF_ERROR (sr_indent);
						}
						Result sr_ts2str = token_string_to_string (&ts2, &line);
						if (sr_ts2str.code != RESULT_SUCCESS) {
							string_buffer_free (&line);
							token_string_cleanup (&ts2);
							RETURN_IF_ERROR (sr_ts2str);
						}
						string_buffer_append (&line, ";");
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
							Result sr_ts = translate_instruction_to_tokens (ei, &ts3);
							if (sr_ts.code != RESULT_SUCCESS) {
								token_string_cleanup (&ts3);
								RETURN_IF_ERROR (sr_ts);
							}
							StringBuffer line;
							Result sr_init = string_buffer_init (&line, 128);
							if (sr_init.code != RESULT_SUCCESS) {
								token_string_cleanup (&ts3);
								RETURN_IF_ERROR (sr_init);
							}
							Result sr_indent = append_indent (&line, base_indent + 1);
							if (sr_indent.code != RESULT_SUCCESS) {
								string_buffer_free (&line);
								token_string_cleanup (&ts3);
								RETURN_IF_ERROR (sr_indent);
							}
							Result sr_ts3str = token_string_to_string (&ts3, &line);
							if (sr_ts3str.code != RESULT_SUCCESS) {
								string_buffer_free (&line);
								token_string_cleanup (&ts3);
								RETURN_IF_ERROR (sr_ts3str);
							}
							string_buffer_append (&line, ";");
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
#endif

Result decompile_function_to_buffer(HBCReader *reader, u32 function_id, HBCDecompileOptions options, StringBuffer *out) {
	if (!reader || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "decompile_function_to_buffer args");
	}
	HermesDecompiler dec;
	RETURN_IF_ERROR (decompiler_init (&dec));
	dec.hbc_reader = reader;
	dec.options = options;
	dec.indent_level = 0;
	Result r = decompile_function (&dec, function_id, NULL, -1, false, false, false);
	if (r.code == RESULT_SUCCESS) {
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "\n\n"));
		RETURN_IF_ERROR (string_buffer_append (out, dec.output.data? dec.output.data: ""));
	}
	decompiler_cleanup (&dec);
	return r;
}

Result decompile_all_to_buffer(HBCReader *reader, HBCDecompileOptions options, StringBuffer *out) {
	if (!reader || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for decompile_all_to_buffer");
	}
	HermesDecompiler dec;
	RETURN_IF_ERROR (decompiler_init (&dec));
	dec.hbc_reader = reader;
	dec.options = options;
	dec.indent_level = 0;

	/* Allocate tracking array for decompiled functions */
	dec.decompiled_functions = (bool *)calloc (reader->header.functionCount, sizeof (bool));
	if (!dec.decompiled_functions) {
		decompiler_cleanup (&dec);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate decompiled_functions tracker");
	}

	/* File preamble */
	if (!options.suppress_comments) {
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "// Decompiled Hermes bytecode\n"));
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "// Version: "));
		char vbuf[32];
		snprintf (vbuf, sizeof (vbuf), "%u", reader->header.version);
		RETURN_IF_ERROR (string_buffer_append (&dec.output, vbuf));
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "\n\n"));
	}

	for (u32 i = 0; i < reader->header.functionCount; i++) {
		/* Skip if already decompiled as a nested function */
		if (dec.decompiled_functions[i]) {
			continue;
		}
		Result r = decompile_function (&dec, i, NULL, -1, false, false, false);
		if (r.code != RESULT_SUCCESS) {
			decompiler_cleanup (&dec);
			return r;
		}
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "\n\n"));
	}

	RETURN_IF_ERROR (string_buffer_append (out, dec.output.data? dec.output.data: ""));
	decompiler_cleanup (&dec);
	return SUCCESS_RESULT ();
}

Result decompile_function_with_provider(HBCDataProvider *provider, u32 function_id, HBCDecompileOptions options, StringBuffer *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "decompile_function_with_provider args");
	}

	/* For now, leverage existing decompile_function_to_buffer by extracting reader.
	 * In Phase 2, we delegate to the provider API. This is a bridge.
	 * TODO: Refactor decompile_function to work directly with provider data */

	/* Try to use existing decompile_function_to_buffer if we can extract HBCReader */
	HermesDecompiler dec;
	RETURN_IF_ERROR (decompiler_init_with_provider (&dec, provider));
	dec.options = options;
	dec.indent_level = 0;

	/* Create a stub HBCReader for internal use.
	 * The provider is responsible for all actual data access. */
	HBCReader stub_reader;
	memset (&stub_reader, 0, sizeof (stub_reader));
	dec.hbc_reader = &stub_reader;

	/* Get header from provider and populate stub */
	HBCHeader header;
	Result hres = hbc_data_provider_get_header (provider, &header);
	if (hres.code != RESULT_SUCCESS) {
		decompiler_cleanup (&dec);
		return hres;
	}
	stub_reader.header = header;

	/* Validate function_id */
	if (function_id >= header.functionCount) {
		decompiler_cleanup (&dec);
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
	}

	/* Allocate and populate function_headers */
	stub_reader.function_headers = (FunctionHeader *)calloc (header.functionCount, sizeof (FunctionHeader));
	if (!stub_reader.function_headers) {
		decompiler_cleanup (&dec);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function_headers");
	}

	for (u32 i = 0; i < header.functionCount; i++) {
		HBCFunctionInfo fi;
		Result fres = hbc_data_provider_get_function_info (provider, i, &fi);
		if (fres.code != RESULT_SUCCESS) {
			free (stub_reader.function_headers);
			decompiler_cleanup (&dec);
			return fres;
		}
		stub_reader.function_headers[i].offset = fi.offset;
		stub_reader.function_headers[i].bytecodeSizeInBytes = fi.size;
		stub_reader.function_headers[i].bytecode = NULL;
	}

	/* Populate strings array from provider */
	if (header.stringCount > 0) {
		stub_reader.strings = (char **)calloc (header.stringCount, sizeof (char *));
		if (!stub_reader.strings) {
			free (stub_reader.function_headers);
			decompiler_cleanup (&dec);
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate strings array");
		}
		for (u32 i = 0; i < header.stringCount; i++) {
			const char *str = NULL;
			Result sres = hbc_data_provider_get_string (provider, i, &str);
			if (sres.code == RESULT_SUCCESS && str) {
				stub_reader.strings[i] = (char *)str; /* Provider owns the string, we just reference it */
			}
		}
	}

	Result r = decompile_function (&dec, function_id, NULL, -1, false, false, false);
	if (r.code == RESULT_SUCCESS) {
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "\n\n"));
		RETURN_IF_ERROR (string_buffer_append (out, dec.output.data? dec.output.data: ""));
	}

	/* Free allocated arrays (strings are owned by provider, don't free individual strings) */
	free (stub_reader.strings);
	free (stub_reader.function_headers);

	decompiler_cleanup (&dec);
	return r;
}

Result decompile_all_with_provider(HBCDataProvider *provider, HBCDecompileOptions options, StringBuffer *out) {
	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for decompile_all_with_provider");
	}
	HermesDecompiler dec;
	RETURN_IF_ERROR (decompiler_init_with_provider (&dec, provider));
	dec.options = options;
	dec.indent_level = 0;

	/* Create a stub HBCReader for internal use */
	HBCReader stub_reader;
	memset (&stub_reader, 0, sizeof (stub_reader));
	dec.hbc_reader = &stub_reader;

	/* Get header from provider and populate stub */
	HBCHeader header;
	Result res = hbc_data_provider_get_header (provider, &header);
	if (res.code != RESULT_SUCCESS) {
		decompiler_cleanup (&dec);
		return res;
	}
	stub_reader.header = header;

	/* Get function count from provider */
	u32 func_count = header.functionCount;
	if (func_count == 0) {
		/* No functions to decompile */
		RETURN_IF_ERROR (string_buffer_append (out, ""));
		decompiler_cleanup (&dec);
		return SUCCESS_RESULT ();
	}

	/* Allocate tracking array for decompiled functions */
	dec.decompiled_functions = (bool *)calloc (func_count, sizeof (bool));
	if (!dec.decompiled_functions) {
		decompiler_cleanup (&dec);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate decompiled_functions tracker");
	}

	/* Allocate function_headers array for the stub */
	stub_reader.function_headers = (FunctionHeader *)calloc (func_count, sizeof (FunctionHeader));
	if (!stub_reader.function_headers) {
		decompiler_cleanup (&dec);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function_headers");
	}

	/* Populate function_headers from provider */
	for (u32 i = 0; i < func_count; i++) {
		HBCFunctionInfo fi;
		Result fres = hbc_data_provider_get_function_info (provider, i, &fi);
		if (fres.code != RESULT_SUCCESS) {
			free (stub_reader.function_headers);
			decompiler_cleanup (&dec);
			return fres;
		}
		stub_reader.function_headers[i].offset = fi.offset;
		stub_reader.function_headers[i].bytecodeSizeInBytes = fi.size;
		stub_reader.function_headers[i].bytecode = NULL; /* Will be loaded on demand */
		/* Other fields are not needed for provider-based decompilation */
	}

	/* Populate strings array from provider */
	if (header.stringCount > 0) {
		stub_reader.strings = (char **)calloc (header.stringCount, sizeof (char *));
		if (!stub_reader.strings) {
			free (stub_reader.function_headers);
			decompiler_cleanup (&dec);
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate strings array");
		}
		for (u32 i = 0; i < header.stringCount; i++) {
			const char *str = NULL;
			Result sres = hbc_data_provider_get_string (provider, i, &str);
			if (sres.code == RESULT_SUCCESS && str) {
				stub_reader.strings[i] = (char *)str; /* Provider owns the string, we just reference it */
			}
		}
	}

	/* File preamble */
	if (!options.suppress_comments) {
		HBCHeader header;
		res = hbc_data_provider_get_header (provider, &header);
		if (res.code != RESULT_SUCCESS) {
			decompiler_cleanup (&dec);
			return res;
		}
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "// Decompiled Hermes bytecode\n"));
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "// Version: "));
		char vbuf[32];
		snprintf (vbuf, sizeof (vbuf), "%u", header.version);
		RETURN_IF_ERROR (string_buffer_append (&dec.output, vbuf));
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "\n\n"));
	}

	for (u32 i = 0; i < func_count; i++) {
		/* Skip if already decompiled as a nested function */
		if (dec.decompiled_functions[i]) {
			continue;
		}
		Result r = decompile_function (&dec, i, NULL, -1, false, false, false);
		if (r.code != RESULT_SUCCESS) {
			decompiler_cleanup (&dec);
			return r;
		}
		RETURN_IF_ERROR (string_buffer_append (&dec.output, "\n\n"));
	}

	RETURN_IF_ERROR (string_buffer_append (out, dec.output.data? dec.output.data: ""));

	/* Free allocated arrays (strings are owned by provider, don't free individual strings) */
	free (stub_reader.strings);
	free (stub_reader.function_headers);

	decompiler_cleanup (&dec);
	return SUCCESS_RESULT ();
}

static Result address_labels_add(AddressLabels **arr, u32 *count, u32 address, const char *label) {
	if (!arr || !count || !label) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "address_labels_add args");
	}
	for (u32 i = 0; i < *count; i++) {
		if ((*arr)[i].address != address) {
			continue;
		}
		char **nl = (char **)realloc ((*arr)[i].labels, ((*arr)[i].label_count + 1) * sizeof (char *));
		if (!nl) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom labels");
		}
		(*arr)[i].labels = nl;
		(*arr)[i].labels[(*arr)[i].label_count] = strdup (label);
		if (! (*arr)[i].labels[(*arr)[i].label_count]) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom strdup label");
		}
		(*arr)[i].label_count++;
		return SUCCESS_RESULT ();
	}

	AddressLabels *na = (AddressLabels *)realloc (*arr, ((*count) + 1) * sizeof (AddressLabels));
	if (!na) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom addrlabels");
	}
	*arr = na;
	(*arr)[*count].address = address;
	(*arr)[*count].labels = (char **)malloc (sizeof (char *));
	if (! (*arr)[*count].labels) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom addrlabels labels");
	}
	(*arr)[*count].labels[0] = strdup (label);
	if (! (*arr)[*count].labels[0]) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom strdup label");
	}
	(*arr)[*count].label_count = 1;
	(*count)++;
	return SUCCESS_RESULT ();
}

static bool bbvec_contains(BasicBlock **arr, u32 count, BasicBlock *bb) {
	for (u32 i = 0; i < count; i++) {
		if (arr[i] == bb) {
			return true;
		}
	}
	return false;
}

static bool token_needs_space(TokenType prev, TokenType cur) {
	bool cur_punct = (cur == TOKEN_TYPE_LEFT_PARENTHESIS || cur == TOKEN_TYPE_RIGHT_PARENTHESIS || cur == TOKEN_TYPE_DOT_ACCESSOR);
	if (cur_punct || prev == TOKEN_TYPE_LEFT_PARENTHESIS || cur == TOKEN_TYPE_RIGHT_PARENTHESIS || cur == TOKEN_TYPE_DOT_ACCESSOR) {
		return false;
	}
	if (prev == TOKEN_TYPE_DOT_ACCESSOR) {
		return false;
	}
	if (prev == TOKEN_TYPE_ASSIGNMENT || cur == TOKEN_TYPE_ASSIGNMENT) {
		return true;
	}
	return true;
}

Result pass1_set_metadata(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	if (!state || !state->hbc_reader || !function_body || !function_body->function_object) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "pass1_set_metadata args");
	}

	HBCReader *reader = state->hbc_reader;
	FunctionHeader *fh = function_body->function_object;
	u32 func_sz = fh->bytecodeSizeInBytes;

	/* Function name - prefer flag name from r2 over embedded name */
	const char *name = NULL;
	char *flag_name = NULL;

	/* Try flag callback first (e.g., r2 flags) */
	if (state->options.flag_callback) {
		flag_name = state->options.flag_callback (state->options.flag_context, (u64)fh->offset);
		if (flag_name && *flag_name) {
			name = flag_name;
		}
	}

	/* Fall back to embedded function name */
	if (!name && reader->strings && fh->functionName < reader->header.stringCount) {
		name = reader->strings[fh->functionName];
	}
	if (!name || !*name) {
		name = "anonymous";
	}
	free (function_body->function_name);
	function_body->function_name = strdup (name);
	free (flag_name); /* Free the heap-allocated flag name */
	if (!function_body->function_name) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom function_name");
	}

	/* Exception handlers + try/catch metadata */
	function_body->exc_handlers = NULL;
	function_body->exc_handlers_count = 0;
	if (fh->hasExceptionHandler && reader->function_id_to_exc_handlers && function_body->function_id < reader->header.functionCount) {
		ExceptionHandlerList *eh = &reader->function_id_to_exc_handlers[function_body->function_id];
		function_body->exc_handlers = eh->handlers;
		function_body->exc_handlers_count = eh->count;
	}

	/* Allocate anchor maps indexed by address (0..func_sz) */
	u32 map_sz = func_sz + 1;
	function_body->jump_anchors = (ParsedInstruction **)calloc (map_sz, sizeof (ParsedInstruction *));
	function_body->ret_anchors = (ParsedInstruction **)calloc (map_sz, sizeof (ParsedInstruction *));
	function_body->throw_anchors = (ParsedInstruction **)calloc (map_sz, sizeof (ParsedInstruction *));
	if (!function_body->jump_anchors || !function_body->ret_anchors || !function_body->throw_anchors) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom anchors");
	}
	function_body->jump_anchors_count = map_sz;
	function_body->ret_anchors_count = map_sz;
	function_body->throw_anchors_count = map_sz;

	/* Record try/catch boundaries */
	for (u32 i = 0; i < function_body->exc_handlers_count; i++) {
		ExceptionHandlerInfo *h = &function_body->exc_handlers[i];
		char buf[64];
		snprintf (buf, sizeof (buf), "try_start_%u", i);
		RETURN_IF_ERROR (address_labels_add (&function_body->try_starts, &function_body->try_starts_count, h->start, buf));
		snprintf (buf, sizeof (buf), "try_end_%u", i);
		RETURN_IF_ERROR (address_labels_add (&function_body->try_ends, &function_body->try_ends_count, h->end, buf));
		snprintf (buf, sizeof (buf), "catch_target_%u", i);
		RETURN_IF_ERROR (address_labels_add (&function_body->catch_targets, &function_body->catch_targets_count, h->target, buf));
	}

	/* Scan instructions for anchors and jump targets */
	for (u32 i = 0; i < function_body->instructions.count; i++) {
		ParsedInstruction *ins = &function_body->instructions.instructions[i];
		if (!ins->inst) {
			continue;
		}
		u32 next = ins->next_pos;
		if (next <= func_sz) {
			if (is_jump_instruction (ins->opcode) || ins->opcode == OP_SwitchImm) {
				function_body->jump_anchors[next] = ins;
			} else if (ins->opcode == OP_Ret) {
				function_body->ret_anchors[next] = ins;
			} else if (ins->opcode == OP_Throw) {
				function_body->throw_anchors[next] = ins;
			}
		}

		/* jump targets */
		if (is_jump_instruction (ins->opcode)) {
			for (int j = 0; j < 6; j++) {
				if (!operand_is_addr (ins->inst, j)) {
					continue;
				}
				u32 taddr = compute_target_address (ins, j);
				if (taddr <= func_sz) {
					RETURN_IF_ERROR (add_jump_target (function_body, taddr));
				}
			}
		} else if (ins->opcode == OP_SwitchImm) {
			/* default */
			for (int j = 0; j < 6; j++) {
				if (!operand_is_addr (ins->inst, j)) {
					continue;
				}
				u32 defaddr = compute_target_address (ins, j);
				if (defaddr <= func_sz) {
					RETURN_IF_ERROR (add_jump_target (function_body, defaddr));
				}
				break;
			}
			if (ins->switch_jump_table && ins->switch_jump_table_size) {
				for (u32 k = 0; k < ins->switch_jump_table_size; k++) {
					if (ins->switch_jump_table[k] <= func_sz) {
						RETURN_IF_ERROR (add_jump_target (function_body, ins->switch_jump_table[k]));
					}
				}
			}
		}
	}

	/* Basic-block boundaries */
	U32Set boundaries = { 0 };
	RETURN_IF_ERROR (u32set_init (&boundaries, func_sz + 1));
	RETURN_IF_ERROR (u32set_add (&boundaries, 0));
	RETURN_IF_ERROR (u32set_add (&boundaries, func_sz));
	for (u32 i = 0; i < function_body->try_starts_count; i++) {
		RETURN_IF_ERROR (u32set_add (&boundaries, function_body->try_starts[i].address));
	}
	for (u32 i = 0; i < function_body->try_ends_count; i++) {
		RETURN_IF_ERROR (u32set_add (&boundaries, function_body->try_ends[i].address));
	}
	for (u32 i = 0; i < function_body->catch_targets_count; i++) {
		RETURN_IF_ERROR (u32set_add (&boundaries, function_body->catch_targets[i].address));
	}
	for (u32 i = 0; i < function_body->instructions.count; i++) {
		ParsedInstruction *ins = &function_body->instructions.instructions[i];
		u32 next = ins->next_pos;
		if (next <= func_sz && (function_body->jump_anchors[next] || function_body->ret_anchors[next] || function_body->throw_anchors[next])) {
			RETURN_IF_ERROR (u32set_add (&boundaries, next));
		}
	}
	for (u32 i = 0; i < function_body->jump_targets_count; i++) {
		if (function_body->jump_targets[i] <= func_sz) {
			RETURN_IF_ERROR (u32set_add (&boundaries, function_body->jump_targets[i]));
		}
	}

	qsort (boundaries.data, boundaries.count, sizeof (u32), cmp_u32);
	if (!boundaries.count || boundaries.data[0] != 0) {
		u32set_free (&boundaries);
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "invalid boundaries");
	}

	/* Create basic blocks from boundaries and link fallthrough */
	bool may_have_fallen_through = false;
	BasicBlock *prev = NULL;
	for (u32 i = 1; i < boundaries.count; i++) {
		u32 start = boundaries.data[i - 1];
		u32 end = boundaries.data[i];
		if (start == end) {
			continue;
		}
		RETURN_IF_ERROR (create_basic_block (function_body, start, end));
		BasicBlock *bb = &function_body->basic_blocks[function_body->basic_blocks_count - 1];

		if (may_have_fallen_through && prev) {
			RETURN_IF_ERROR (bbvec_push (&bb->parent_nodes, &bb->parent_nodes_count, &bb->parent_nodes_capacity, prev));
			RETURN_IF_ERROR (bbvec_push (&prev->child_nodes, &prev->child_nodes_count, &prev->child_nodes_capacity, bb));
		}

		may_have_fallen_through = true;
		if (end <= func_sz && function_body->ret_anchors[end]) {
			may_have_fallen_through = false;
			bb->anchor_instruction = function_body->ret_anchors[end];
			bb->is_unconditional_return_end = true;
		} else if (end <= func_sz && function_body->throw_anchors[end]) {
			may_have_fallen_through = false;
			bb->anchor_instruction = function_body->throw_anchors[end];
			bb->is_unconditional_throw_anchor = true;
		} else if (end <= func_sz && function_body->jump_anchors[end]) {
			ParsedInstruction *op = function_body->jump_anchors[end];
			bb->anchor_instruction = op;
			u8 opcd = op->opcode;
			/* Collect targets for this anchor */
			U32Set tset = { 0 };
			RETURN_IF_ERROR (u32set_init (&tset, func_sz + 1));
			for (int j = 0; j < 6; j++) {
				if (operand_is_addr (op->inst, j)) {
					u32 taddr = compute_target_address (op, j);
					if (taddr <= func_sz) {
						u32set_add (&tset, taddr);
					}
				}
			}
			if (op->switch_jump_table && op->switch_jump_table_size) {
				for (u32 k = 0; k < op->switch_jump_table_size; k++) {
					if (op->switch_jump_table[k] <= func_sz) {
						u32set_add (&tset, op->switch_jump_table[k]);
					}
				}
			}
			qsort (tset.data, tset.count, sizeof (u32), cmp_u32);
			if (tset.count) {
				bb->jump_targets_for_anchor = (u32 *)malloc (tset.count * sizeof (u32));
				if (!bb->jump_targets_for_anchor) {
					u32set_free (&tset);
					u32set_free (&boundaries);
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom jump_targets_for_anchor");
				}
				memcpy (bb->jump_targets_for_anchor, tset.data, tset.count * sizeof (u32));
				bb->jump_targets_count = tset.count;
			}
			u32set_free (&tset);

			if (opcd == OP_Jmp || opcd == OP_JmpLong) {
				may_have_fallen_through = false;
				bb->is_unconditional_jump_anchor = true;
			} else if (opcd == OP_SwitchImm) {
				may_have_fallen_through = false;
				bb->is_switch_action_anchor = true;
			} else if (opcd == OP_SaveGenerator || opcd == OP_SaveGeneratorLong) {
				may_have_fallen_through = true;
				bb->is_yield_action_anchor = true;
			} else {
				may_have_fallen_through = true;
				bb->is_conditional_jump_anchor = true;
			}
		}

		prev = bb;
	}

	/* Link explicit jump/switch edges */
	for (u32 i = 0; i < function_body->basic_blocks_count; i++) {
		BasicBlock *bb = &function_body->basic_blocks[i];
		for (u32 j = 0; j < bb->jump_targets_count; j++) {
			u32 tgt = bb->jump_targets_for_anchor[j];
			BasicBlock *child = find_block_by_start (function_body, tgt);
			if (!child) {
				continue;
			}
			if (!bbvec_contains (bb->child_nodes, bb->child_nodes_count, child)) {
				RETURN_IF_ERROR (bbvec_push (&bb->child_nodes, &bb->child_nodes_count, &bb->child_nodes_capacity, child));
			}
			if (!bbvec_contains (child->parent_nodes, child->parent_nodes_count, bb)) {
				RETURN_IF_ERROR (bbvec_push (&child->parent_nodes, &child->parent_nodes_count, &child->parent_nodes_capacity, bb));
			}
		}
		/* Error-handling edges */
		for (u32 h = 0; h < function_body->exc_handlers_count; h++) {
			ExceptionHandlerInfo *eh = &function_body->exc_handlers[h];
			bool overlaps = ((bb->start_address <= eh->start && eh->start < bb->end_address) ||
				(bb->start_address < eh->end && eh->end <= bb->end_address));
			if (!overlaps) {
				continue;
			}
			BasicBlock *handler_bb = find_block_by_start (function_body, eh->target);
			if (!handler_bb) {
				continue;
			}
			if (!bbvec_contains (bb->error_handling_child_nodes, bb->error_handling_child_nodes_count, handler_bb)) {
				RETURN_IF_ERROR (bbvec_push (&bb->error_handling_child_nodes, &bb->error_handling_child_nodes_count, &bb->error_handling_child_nodes_capacity, handler_bb));
			}
			if (!bbvec_contains (handler_bb->error_handling_parent_nodes, handler_bb->error_handling_parent_nodes_count, bb)) {
				RETURN_IF_ERROR (bbvec_push (&handler_bb->error_handling_parent_nodes, &handler_bb->error_handling_parent_nodes_count, &handler_bb->error_handling_parent_nodes_capacity, bb));
			}
		}
	}

	u32set_free (&boundaries);
	return SUCCESS_RESULT ();
}

Result pass2_transform_code(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	if (!state || !function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "pass2_transform_code args");
	}
	/* Translate each parsed instruction into a TokenString line */
	for (u32 i = 0; i < function_body->instructions.count; i++) {
		ParsedInstruction *ins = &function_body->instructions.instructions[i];
		if (!ins->inst) {
			continue;
		}
		TokenString ts;
		Result tr = translate_instruction_to_tokens (ins, &ts);
		if (tr.code != RESULT_SUCCESS) {
			token_string_cleanup (&ts);
			return tr;
		}
		Result pr = statements_push (function_body, &ts);
		if (pr.code != RESULT_SUCCESS) {
			token_string_cleanup (&ts);
			return pr;
		}
	}
	return SUCCESS_RESULT ();
}

Result pass3_parse_forin_loops(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	(void)state;
	if (!function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "pass3_parse_forin_loops args");
	}
	/* Recreate simple for..in structures (non-nested case) */
	for (u32 i = 0; i < function_body->statements_count; i++) {
		TokenString *line = &function_body->statements[i];
		if (!line->head || line->head->type != TOKEN_TYPE_FOR_IN_LOOP_INIT) {
			continue;
		}
		u32 other = 0;
		bool found = false;
		for (u32 j = i; j < function_body->statements_count; j++) {
			if (function_body->statements[j].head && function_body->statements[j].head->type == TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER) {
				other = j;
				found = true;
				break;
			}
		}
		if (!found || other + 1 >= function_body->statements_count || i + 2 >= function_body->statements_count) {
			continue;
		}
		TokenString *j1 = &function_body->statements[i + 1];
		TokenString *j2 = &function_body->statements[other + 1];
		if (!j1->head || !j2->head) {
			continue;
		}
		if (j1->head->type != TOKEN_TYPE_JUMP_NOT_CONDITION || j2->head->type != TOKEN_TYPE_JUMP_NOT_CONDITION) {
			continue; /* nested/weird cases not handled yet */
		}
		ParsedInstruction *begin_ins = function_body->statements[i + 2].assembly;
		if (!begin_ins) {
			continue;
		}
		u32 begin_address = begin_ins->original_pos;
		u32 end_address = ((JumpNotConditionToken *)j2->head)->target_address;
		if (end_address <= begin_address) {
			continue;
		}

		RETURN_IF_ERROR (nested_frames_push (function_body, begin_address, end_address));

		ForInLoopInitToken *fili = (ForInLoopInitToken *)line->head;
		ForInLoopNextIterToken *filni = (ForInLoopNextIterToken *)function_body->statements[other].head;
		if (!filni || function_body->statements[other].head->type != TOKEN_TYPE_FOR_IN_LOOP_NEXT_ITER) {
			continue;
		}

		/* Replace GetPNameList line with a `for (<next> in <obj>)` header */
		RETURN_IF_ERROR (token_string_clear_tokens (line));
		RETURN_IF_ERROR (token_string_add_token (line, create_raw_token ("for")));
		RETURN_IF_ERROR (token_string_add_token (line, create_left_parenthesis_token ()));
		RETURN_IF_ERROR (token_string_add_token (line, create_left_hand_reg_token (filni->next_value_register)));
		RETURN_IF_ERROR (token_string_add_token (line, create_raw_token ("in")));
		RETURN_IF_ERROR (token_string_add_token (line, create_right_hand_reg_token (fili->obj_register)));
		RETURN_IF_ERROR (token_string_add_token (line, create_right_parenthesis_token ()));

		/* Silence the loop plumbing instructions */
		RETURN_IF_ERROR (token_string_clear_tokens (j1));
		RETURN_IF_ERROR (token_string_clear_tokens (&function_body->statements[other]));
		RETURN_IF_ERROR (token_string_clear_tokens (j2));
	}
	return SUCCESS_RESULT ();
}

Result pass4_name_closure_vars(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	(void)state;
	if (!function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "pass4_name_closure_vars args");
	}
	Environment *parent_environment = function_body->parent_environment;

	for (u32 i = 0; i < function_body->statements_count; i++) {
		TokenString *line = &function_body->statements[i];
		for (Token *tok = line->head; tok; tok = tok->next) {
			if (tok->type == TOKEN_TYPE_NEW_ENVIRONMENT) {
				NewEnvironmentToken *t = (NewEnvironmentToken *)tok;
				Environment *env = (Environment *)calloc (1, sizeof (Environment));
				if (!env) {
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom environment");
				}
				env->parent_environment = parent_environment;
				env->nesting_quantity = parent_environment? (parent_environment->nesting_quantity + 1): 0;
				env->slot_index_to_varname = NULL;
				env->var_count = 0;
				env->slot_capacity = 0;
				RETURN_IF_ERROR (owned_env_push (function_body, env));
				RETURN_IF_ERROR (envmap_set (function_body, t->reg_num, env));
				RETURN_IF_ERROR (token_string_clear_tokens (line));
				break;
			} else if (tok->type == TOKEN_TYPE_NEW_INNER_ENVIRONMENT) {
				NewInnerEnvironmentToken *t = (NewInnerEnvironmentToken *)tok;
				Environment *outer = envmap_get (function_body, t->parent_register);
				if (!outer) {
					continue;
				}
				Environment *env = (Environment *)calloc (1, sizeof (Environment));
				if (!env) {
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom environment");
				}
				env->parent_environment = outer;
				env->nesting_quantity = outer->nesting_quantity + 1;
				env->slot_index_to_varname = NULL;
				env->var_count = 0;
				env->slot_capacity = 0;
				RETURN_IF_ERROR (owned_env_push (function_body, env));
				RETURN_IF_ERROR (envmap_set (function_body, t->dest_register, env));
			} else if (tok->type == TOKEN_TYPE_GET_ENVIRONMENT) {
				GetEnvironmentToken *t = (GetEnvironmentToken *)tok;
				Environment *env = parent_environment;
				for (int n = 0; env && n < t->nesting_level; n++) {
					env = env->parent_environment;
				}
				if (env) {
					RETURN_IF_ERROR (envmap_set (function_body, t->reg_num, env));
				}
				RETURN_IF_ERROR (token_string_clear_tokens (line));
				break;
			} else if (tok->type == TOKEN_TYPE_FUNCTION_TABLE_INDEX) {
				FunctionTableIndexToken *t = (FunctionTableIndexToken *)tok;
				t->state = state;
				if (t->environment_id >= 0) {
					Environment *env = envmap_get (function_body, t->environment_id);
					if (env) {
						t->parent_environment = env;
					}
				}
			} else if (tok->type == TOKEN_TYPE_STORE_TO_ENVIRONMENT) {
				StoreToEnvironmentToken *t = (StoreToEnvironmentToken *)tok;
				Environment *env = envmap_get (function_body, t->env_register);
				if (!env) {
					continue;
				}
				char namebuf[64];
				snprintf (namebuf, sizeof (namebuf), "_closure%d_slot%d", env->nesting_quantity, t->slot_index);
				const char *existing = environment_slot_get (env, t->slot_index);
				bool first = (existing == NULL);
				if (first) {
					RETURN_IF_ERROR (environment_slot_set (env, t->slot_index, namebuf));
					existing = environment_slot_get (env, t->slot_index);
				}
				if (!existing) {
					continue;
				}
				RETURN_IF_ERROR (token_string_clear_tokens (line));
				if (first) {
					RETURN_IF_ERROR (token_string_add_token (line, create_raw_token ("var")));
				}
				RETURN_IF_ERROR (token_string_add_token (line, create_raw_token (existing)));
				RETURN_IF_ERROR (token_string_add_token (line, create_assignment_token ()));
				RETURN_IF_ERROR (token_string_add_token (line, create_right_hand_reg_token (t->value_register)));
				break;
			} else if (tok->type == TOKEN_TYPE_LOAD_FROM_ENVIRONMENT) {
				LoadFromEnvironmentToken *t = (LoadFromEnvironmentToken *)tok;
				Environment *env = envmap_get (function_body, t->reg_num);
				if (!env) {
					continue;
				}
				char namebuf[64];
				snprintf (namebuf, sizeof (namebuf), "_closure%d_slot%d", env->nesting_quantity, t->slot_index);
				const char *existing = environment_slot_get (env, t->slot_index);
				if (!existing) {
					RETURN_IF_ERROR (environment_slot_set (env, t->slot_index, namebuf));
					existing = environment_slot_get (env, t->slot_index);
				}
				if (!existing) {
					continue;
				}
				/* Replace this token with the resolved variable name */
				RawToken *rt = (RawToken *)create_raw_token (existing);
				if (!rt) {
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom token");
				}
				Token *next = tok->next;
				Token *prev = NULL;
				for (Token *it = line->head; it && it != tok; it = it->next) {
					prev = it;
				}
				if (prev) {
					prev->next = (Token *)rt;
				} else {
					line->head = (Token *)rt;
				}
				((Token *)rt)->next = next;
				if (line->tail == tok) {
					line->tail = (Token *)rt;
				}
				token_free (tok);
				break;
			}
		}
	}
	return SUCCESS_RESULT ();
}

Result output_code(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	if (!state || !function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "output_code args");
	}
	StringBuffer *out = &state->output;

	/* Function header (skip for global) */
	if (!function_body->is_global) {
		/* Only indent the function keyword if not inlining */
		if (!state->inlining_function) {
			if (function_body->is_async) {
				RETURN_IF_ERROR (append_indent (out, state->indent_level));
				RETURN_IF_ERROR (string_buffer_append (out, "async "));
			} else {
				RETURN_IF_ERROR (append_indent (out, state->indent_level));
			}
		}
		if (function_body->is_async && state->inlining_function) {
			RETURN_IF_ERROR (string_buffer_append (out, "async "));
		}
		RETURN_IF_ERROR (string_buffer_append (out, "function"));
		if (function_body->is_generator) {
			RETURN_IF_ERROR (string_buffer_append (out, "*"));
		}
		if (! (function_body->is_closure || function_body->is_generator)) {
			RETURN_IF_ERROR (string_buffer_append (out, " "));
			RETURN_IF_ERROR (string_buffer_append (out, function_body->function_name? function_body->function_name: "anonymous"));
		}
		RETURN_IF_ERROR (string_buffer_append (out, "("));
		u32 pcnt = function_body->function_object? function_body->function_object->paramCount: 0;
		for (u32 i = 0; i < pcnt; i++) {
			if (i) {
				RETURN_IF_ERROR (string_buffer_append (out, ", "));
			}
			char pbuf[16];
			snprintf (pbuf, sizeof (pbuf), "a%u", i);
			RETURN_IF_ERROR (string_buffer_append (out, pbuf));
		}
		RETURN_IF_ERROR (string_buffer_append (out, ") {"));
		if (!state->options.suppress_comments && (function_body->is_closure || function_body->is_generator)) {
			if (function_body->function_name && *function_body->function_name) {
				RETURN_IF_ERROR (string_buffer_append (out, " // Original name: "));
				RETURN_IF_ERROR (string_buffer_append (out, function_body->function_name));
				if (function_body->environment_id >= 0) {
					RETURN_IF_ERROR (string_buffer_append (out, ", environment: r"));
					RETURN_IF_ERROR (string_buffer_append_int (out, function_body->environment_id));
				}
			} else if (function_body->environment_id >= 0) {
				RETURN_IF_ERROR (string_buffer_append (out, " // Environment: r"));
				RETURN_IF_ERROR (string_buffer_append_int (out, function_body->environment_id));
			}
		}
		RETURN_IF_ERROR (string_buffer_append (out, "\n"));
		state->indent_level++;
	}

	/* Collect frame start/end lists */
	u32 nf = function_body->nested_frames_count;
	u32 *frame_starts = (nf? (u32 *)malloc (nf * sizeof (u32)): NULL);
	u32 *frame_ends = (nf? (u32 *)malloc (nf * sizeof (u32)): NULL);
	if ((nf && (!frame_starts || !frame_ends))) {
		free (frame_starts);
		free (frame_ends);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom nested frame lists");
	}
	for (u32 i = 0; i < nf; i++) {
		frame_starts[i] = function_body->nested_frames[i].start_address;
		frame_ends[i] = function_body->nested_frames[i].end_address;
	}
	qsort (frame_starts, nf, sizeof (u32), cmp_u32);
	qsort (frame_ends, nf, sizeof (u32), cmp_u32);
	u32 frame_starts_count = nf;
	u32 frame_ends_count = nf;

	/* Collect basic block starts/ends */
	u32 bbcount = function_body->basic_blocks_count;
	u32 *bb_starts = (bbcount? (u32 *)malloc (bbcount * sizeof (u32)): NULL);
	u32 *bb_ends = (bbcount? (u32 *)malloc (bbcount * sizeof (u32)): NULL);
	if ((bbcount && (!bb_starts || !bb_ends))) {
		free (frame_starts);
		free (frame_ends);
		free (bb_starts);
		free (bb_ends);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom bb lists");
	}
	for (u32 i = 0; i < bbcount; i++) {
		bb_starts[i] = function_body->basic_blocks[i].start_address;
		bb_ends[i] = function_body->basic_blocks[i].end_address;
	}
	qsort (bb_starts, bbcount, sizeof (u32), cmp_u32);
	qsort (bb_ends, bbcount, sizeof (u32), cmp_u32);

	bool use_dispatch = (bbcount > 1);
	if (use_dispatch) {
		RETURN_IF_ERROR (append_indent (out, state->indent_level));
		RETURN_IF_ERROR (string_buffer_append (out, "_fun"));
		RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
		RETURN_IF_ERROR (string_buffer_append (out, ": for(var _fun"));
		RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
		RETURN_IF_ERROR (string_buffer_append (out, "_ip = 0; ; ) switch(_fun"));
		RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
		RETURN_IF_ERROR (string_buffer_append (out, "_ip) {\n"));
		state->indent_level++;
	}

	u32 cur_bb_index = 0;
	for (u32 si = 0; si < function_body->statements_count; si++) {
		TokenString *st = &function_body->statements[si];
		ParsedInstruction *asm_ref = st->assembly;
		if (asm_ref) {
			u32 pos = asm_ref->original_pos;
			/* Close frames */
			while (frame_ends_count && frame_ends[0] == pos) {
				/* pop front */
				memmove (frame_ends, frame_ends + 1, (frame_ends_count - 1) * sizeof (u32));
				frame_ends_count--;
				state->indent_level--;
				RETURN_IF_ERROR (append_indent (out, state->indent_level));
				RETURN_IF_ERROR (string_buffer_append (out, "}\n"));
			}

			/* Basic block case label */
			if (use_dispatch) {
				bool is_bb_start = (bsearch (&pos, bb_starts, bbcount, sizeof (u32), cmp_u32) != NULL);
				if (is_bb_start) {
					RETURN_IF_ERROR (append_indent (out, state->indent_level));
					RETURN_IF_ERROR (string_buffer_append (out, "case "));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)pos));
					RETURN_IF_ERROR (string_buffer_append (out, ":"));
					if (!state->options.suppress_comments) {
						for (u32 li = 0; li < function_body->try_starts_count; li++) {
							if (function_body->try_starts[li].address == pos) {
								for (u32 k = 0; k < function_body->try_starts[li].label_count; k++) {
									RETURN_IF_ERROR (string_buffer_append (out, " // "));
									RETURN_IF_ERROR (string_buffer_append (out, function_body->try_starts[li].labels[k]));
								}
							}
						}
						for (u32 li = 0; li < function_body->try_ends_count; li++) {
							if (function_body->try_ends[li].address == pos) {
								for (u32 k = 0; k < function_body->try_ends[li].label_count; k++) {
									RETURN_IF_ERROR (string_buffer_append (out, " // "));
									RETURN_IF_ERROR (string_buffer_append (out, function_body->try_ends[li].labels[k]));
								}
							}
						}
						for (u32 li = 0; li < function_body->catch_targets_count; li++) {
							if (function_body->catch_targets[li].address == pos) {
								for (u32 k = 0; k < function_body->catch_targets[li].label_count; k++) {
									RETURN_IF_ERROR (string_buffer_append (out, " // "));
									RETURN_IF_ERROR (string_buffer_append (out, function_body->catch_targets[li].labels[k]));
								}
							}
						}
					}
					RETURN_IF_ERROR (string_buffer_append (out, "\n"));
					/* track current basic block */
					while (cur_bb_index < bbcount && function_body->basic_blocks[cur_bb_index].start_address != pos) {
						cur_bb_index++;
					}
				}
			}

			/* Open frames */
			while (frame_starts_count && frame_starts[0] == pos) {
				memmove (frame_starts, frame_starts + 1, (frame_starts_count - 1) * sizeof (u32));
				frame_starts_count--;
				RETURN_IF_ERROR (append_indent (out, state->indent_level));
				RETURN_IF_ERROR (string_buffer_append (out, "{\n"));
				state->indent_level++;
			}
		}

		if (!st->head) {
			continue;
		}

		/* Calculate absolute address for offset display and comments */
		u64 abs_addr = 0;
		if (asm_ref) {
			abs_addr = state->options.function_base + asm_ref->original_pos;
		}

		/* Show offset if requested (pd:ho mode) */
		if (state->options.show_offsets && asm_ref) {
			char addr_buf[24];
			snprintf (addr_buf, sizeof (addr_buf), "0x%08llx: ", (unsigned long long)abs_addr);
			RETURN_IF_ERROR (string_buffer_append (out, addr_buf));
		} else {
			RETURN_IF_ERROR (append_indent (out, state->indent_level));
		}

		/* Detect `for (` header used as a block statement */
		bool is_block_stmt = false;
		if (st->head && st->head->type == TOKEN_TYPE_RAW) {
			RawToken *rt = (RawToken *)st->head;
			if (rt->text && strcmp (rt->text, "for") == 0 && st->head->next && st->head->next->type == TOKEN_TYPE_LEFT_PARENTHESIS) {
				is_block_stmt = true;
			}
		}

		bool emitted_continue = false;
		Token *head = st->head;
		if (head->type == TOKEN_TYPE_JUMP_NOT_CONDITION || head->type == TOKEN_TYPE_JUMP_CONDITION) {
			/* Serialize the condition part (tokens after the jump token) */
			TokenString cond_ts = { .head = head->next, .tail = st->tail, .assembly = NULL };
			StringBuffer cond;
			RETURN_IF_ERROR (string_buffer_init (&cond, 32));
			RETURN_IF_ERROR (token_string_to_string (&cond_ts, &cond));
			const char *cond_s = cond.data? cond.data: "";
			u32 tgt = (head->type == TOKEN_TYPE_JUMP_NOT_CONDITION)
				? ((JumpNotConditionToken *)head)->target_address
				: ((JumpConditionToken *)head)->target_address;

			if (head->type == TOKEN_TYPE_JUMP_NOT_CONDITION) {
				if (strcmp (cond_s, "false") == 0) {
					RETURN_IF_ERROR (string_buffer_append (out, "_fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					RETURN_IF_ERROR (string_buffer_append (out, "_ip = "));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)tgt));
					RETURN_IF_ERROR (string_buffer_append (out, "; continue _fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					emitted_continue = true;
				} else {
					is_block_stmt = true;
					RETURN_IF_ERROR (string_buffer_append (out, "if(!("));
					RETURN_IF_ERROR (string_buffer_append (out, cond_s));
					RETURN_IF_ERROR (string_buffer_append (out, ")) { _fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					RETURN_IF_ERROR (string_buffer_append (out, "_ip = "));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)tgt));
					RETURN_IF_ERROR (string_buffer_append (out, "; continue _fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					RETURN_IF_ERROR (string_buffer_append (out, " }"));
				}
			} else {
				if (strcmp (cond_s, "true") == 0) {
					RETURN_IF_ERROR (string_buffer_append (out, "_fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					RETURN_IF_ERROR (string_buffer_append (out, "_ip = "));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)tgt));
					RETURN_IF_ERROR (string_buffer_append (out, "; continue _fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					emitted_continue = true;
				} else {
					is_block_stmt = true;
					RETURN_IF_ERROR (string_buffer_append (out, "if("));
					RETURN_IF_ERROR (string_buffer_append (out, cond_s));
					RETURN_IF_ERROR (string_buffer_append (out, ") { _fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					RETURN_IF_ERROR (string_buffer_append (out, "_ip = "));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)tgt));
					RETURN_IF_ERROR (string_buffer_append (out, "; continue _fun"));
					RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
					RETURN_IF_ERROR (string_buffer_append (out, " }"));
				}
			}
			string_buffer_free (&cond);
		} else {
			/* Emit all tokens, handling nested function expressions */
			bool first_tok = true;
			TokenType prev_type = (TokenType) (-1);
			for (Token *t = st->head; t; t = t->next) {
				if (t->type == TOKEN_TYPE_FUNCTION_TABLE_INDEX) {
					FunctionTableIndexToken *fti = (FunctionTableIndexToken *)t;
					if ((fti->is_closure || fti->is_generator) && !fti->is_builtin) {
						if (!first_tok && token_needs_space (prev_type, TOKEN_TYPE_RAW)) {
							RETURN_IF_ERROR (string_buffer_append_char (out, ' '));
						}
						int saved_indent = state->indent_level;
						state->inlining_function = true;
						RETURN_IF_ERROR (decompile_function (state, fti->function_id, fti->parent_environment, fti->environment_id, fti->is_closure, fti->is_generator, fti->is_async));
						state->inlining_function = false;
						state->indent_level = saved_indent;
						first_tok = false;
						prev_type = TOKEN_TYPE_RAW;
						continue;
					}
				}
				if (!first_tok && token_needs_space (prev_type, t->type)) {
					RETURN_IF_ERROR (string_buffer_append_char (out, ' '));
				}
				RETURN_IF_ERROR (token_to_string (t, out));
				first_tok = false;
				prev_type = t->type;
			}
		}

		/* Append r2 comment if available via callback */
		if (state->options.comment_callback && asm_ref) {
			char *comment = state->options.comment_callback (state->options.comment_context, abs_addr);
			if (comment) {
				RETURN_IF_ERROR (string_buffer_append (out, " // "));
				RETURN_IF_ERROR (string_buffer_append (out, comment));
				free (comment);
			}
		}

		if (is_block_stmt) {
			RETURN_IF_ERROR (string_buffer_append (out, "\n"));
		} else {
			RETURN_IF_ERROR (string_buffer_append (out, ";\n"));
		}

		/* Insert fallthrough ip update at end of basic block */
		if (use_dispatch && asm_ref && cur_bb_index < bbcount) {
			BasicBlock *bb = &function_body->basic_blocks[cur_bb_index];
			bool is_last_in_block = (asm_ref->next_pos == bb->end_address);
			if (is_last_in_block && !emitted_continue && !bb->is_unconditional_jump_anchor && !bb->is_unconditional_return_end && !bb->is_unconditional_throw_anchor) {
				RETURN_IF_ERROR (append_indent (out, state->indent_level));
				RETURN_IF_ERROR (string_buffer_append (out, "_fun"));
				RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
				RETURN_IF_ERROR (string_buffer_append (out, "_ip = "));
				RETURN_IF_ERROR (string_buffer_append_int (out, (int)bb->end_address));
				RETURN_IF_ERROR (string_buffer_append (out, "; continue _fun"));
				RETURN_IF_ERROR (string_buffer_append_int (out, (int)function_body->function_id));
				RETURN_IF_ERROR (string_buffer_append (out, ";\n"));
			}
		}
	}

	/* Close switch loop */
	if (use_dispatch) {
		state->indent_level--;
		RETURN_IF_ERROR (append_indent (out, state->indent_level));
		RETURN_IF_ERROR (string_buffer_append (out, "}\n"));
	}
	if (!function_body->is_global) {
		state->indent_level--;
		RETURN_IF_ERROR (append_indent (out, state->indent_level));
		RETURN_IF_ERROR (string_buffer_append (out, "}"));
	}

	free (frame_starts);
	free (frame_ends);
	free (bb_starts);
	free (bb_ends);
	return SUCCESS_RESULT ();
}

Result decompile_function(HermesDecompiler *state, u32 function_id, Environment *parent_environment, int environment_id, bool is_closure, bool is_generator, bool is_async) {
	if (!state || !state->hbc_reader) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "decompile_function args");
	}
	HBCReader *reader = state->hbc_reader;
	if (function_id >= reader->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "decompile_function bad id");
	}

	/* Mark function as decompiled to prevent duplicate processing */
	if (state->decompiled_functions) {
		state->decompiled_functions[function_id] = true;
	}

	/* Load bytecode either from provider or from file buffer */
	if (state->data_provider) {
		RETURN_IF_ERROR (ensure_function_bytecode_loaded_from_provider (state->data_provider, &reader->function_headers[function_id], function_id));
	} else {
		RETURN_IF_ERROR (ensure_function_bytecode_loaded (reader, function_id));
	}

	/* Update function_base for current function (used for offset display) */
	state->options.function_base = reader->function_headers[function_id].offset;
	HBCISA isa = hbc_isa_getv (reader->header.version);

	ParsedInstructionList list;
	RETURN_IF_ERROR (parse_function_bytecode (reader, function_id, &list, isa));

	DecompiledFunctionBody fb;
	RETURN_IF_ERROR (function_body_init (&fb, function_id, &reader->function_headers[function_id], function_id == reader->header.globalCodeIndex));
	fb.parent_environment = parent_environment;
	fb.environment_id = environment_id;
	fb.is_closure = is_closure;
	fb.is_generator = is_generator;
	fb.is_async = is_async;

	/* Transfer parsed instructions into the function body */
	fb.instructions = list;
	memset (&list, 0, sizeof (list));

	/* Execute transformation passes (configurable via decompile options) */
	Result r = SUCCESS_RESULT ();
	if (!state->options.skip_pass1_metadata) {
		r = pass1_set_metadata (state, &fb);
	}
	if (r.code == RESULT_SUCCESS && !state->options.skip_pass2_transform) {
		r = pass2_transform_code (state, &fb);
	}
	if (r.code == RESULT_SUCCESS && !state->options.skip_pass3_forin) {
		r = pass3_parse_forin_loops (state, &fb);
	}
	if (r.code == RESULT_SUCCESS && !state->options.skip_pass4_closure) {
		r = pass4_name_closure_vars (state, &fb);
	}
	if (r.code == RESULT_SUCCESS) {
		r = output_code (state, &fb);
	}

	function_body_cleanup (&fb);
	return r;
}

/* removed old stubs (replaced above with real implementations) */
