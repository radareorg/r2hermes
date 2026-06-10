/* radare2 - BSD - Copyright 2025-2026 - pancake */

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
#include "../hbc_internal.h"

/* Ensure that the function's bytecode buffer is loaded into memory. */
/**
 * Load bytecode for a function using the state.
 */
static Result ensure_function_bytecode_loaded_from_state(HBC *hbc, FunctionHeader *function_header, u32 function_id) {
	if (!hbc || !function_header) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "ensure: state or header NULL");
	}
	if (function_header->bytecode) {
		return SUCCESS_RESULT ();
	}

	/* Get bytecode from state */
	const u8 *bytecode_ptr = NULL;
	u32 bytecode_size = 0;
	Result res = hbc_get_function_bytecode (hbc, function_id, &bytecode_ptr, &bytecode_size);
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
	Result sr = _hbc_buffer_reader_seek (&reader->file_buffer, function_header->offset);
	if (sr.code != RESULT_SUCCESS) {
		free (function_header->bytecode);
		function_header->bytecode = NULL;
		reader->file_buffer.position = saved;
		return sr;
	}
	sr = _hbc_buffer_reader_read_bytes (&reader->file_buffer, function_header->bytecode, function_header->bytecodeSizeInBytes);
	reader->file_buffer.position = saved;
	if (sr.code != RESULT_SUCCESS) {
		free (function_header->bytecode);
		function_header->bytecode = NULL;
		return sr;
	}
	return SUCCESS_RESULT ();
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
	return (s->bitmap[v / 8] & (1 << (v % 8))) != 0;
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
	RETURN_IF_ERROR (grow_array (&s->data, &s->cap, s->count, sizeof (u32), 16));
	s->data[s->count++] = v;
	return SUCCESS_RESULT ();
}

typedef Result(*TargetCallback)(u32 target, void *ctx);

static Result add_target_to_set(u32 target, void *ctx) {
	return u32set_add ((U32Set *)ctx, target);
}

static Result add_target_to_jumplist(u32 target, void *ctx) {
	return _hbc_add_jump_target ((DecompiledFunctionBody *)ctx, target);
}

static Result for_each_branch_target(const ParsedInstruction *insn, u32 func_sz, bool first_only, TargetCallback cb, void *ctx) {
	if (!insn || !insn->inst || !cb) {
		return SUCCESS_RESULT ();
	}
	for (int j = 0; j < 6; j++) {
		if (!_hbc_operand_is_addr (insn->inst, j)) {
			continue;
		}
		u32 tgt = _hbc_compute_target_address (insn, j);
		if (tgt <= func_sz) {
			RETURN_IF_ERROR (cb (tgt, ctx));
		}
		if (first_only) {
			break;
		}
	}
	if (!insn->switch_jump_table || !insn->switch_jump_table_size) {
		return SUCCESS_RESULT ();
	}
	for (u32 k = 0; k < insn->switch_jump_table_size; k++) {
		u32 tgt = insn->switch_jump_table[k];
		if (tgt <= func_sz) {
			RETURN_IF_ERROR (cb (tgt, ctx));
		}
	}
	return SUCCESS_RESULT ();
}

static Result append_indent(StringBuffer *sb, int level) {
	for (int i = 0; i < level; i++) {
		RETURN_IF_ERROR (_hbc_string_buffer_append (sb, "  "));
	}
	return SUCCESS_RESULT ();
}

static Result emit_close_brace(HermesDecompiler *state, StringBuffer *out) {
	state->indent_level--;
	RETURN_IF_ERROR (append_indent (out, state->indent_level));
	return _hbc_string_buffer_append (out, "}\n");
}

/* Labels always start at column 0. empty_stmt adds a ';' so the label can
 * legally precede a closing brace. */
static Result emit_label(StringBuffer *out, u64 addr, bool empty_stmt) {
	char lbl[40];
	snprintf (lbl, sizeof (lbl), empty_stmt? "loc_%08llx:;\n": "loc_%08llx:\n", (unsigned long long)addr);
	return _hbc_string_buffer_append (out, lbl);
}

static Result emit_goto(StringBuffer *out, u64 addr) {
	char buf[48];
	snprintf (buf, sizeof (buf), "goto loc_%08llx;\n", (unsigned long long)addr);
	return _hbc_string_buffer_append (out, buf);
}

static Result token_string_clear_tokens(TokenString *ts) {
	if (!ts) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "token_string_clear_tokens: ts NULL");
	}
	ParsedInstruction *asm_ref = ts->assembly;
	_hbc_token_string_cleanup (ts);
	ts->assembly = asm_ref;
	return SUCCESS_RESULT ();
}

static Result statements_push(DecompiledFunctionBody *fb, const TokenString *ts) {
	if (!fb || !ts) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "statements_push args");
	}
	RETURN_IF_ERROR (grow_array (&fb->statements, &fb->statements_capacity, fb->statements_count, sizeof (TokenString), 64));
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
	RETURN_IF_ERROR (grow_array (&fb->nested_frames, &fb->nested_frames_capacity, fb->nested_frames_count, sizeof (NestedFrame), 8));
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
	RETURN_IF_ERROR (grow_array (&fb->owned_environments, &fb->owned_environments_capacity, fb->owned_environments_count, sizeof (Environment *), 8));
	fb->owned_environments[fb->owned_environments_count++] = env;
	return SUCCESS_RESULT ();
}

/* Allocate an Environment owned by fb, chained under parent */
static Environment *env_new(DecompiledFunctionBody *fb, Environment *parent) {
	Environment *env = (Environment *)calloc (1, sizeof (Environment));
	if (!env) {
		return NULL;
	}
	env->parent_environment = parent;
	env->nesting_quantity = parent? (parent->nesting_quantity + 1): 0;
	if (owned_env_push (fb, env).code != RESULT_SUCCESS) {
		free (env);
		return NULL;
	}
	return env;
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

/* Resolve the variable name of an environment slot, naming it on first use */
static Result env_slot_resolve(Environment *env, int slot_index, const char **name, bool *first) {
	*name = environment_slot_get (env, slot_index);
	if (first) {
		*first = (*name == NULL);
	}
	if (!*name) {
		char namebuf[64];
		snprintf (namebuf, sizeof (namebuf), "_closure%d_slot%d", env->nesting_quantity, slot_index);
		RETURN_IF_ERROR (environment_slot_set (env, slot_index, namebuf));
		*name = environment_slot_get (env, slot_index);
	}
	return SUCCESS_RESULT ();
}

/* Output code helper struct and cleanup */
typedef struct {
	u32 *frame_starts;
	u32 *frame_ends;
	u32 *if_block_stack;
	u32 if_block_stack_count;
	u32 if_block_stack_cap;
} OutputBuffers;

static inline void output_buffers_fini(OutputBuffers *ob) {
	free (ob->frame_starts);
	free (ob->frame_ends);
	free (ob->if_block_stack);
}

static inline Result if_block_stack_push(OutputBuffers *ob, u32 target_addr) {
	RETURN_IF_ERROR (grow_array (&ob->if_block_stack, &ob->if_block_stack_cap, ob->if_block_stack_count, sizeof (u32), 16));
	ob->if_block_stack[ob->if_block_stack_count++] = target_addr;
	return SUCCESS_RESULT ();
}

/* Pop if-blocks whose end address is at or before pos; UINT32_MAX pops all. */
static Result close_if_blocks(HermesDecompiler *state, StringBuffer *out, OutputBuffers *ob, u32 pos) {
	while (ob->if_block_stack_count > 0 && ob->if_block_stack[ob->if_block_stack_count - 1] <= pos) {
		ob->if_block_stack_count--;
		RETURN_IF_ERROR (emit_close_brace (state, out));
	}
	return SUCCESS_RESULT ();
}

/* ============= CFG construction ============= */
static Result bbvec_push(BasicBlock ***arr, u32 *count, u32 *cap, BasicBlock *bb) {
	RETURN_IF_ERROR (grow_array (arr, cap, *count, sizeof (BasicBlock *), 8));
	(*arr)[(*count)++] = bb;
	return SUCCESS_RESULT ();
}

static BasicBlock *find_block_by_start(DecompiledFunctionBody *fb, u32 start) {
	if (!fb) {
		return NULL;
	}
	for (u32 i = 0; i < fb->basic_blocks_count; i++) {
		BasicBlock *bb = fb->basic_blocks[i];
		if (bb && bb->start_address == start) {
			return bb;
		}
	}
	return NULL;
}

typedef struct {
	DecompiledFunctionBody *fb;
	BasicBlock *bb;
} ChildAddCtx;

static Result add_target_as_child(u32 target, void *ctx) {
	ChildAddCtx *c = (ChildAddCtx *)ctx;
	if (!c || !c->fb || !c->bb) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "add_target_as_child ctx");
	}
	BasicBlock *child = find_block_by_start (c->fb, target);
	if (!child) {
		return SUCCESS_RESULT ();
	}
	return bbvec_push (&c->bb->child_nodes, &c->bb->child_nodes_count, &c->bb->child_nodes_capacity, child);
}

Result _hbc_function_body_init(DecompiledFunctionBody *body, u32 function_id, FunctionHeader *function_object, bool is_global) {
	if (!body || !function_object) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "fb_init args");
	}
	memset (body, 0, sizeof (*body));
	body->is_global = is_global;
	body->function_id = function_id;
	body->function_object = function_object;
	return SUCCESS_RESULT ();
}

static void address_labels_free(AddressLabels *arr, u32 count) {
	if (!arr) {
		return;
	}
	for (u32 i = 0; i < count; i++) {
		for (u32 k = 0; k < arr[i].label_count; k++) {
			free (arr[i].labels[k]);
		}
		free (arr[i].labels);
	}
	free (arr);
}

void _hbc_function_body_cleanup(DecompiledFunctionBody *body) {
	if (!body) {
		return;
	}
	free (body->function_name);
	address_labels_free (body->try_starts, body->try_starts_count);
	address_labels_free (body->try_ends, body->try_ends_count);
	address_labels_free (body->catch_targets, body->catch_targets_count);
	free (body->jump_anchors);
	free (body->ret_anchors);
	free (body->throw_anchors);
	free (body->jump_targets);
	if (body->basic_blocks) {
		for (u32 i = 0; i < body->basic_blocks_count; i++) {
			BasicBlock *bb = body->basic_blocks[i];
			if (!bb) {
				continue;
			}
			free (bb->jump_targets_for_anchor);
			free (bb->child_nodes);
			free (bb->parent_nodes);
			free (bb->error_handling_child_nodes);
			free (bb->error_handling_parent_nodes);
			free (bb);
		}
		free (body->basic_blocks);
	}
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
			_hbc_token_string_cleanup (&body->statements[i]);
		}
		free (body->statements);
	}
	_hbc_parsed_instruction_list_free (&body->instructions);
	memset (body, 0, sizeof (*body));
}

Result _hbc_add_jump_target(DecompiledFunctionBody *body, u32 address) {
	if (!body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_add_jump_target: body");
	}
	for (u32 i = 0; i < body->jump_targets_count; i++) {
		if (body->jump_targets[i] == address) {
			return SUCCESS_RESULT ();
		}
	}
	RETURN_IF_ERROR (grow_array (&body->jump_targets, &body->jump_targets_capacity, body->jump_targets_count, sizeof (u32), 16));
	body->jump_targets[body->jump_targets_count++] = address;
	return SUCCESS_RESULT ();
}

Result _hbc_create_basic_block(DecompiledFunctionBody *body, u32 start_address, u32 end_address) {
	if (!body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "create_bb body");
	}
	RETURN_IF_ERROR (grow_array (&body->basic_blocks, &body->basic_blocks_capacity, body->basic_blocks_count, sizeof (BasicBlock *), 16));
	BasicBlock *bb = (BasicBlock *)calloc (1, sizeof (*bb));
	if (!bb) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom create_bb");
	}
	bb->start_address = start_address;
	bb->end_address = end_address;
	bb->stay_visible = true;
	body->basic_blocks[body->basic_blocks_count++] = bb;
	return SUCCESS_RESULT ();
}

/* Build a control-flow graph using simple leader splitting and edge wiring */
Result _hbc_build_control_flow_graph(HBCReader *reader, u32 function_id, ParsedInstructionList *list, DecompiledFunctionBody *out_body) {
	if (!reader || !list || !out_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "build_cfg args");
	}
	FunctionHeader *fh = &reader->function_headers[function_id];
	RETURN_IF_ERROR (_hbc_function_body_init (out_body, function_id, fh, function_id == reader->header.globalCodeIndex));
	/* Leaders: entry, jump targets, fallthrough after terminators */
	U32Set leaders = { 0 };
	u32 func_sz = fh->bytecodeSizeInBytes;
	u32 target_limit = func_sz? (func_sz - 1): 0;
	RETURN_IF_ERROR (u32set_init (&leaders, func_sz));
	u32set_add (&leaders, 0);
	for (u32 i = 0; i < list->count; i++) {
		ParsedInstruction *ins = &list->instructions[i];
		RETURN_IF_ERROR (for_each_branch_target (ins, target_limit, false, add_target_to_set, &leaders));
		bool term = _hbc_is_jump_instruction (ins->opcode) || ins->opcode == OP_Ret || ins->opcode == OP_Throw;
		if (term && ins->next_pos < func_sz) {
			RETURN_IF_ERROR (u32set_add (&leaders, ins->next_pos));
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
		RETURN_IF_ERROR (_hbc_create_basic_block (out_body, start, end));
	}
	/* Anchor and wire edges */
	for (u32 i = 0; i < out_body->basic_blocks_count; i++) {
		BasicBlock *bb = out_body->basic_blocks[i];
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
			ChildAddCtx cctx = { .fb = out_body, .bb = bb };
			RETURN_IF_ERROR (for_each_branch_target (last, target_limit, false, add_target_as_child, &cctx));
			/* switch is unconditional in the sense that one target must be taken */
			bb->is_unconditional_jump_anchor = true;
		}
		if (_hbc_is_jump_instruction (op)) {
			ChildAddCtx cctx = { .fb = out_body, .bb = bb };
			RETURN_IF_ERROR (for_each_branch_target (last, target_limit, false, add_target_as_child, &cctx));
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

Result _hbc_decompiler_init(HermesDecompiler *decompiler) {
	if (!decompiler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler pointer");
	}

	decompiler->calldirect_function_ids = NULL;
	decompiler->calldirect_function_ids_count = 0;
	decompiler->calldirect_function_ids_capacity = 0;
	decompiler->decompiled_functions = NULL;
	decompiler->function_in_progress = NULL;
	decompiler->indent_level = 0;
	decompiler->inlining_function = false;
	decompiler->output_truncated = false;
	decompiler->truncation_marker_emitted = false;
	decompiler->hbc = NULL; /* Will be set if using state-based API */
	decompiler->options.pretty_literals = true;
	decompiler->options.suppress_comments = false;

	// Initialize string buffer for output
	_hbc_string_buffer_init (&decompiler->output, 4096); // Start with 4KB buffer

	return SUCCESS_RESULT ();
}

Result _hbc_decompiler_init_with_state(HermesDecompiler *decompiler, HBC *hbc) {
	if (!decompiler || !hbc) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler or state pointer");
	}

	/* Initialize common fields */
	Result res = _hbc_decompiler_init (decompiler);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	/* Store state reference */
	decompiler->hbc = hbc;

	return SUCCESS_RESULT ();
}

Result _hbc_decompiler_cleanup(HermesDecompiler *decompiler) {
	if (!decompiler) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Null decompiler pointer");
	}

	free (decompiler->calldirect_function_ids);
	decompiler->calldirect_function_ids = NULL;
	free (decompiler->decompiled_functions);
	decompiler->decompiled_functions = NULL;
	free (decompiler->function_in_progress);
	decompiler->function_in_progress = NULL;
	/* The hbc state may be owned by the caller; never freed here */
	decompiler->hbc = NULL;
	_hbc_string_buffer_free (&decompiler->output);
	return SUCCESS_RESULT ();
}

Result _hbc_decompile_file(const char *input_file, const char *output_file) {
	Result result;
	HermesDecompiler decompiler;
	HBCReader reader;

	// Initialize structs
	result = _hbc_decompiler_init (&decompiler);
	if (result.code != RESULT_SUCCESS) {
		return result;
	}

	result = _hbc_reader_init (&reader);
	if (result.code != RESULT_SUCCESS) {
		_hbc_decompiler_cleanup (&decompiler);
		return result;
	}

	// Store file paths
	decompiler.input_file = (char *)input_file;
	decompiler.output_file = (char *)output_file;
	decompiler.hbc_reader = &reader;

	result = _hbc_reader_read_whole_file (&reader, input_file);
	if (result.code != RESULT_SUCCESS) {
		_hbc_reader_cleanup (&reader);
		_hbc_decompiler_cleanup (&decompiler);
		return result;
	}

	// Produce decompilation into a temporary buffer, then write to file/stdout
	StringBuffer sb;
	_hbc_string_buffer_init (&sb, 64 * 1024);
	HBCDecompOptions options = { .pretty_literals = LITERALS_PRETTY_AUTO, .suppress_comments = false };
	result = _hbc_decompile_all_to_buffer (&reader, options, &sb);
	if (result.code != RESULT_SUCCESS) {
		_hbc_string_buffer_free (&sb);
		_hbc_reader_cleanup (&reader);
		_hbc_decompiler_cleanup (&decompiler);
		return result;
	}

	FILE *out = stdout;
	if (output_file) {
		out = fopen (output_file, "w");
		if (!out) {
			_hbc_string_buffer_free (&sb);
			_hbc_reader_cleanup (&reader);
			_hbc_decompiler_cleanup (&decompiler);
			return ERROR_RESULT (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file for writing");
		}
	}
	fputs (sb.data? sb.data: "", out);
	if (output_file && out != stdout) {
		fclose (out);
	}
	_hbc_string_buffer_free (&sb);

	// Cleanup
	_hbc_reader_cleanup (&reader);
	_hbc_decompiler_cleanup (&decompiler);

	return SUCCESS_RESULT ();
}

/* Shared tail for the public decompile entry points: run one function
 *(single) or all of them, flush dec->output into out and cleanup dec. */
static Result decompile_emit(HermesDecompiler *dec, u32 func_count, u32 version, bool single, u32 fid, StringBuffer *out) {
	Result r = SUCCESS_RESULT ();
	if (single) {
		if (fid >= func_count) {
			r = ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Function ID out of range");
		} else {
			r = _hbc_decompile_function (dec, fid, NULL, -1, false, false, false);
		}
		if (r.code == RESULT_SUCCESS) {
			r = _hbc_string_buffer_append (&dec->output, "\n\n");
		}
	} else {
		/* Tracking array to skip functions already decompiled as nested ones */
		dec->decompiled_functions = (bool *)calloc (func_count? func_count: 1, sizeof (bool));
		if (!dec->decompiled_functions) {
			r = ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate decompiled_functions tracker");
		}
		if (r.code == RESULT_SUCCESS && !dec->options.suppress_comments) {
			char vbuf[64];
			snprintf (vbuf, sizeof (vbuf), "// Decompiled Hermes bytecode\n// Version: %u\n\n", version);
			r = _hbc_string_buffer_append (&dec->output, vbuf);
		}
		for (u32 i = 0; r.code == RESULT_SUCCESS && i < func_count && !dec->output_truncated; i++) {
			if (dec->decompiled_functions[i]) {
				continue;
			}
			r = _hbc_decompile_function (dec, i, NULL, -1, false, false, false);
			if (r.code == RESULT_SUCCESS) {
				r = _hbc_string_buffer_append (&dec->output, "\n\n");
			}
		}
	}
	if (r.code == RESULT_SUCCESS) {
		r = _hbc_string_buffer_append (out, dec->output.data? dec->output.data: "");
	}
	_hbc_decompiler_cleanup (dec);
	return r;
}

Result _hbc_decompile_function_to_buffer(HBCReader *reader, u32 function_id, HBCDecompOptions options, StringBuffer *out) {
	if (!reader || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_decompile_function_to_buffer args");
	}
	HermesDecompiler dec;
	RETURN_IF_ERROR (_hbc_decompiler_init (&dec));
	dec.hbc_reader = reader;
	dec.options = options;
	return decompile_emit (&dec, reader->header.functionCount, reader->header.version, true, function_id, out);
}

Result _hbc_decompile_all_to_buffer(HBCReader *reader, HBCDecompOptions options, StringBuffer *out) {
	if (!reader || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for _hbc_decompile_all_to_buffer");
	}
	HermesDecompiler dec;
	RETURN_IF_ERROR (_hbc_decompiler_init (&dec));
	dec.hbc_reader = reader;
	dec.options = options;
	return decompile_emit (&dec, reader->header.functionCount, reader->header.version, false, 0, out);
}

Result _hbc_decompile_function_with_state(HBC *hbc, u32 function_id, HBCDecompOptions options, StringBuffer *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_decompile_function_with_state args");
	}
	HermesDecompiler dec;
	RETURN_IF_ERROR (_hbc_decompiler_init_with_state (&dec, hbc));
	dec.hbc_reader = &hbc->reader;
	dec.options = options;
	HBCHeader header;
	Result hres = hbc_get_header (hbc, &header);
	if (hres.code != RESULT_SUCCESS) {
		_hbc_decompiler_cleanup (&dec);
		return hres;
	}
	return decompile_emit (&dec, header.functionCount, header.version, true, function_id, out);
}

Result _hbc_decompile_all_with_state(HBC *hbc, HBCDecompOptions options, StringBuffer *out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for _hbc_decompile_all_with_state");
	}
	HermesDecompiler dec;
	RETURN_IF_ERROR (_hbc_decompiler_init_with_state (&dec, hbc));
	dec.hbc_reader = &hbc->reader;
	dec.options = options;
	HBCHeader header;
	Result res = hbc_get_header (hbc, &header);
	if (res.code != RESULT_SUCCESS) {
		_hbc_decompiler_cleanup (&dec);
		return res;
	}
	return decompile_emit (&dec, header.functionCount, header.version, false, 0, out);
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

static Result bbvec_push_unique(BasicBlock ***arr, u32 *count, u32 *cap, BasicBlock *bb) {
	if (bbvec_contains (*arr, *count, bb)) {
		return SUCCESS_RESULT ();
	}
	return bbvec_push (arr, count, cap, bb);
}

static bool token_needs_space(TokenType prev, TokenType cur) {
	if (cur == TOKEN_TYPE_LEFT_PARENTHESIS) {
		/* No space in calls like r1 (args) */
		return prev != TOKEN_TYPE_RIGHT_HAND_REG && prev != TOKEN_TYPE_LEFT_HAND_REG;
	}
	/* No space before other punctuation nor after '(' or '.' */
	if (cur == TOKEN_TYPE_RIGHT_PARENTHESIS || cur == TOKEN_TYPE_DOT_ACCESSOR) {
		return false;
	}
	return prev != TOKEN_TYPE_LEFT_PARENTHESIS && prev != TOKEN_TYPE_DOT_ACCESSOR;
}

Result _hbc_pass1_set_metadata(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	if (!state || !state->hbc_reader || !function_body || !function_body->function_object) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_pass1_set_metadata args");
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
			if (_hbc_is_jump_instruction (ins->opcode) || ins->opcode == OP_SwitchImm) {
				function_body->jump_anchors[next] = ins;
			} else if (ins->opcode == OP_Ret) {
				function_body->ret_anchors[next] = ins;
			} else if (ins->opcode == OP_Throw) {
				function_body->throw_anchors[next] = ins;
			}
		}

		if (_hbc_is_jump_instruction (ins->opcode)) {
			RETURN_IF_ERROR (for_each_branch_target (ins, func_sz, false, add_target_to_jumplist, function_body));
		} else if (ins->opcode == OP_SwitchImm) {
			RETURN_IF_ERROR (for_each_branch_target (ins, func_sz, true, add_target_to_jumplist, function_body));
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
		RETURN_IF_ERROR (_hbc_create_basic_block (function_body, start, end));
		BasicBlock *bb = function_body->basic_blocks[function_body->basic_blocks_count - 1];

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
			Result tres = for_each_branch_target (op, func_sz, false, add_target_to_set, &tset);
			if (tres.code != RESULT_SUCCESS) {
				u32set_free (&tset);
				u32set_free (&boundaries);
				return tres;
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
		BasicBlock *bb = function_body->basic_blocks[i];
		for (u32 j = 0; j < bb->jump_targets_count; j++) {
			u32 tgt = bb->jump_targets_for_anchor[j];
			BasicBlock *child = find_block_by_start (function_body, tgt);
			if (!child) {
				continue;
			}
			RETURN_IF_ERROR (bbvec_push_unique (&bb->child_nodes, &bb->child_nodes_count, &bb->child_nodes_capacity, child));
			RETURN_IF_ERROR (bbvec_push_unique (&child->parent_nodes, &child->parent_nodes_count, &child->parent_nodes_capacity, bb));
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
			RETURN_IF_ERROR (bbvec_push_unique (&bb->error_handling_child_nodes, &bb->error_handling_child_nodes_count, &bb->error_handling_child_nodes_capacity, handler_bb));
			RETURN_IF_ERROR (bbvec_push_unique (&handler_bb->error_handling_parent_nodes, &handler_bb->error_handling_parent_nodes_count, &handler_bb->error_handling_parent_nodes_capacity, bb));
		}
	}

	u32set_free (&boundaries);
	return SUCCESS_RESULT ();
}

Result _hbc_pass2_transform_code(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	if (!state || !function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_pass2_transform_code args");
	}
	int ast_budget = state->options.max_ast_statements;
	for (u32 i = 0; i < function_body->instructions.count; i++) {
		/* AST-size cap: bail mid-build so pass3/4 and output stay cheap. */
		if (ast_budget > 0 && function_body->statements_count >= (u32)ast_budget) {
			state->output_truncated = true;
			break;
		}
		ParsedInstruction *ins = &function_body->instructions.instructions[i];
		if (!ins->inst) {
			continue;
		}
		TokenString ts;
		Result tr = _hbc_translate_instruction_to_tokens (ins, &ts);
		if (tr.code != RESULT_SUCCESS) {
			_hbc_token_string_cleanup (&ts);
			return tr;
		}
		Result pr = statements_push (function_body, &ts);
		if (pr.code != RESULT_SUCCESS) {
			_hbc_token_string_cleanup (&ts);
			return pr;
		}
	}
	return SUCCESS_RESULT ();
}

Result _hbc_pass3_parse_forin_loops(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	(void)state;
	if (!function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_pass3_parse_forin_loops args");
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
		int next_value_register = filni->next_value_register;
		int obj_register = fili->obj_register;

		/* Replace GetPNameList line with a `for (<next> in <obj>)` header */
		RETURN_IF_ERROR (token_string_clear_tokens (line));
		RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_raw_token ("for")));
		RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_left_parenthesis_token ()));
		RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_left_hand_reg_token (next_value_register)));
		RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_raw_token ("in")));
		RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_right_hand_reg_token (obj_register)));
		RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_right_parenthesis_token ()));

		/* Silence the loop plumbing instructions */
		RETURN_IF_ERROR (token_string_clear_tokens (j1));
		RETURN_IF_ERROR (token_string_clear_tokens (&function_body->statements[other]));
		RETURN_IF_ERROR (token_string_clear_tokens (j2));
	}
	return SUCCESS_RESULT ();
}

Result _hbc_pass4_name_closure_vars(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	(void)state;
	if (!function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_pass4_name_closure_vars args");
	}
	Environment *parent_environment = function_body->parent_environment;

	for (u32 i = 0; i < function_body->statements_count; i++) {
		TokenString *line = &function_body->statements[i];
		for (Token *tok = line->head; tok; tok = tok->next) {
			if (tok->type == TOKEN_TYPE_NEW_ENVIRONMENT) {
				NewEnvironmentToken *t = (NewEnvironmentToken *)tok;
				Environment *env = env_new (function_body, parent_environment);
				if (!env) {
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom environment");
				}
				RETURN_IF_ERROR (envmap_set (function_body, t->reg_num, env));
				RETURN_IF_ERROR (token_string_clear_tokens (line));
				break;
			} else if (tok->type == TOKEN_TYPE_NEW_INNER_ENVIRONMENT) {
				NewInnerEnvironmentToken *t = (NewInnerEnvironmentToken *)tok;
				Environment *outer = envmap_get (function_body, t->parent_register);
				if (!outer) {
					continue;
				}
				Environment *env = env_new (function_body, outer);
				if (!env) {
					return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom environment");
				}
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
				int value_register = t->value_register;
				Environment *env = envmap_get (function_body, t->env_register);
				if (!env) {
					continue;
				}
				const char *existing;
				bool first;
				RETURN_IF_ERROR (env_slot_resolve (env, t->slot_index, &existing, &first));
				if (!existing) {
					continue;
				}
				RETURN_IF_ERROR (token_string_clear_tokens (line));
				if (first) {
					RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_raw_token ("var")));
				}
				RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_raw_token (existing)));
				RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_assignment_token ()));
				RETURN_IF_ERROR (_hbc_token_string_add_token (line, create_right_hand_reg_token (value_register)));
				break;
			} else if (tok->type == TOKEN_TYPE_LOAD_FROM_ENVIRONMENT) {
				LoadFromEnvironmentToken *t = (LoadFromEnvironmentToken *)tok;
				Environment *env = envmap_get (function_body, t->reg_num);
				if (!env) {
					continue;
				}
				const char *existing;
				RETURN_IF_ERROR (env_slot_resolve (env, t->slot_index, &existing, NULL));
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
				_hbc_token_free (tok);
				break;
			}
		}
	}
	return SUCCESS_RESULT ();
}

/* Dead Code Elimination (DCE): Identify statements with assignments to registers
 * that are never read. Returns a boolean array where dce[i] = true means statement i
 * can be eliminated.
 */
static Result identify_dead_assignments(DecompiledFunctionBody *function_body, bool **dce_out) {
	if (!function_body || function_body->statements_count == 0) {
		*dce_out = NULL;
		return SUCCESS_RESULT ();
	}

	bool *dce = (bool *)calloc (function_body->statements_count, sizeof (bool));
	if (!dce) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom dce");
	}

	/* Track which registers are read/written */
	bool *register_read_after = (bool *)calloc (256, sizeof (bool));
	if (!register_read_after) {
		free (dce);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom register_read");
	}

	/* Scan statements in reverse to find register usage */
	for (int si = (int)function_body->statements_count - 1; si >= 0; si--) {
		TokenString *st = &function_body->statements[si];
		if (!st->head) {
			continue;
		}

		/* Detect if this is a pure assignment: starts with left-hand register token */
		bool is_assignment = (st->head->type == TOKEN_TYPE_LEFT_HAND_REG);
		int written_reg_num = -1;

		bool has_call = false;
		bool has_jump = false;
		for (Token *tok = st->head; tok; tok = tok->next) {
			if (tok->type == TOKEN_TYPE_LEFT_PARENTHESIS) {
				has_call = true;
			}
			if (tok->type == TOKEN_TYPE_JUMP_CONDITION || tok->type == TOKEN_TYPE_JUMP_NOT_CONDITION) {
				has_jump = true;
			}
		}

		if (has_jump) {
			for (int r = 0; r < 256; r++) {
				register_read_after[r] = true;
			}
		}

		if (is_assignment) {
			LeftHandRegToken *lhr = (LeftHandRegToken *)st->head;
			written_reg_num = lhr->reg_num;

			/* Mark as dead if it writes a register never read after this point */
			/* BUT never eliminate function calls - they may have side effects */
			if (written_reg_num >= 0 && written_reg_num < 256) {
				if (!register_read_after[written_reg_num] && !has_call) {
					dce[si] = true;
				}
				/* Now mark this register as written (no longer readable after) */
				register_read_after[written_reg_num] = false;
			}
		}

		/* Mark all registers read in this statement */
		for (Token *tok = st->head; tok; tok = tok->next) {
			if (tok->type == TOKEN_TYPE_RIGHT_HAND_REG) {
				RightHandRegToken *rhr = (RightHandRegToken *)tok;
				if (rhr->reg_num >= 0 && rhr->reg_num < 256) {
					register_read_after[rhr->reg_num] = true;
				}
			}
		}
	}

	free (register_read_after);
	*dce_out = dce;
	return SUCCESS_RESULT ();
}

/* True when a conditional-jump statement is unconditional (its condition is the
 * literal `true`/`false`, i.e. a plain goto). */
static bool jump_is_unconditional(const Token *head) {
	if (!head->next || head->next->type != TOKEN_TYPE_RAW || head->next->next) {
		return false;
	}
	const RawToken *rt = (const RawToken *)head->next;
	return rt->text && (!strcmp (rt->text, "true") || !strcmp (rt->text, "false"));
}

static u32 jump_target_of(const Token *head) {
	if (head->type == TOKEN_TYPE_JUMP_CONDITION) {
		return ((const JumpConditionToken *)head)->target_address;
	}
	return ((const JumpNotConditionToken *)head)->target_address;
}

typedef struct {
	u32 try_start;
	u32 try_end;
	u32 catch_start;
	u32 catch_end;
	int catch_reg;
	bool catch_open;
} StructuredCatch;

static Result build_structured_catches(DecompiledFunctionBody *fb, const bool *dce, u32 func_sz, StructuredCatch **out, u32 *out_count) {
	*out = NULL;
	*out_count = 0;
	if (!fb->exc_handlers_count) {
		return SUCCESS_RESULT ();
	}
	StructuredCatch *plans = (StructuredCatch *)calloc (fb->exc_handlers_count, sizeof (StructuredCatch));
	if (!plans) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom structured catches");
	}
	for (u32 i = 0; i < fb->exc_handlers_count; i++) {
		ExceptionHandlerInfo *h = &fb->exc_handlers[i];
		u32 catch_end = UINT32_MAX;
		int catch_reg = -1;
		bool has_try_start = false;
		for (u32 si = 0; si < fb->statements_count; si++) {
			if (dce && dce[si]) {
				continue;
			}
			TokenString *st = &fb->statements[si];
			if (!st->head || !st->assembly) {
				continue;
			}
			u32 pos = st->assembly->original_pos;
			if (pos == h->start) {
				has_try_start = true;
			} else if (pos == h->target && st->head->type == TOKEN_TYPE_CATCH_BLOCK_START) {
				catch_reg = ((CatchBlockStartToken *)st->head)->arg_register;
			} else if (pos == h->end &&
				(st->head->type == TOKEN_TYPE_JUMP_CONDITION || st->head->type == TOKEN_TYPE_JUMP_NOT_CONDITION) &&
				jump_is_unconditional (st->head)) {
				catch_end = jump_target_of (st->head);
			}
		}
		if (!has_try_start || catch_reg < 0 || catch_end <= h->target || catch_end > func_sz) {
			continue;
		}
		plans[*out_count] = (StructuredCatch){ h->start, h->end, h->target, catch_end, catch_reg, false };
		(*out_count)++;
	}
	if (!*out_count) {
		free (plans);
		return SUCCESS_RESULT ();
	}
	*out = plans;
	return SUCCESS_RESULT ();
}

static StructuredCatch *structured_catch_at(StructuredCatch *plans, u32 count, u32 pos, char kind) {
	for (u32 i = 0; i < count; i++) {
		if ((kind == 's' && plans[i].try_start == pos) ||
			(kind == 'e' && plans[i].try_end == pos) ||
			(kind == 'c' && plans[i].catch_start == pos) ||
			(kind == 'm' && plans[i].catch_open && plans[i].catch_end == pos)) {
			return &plans[i];
		}
	}
	return NULL;
}

static bool raw_token_is(const Token *tok, const char *text) {
	if (!tok || tok->type != TOKEN_TYPE_RAW) {
		return false;
	}
	const RawToken *rt = (const RawToken *)tok;
	return rt->text && !strcmp (rt->text, text);
}

static Result append_condition_tokens(StringBuffer *out, Token *cond, bool invert) {
	if (invert && raw_token_is (cond, "!") && cond->next) {
		cond = cond->next;
		invert = false;
	}
	if (invert) {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, "!("));
	}
	for (Token *t = cond; t; t = t->next) {
		RETURN_IF_ERROR (_hbc_token_to_string (t, out));
	}
	if (invert) {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, ")"));
	}
	return SUCCESS_RESULT ();
}

/* Emit one token, preceded by a space when the token pair requires it */
static Result append_token_spaced(StringBuffer *out, Token *t, bool first, TokenType prev) {
	bool needs_space = !first && token_needs_space (prev, t->type);
	if (needs_space && t->type == TOKEN_TYPE_RAW) {
		const RawToken *rt = (const RawToken *)t;
		if (rt->text && (rt->text[0] == ',' || rt->text[0] == ';' || rt->text[0] == ')')) {
			needs_space = false;
		}
	}
	if (needs_space) {
		RETURN_IF_ERROR (_hbc_string_buffer_append_char (out, ' '));
	}
	return _hbc_token_to_string (t, out);
}

static Result append_plain_tokens(StringBuffer *out, Token *tok) {
	TokenType prev_type = (TokenType) (-1);
	for (Token *t = tok; t; t = t->next) {
		RETURN_IF_ERROR (append_token_spaced (out, t, t == tok, prev_type));
		prev_type = t->type;
	}
	return SUCCESS_RESULT ();
}

/* Decide whether a closure reference gets inlined as a function expression.
 * inline_threshold: negative = never inline, 0 = no limit, >0 = max bytes */
static bool should_inline_closure(const HermesDecompiler *state, const FunctionTableIndexToken *fti) {
	if (!state->options.inline_closures || state->options.inline_threshold < 0) {
		return false;
	}
	if (!state->hbc_reader || fti->function_id >= state->hbc_reader->header.functionCount) {
		return false;
	}
	int threshold = state->options.inline_threshold;
	if (threshold > 0 && state->hbc_reader->function_headers[fti->function_id].bytecodeSizeInBytes > (u32)threshold) {
		return false;
	}
	return ! (state->function_in_progress && state->function_in_progress[fti->function_id]);
}

static Result labels_add_target(U32Set *labels, u32 target, u32 func_sz, u32 *end_label_addr) {
	if (target >= func_sz) {
		*end_label_addr = func_sz;
		return SUCCESS_RESULT ();
	}
	return u32set_add (labels, target);
}

static Result collect_labels(DecompiledFunctionBody *fb, const bool *dce, u32 func_sz, U32Set *labels, u32 *end_label_addr, bool *has_catch) {
	*end_label_addr = UINT32_MAX;
	*has_catch = false;
	for (u32 si = 0; si < fb->statements_count; si++) {
		if (dce && dce[si]) {
			continue;
		}
		TokenString *st = &fb->statements[si];
		ParsedInstruction *asm_ref = st->assembly;
		if (!st->head) {
			continue;
		}
		if (asm_ref && st->head->type == TOKEN_TYPE_CATCH_BLOCK_START) {
			*has_catch = true;
			RETURN_IF_ERROR (labels_add_target (labels, asm_ref->original_pos, func_sz, end_label_addr));
		}
		if (asm_ref && asm_ref->opcode == OP_SwitchImm) {
			for (u32 k = 0; k < asm_ref->switch_jump_table_size; k++) {
				RETURN_IF_ERROR (labels_add_target (labels, asm_ref->switch_jump_table[k], func_sz, end_label_addr));
			}
			for (int j = 0; asm_ref->inst && j < 6; j++) {
				if (_hbc_operand_is_addr (asm_ref->inst, j)) {
					RETURN_IF_ERROR (labels_add_target (labels, _hbc_compute_target_address (asm_ref, j), func_sz, end_label_addr));
				}
			}
		}
		if (asm_ref && (asm_ref->opcode == OP_SaveGenerator || asm_ref->opcode == OP_SaveGeneratorLong)) {
			RETURN_IF_ERROR (labels_add_target (labels, _hbc_compute_target_address (asm_ref, 0), func_sz, end_label_addr));
		}
		Token *head = st->head;
		if (head->type == TOKEN_TYPE_JUMP_CONDITION || head->type == TOKEN_TYPE_JUMP_NOT_CONDITION) {
			RETURN_IF_ERROR (labels_add_target (labels, jump_target_of (head), func_sz, end_label_addr));
		}
	}
	return SUCCESS_RESULT ();
}

Result _hbc_output_code(HermesDecompiler *state, DecompiledFunctionBody *function_body) {
	if (!state || !function_body) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_output_code args");
	}
	StringBuffer *out = &state->output;

	/* Function header line prefix: offset in pd:ho mode, indentation otherwise */
	if (state->options.show_offsets) {
		char addr_buf[24];
		snprintf (addr_buf, sizeof (addr_buf), "0x%08llx: ", (unsigned long long)state->options.function_base);
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, addr_buf));
	} else if (!state->inlining_function && !function_body->is_global) {
		RETURN_IF_ERROR (append_indent (out, state->indent_level));
	}
	if (function_body->is_async) {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, "async "));
	}
	if (function_body->is_global) {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, "function global() {"));
	} else {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, function_body->is_generator? "function* ": "function "));
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, function_body->function_name? function_body->function_name: "anonymous"));
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, "("));
		u32 pcnt = function_body->function_object? function_body->function_object->paramCount: 0;
		for (u32 i = 0; i < pcnt; i++) {
			char pbuf[16];
			snprintf (pbuf, sizeof (pbuf), i? ", a%u": "a%u", i);
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, pbuf));
		}
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, ") {"));
	}
	/* First priority: r2 comment at function start, then name/env fallback */
	char *r2_comment = state->options.comment_callback? state->options.comment_callback (state->options.comment_context, state->options.function_base): NULL;
	if (r2_comment) {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, " // "));
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, r2_comment));
		free (r2_comment);
	} else if (!function_body->is_global && !state->options.suppress_comments &&
		(function_body->is_closure || function_body->is_generator)) {
		if (function_body->function_name && *function_body->function_name) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, " // Original name: "));
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, function_body->function_name));
			if (function_body->environment_id >= 0) {
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, ", environment: r"));
				RETURN_IF_ERROR (_hbc_string_buffer_append_int (out, function_body->environment_id));
			}
		} else if (function_body->environment_id >= 0) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, " // Environment: r"));
			RETURN_IF_ERROR (_hbc_string_buffer_append_int (out, function_body->environment_id));
		}
	}
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, "\n"));
	state->indent_level++;

	/* Collect sorted nested-frame start/end address lists */
	OutputBuffers ob = { 0 };
	u32 nf = function_body->nested_frames_count;
	ob.frame_starts = (nf? (u32 *)malloc (nf * sizeof (u32)): NULL);
	ob.frame_ends = (nf? (u32 *)malloc (nf * sizeof (u32)): NULL);
	if ((nf && (!ob.frame_starts || !ob.frame_ends))) {
		output_buffers_fini (&ob);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom nested frame lists");
	}
	for (u32 i = 0; i < nf; i++) {
		ob.frame_starts[i] = function_body->nested_frames[i].start_address;
		ob.frame_ends[i] = function_body->nested_frames[i].end_address;
	}
	qsort (ob.frame_starts, nf, sizeof (u32), cmp_u32);
	qsort (ob.frame_ends, nf, sizeof (u32), cmp_u32);
	u32 frame_start_idx = 0;
	u32 frame_end_idx = 0;

	/* Dead Code Elimination: identify statements with unused register assignments */
	bool *dce = NULL;
	Result dce_result = identify_dead_assignments (function_body, &dce);
	if (dce_result.code != RESULT_SUCCESS) {
		output_buffers_fini (&ob);
		free (dce);
		return dce_result;
	}

	u32 plan_func_sz = function_body->function_object? function_body->function_object->bytecodeSizeInBytes: 0;
	U32Set goto_labels = { 0 };
	Result lbl_init = u32set_init (&goto_labels, plan_func_sz + 1);
	if (lbl_init.code != RESULT_SUCCESS) {
		output_buffers_fini (&ob);
		free (dce);
		return lbl_init;
	}
	u32 end_label_addr = UINT32_MAX;
	bool has_catch = false;
	Result labels_res = collect_labels (function_body, dce, plan_func_sz, &goto_labels, &end_label_addr, &has_catch);
	if (labels_res.code != RESULT_SUCCESS) {
		output_buffers_fini (&ob);
		free (dce);
		u32set_free (&goto_labels);
		return labels_res;
	}
	/* Emit labels in address order. A target need not land exactly on a
	 * surviving statement (it may be DCE'd or sit between statements), so a
	 * label is flushed before the first statement at or past its address. */
	qsort (goto_labels.data, goto_labels.count, sizeof (u32), cmp_u32);
	u32 label_idx = 0;

	StructuredCatch *catch_plans = NULL;
	u32 catch_plan_count = 0;
	Result catch_res = build_structured_catches (function_body, dce, plan_func_sz, &catch_plans, &catch_plan_count);
	if (catch_res.code != RESULT_SUCCESS) {
		output_buffers_fini (&ob);
		free (dce);
		u32set_free (&goto_labels);
		return catch_res;
	}

	hbc_debug_printf ("[_hbc_output_code] START function_base=0x%llx, stmt_count=%u\n",
		(unsigned long long)state->options.function_base,
		function_body->statements_count);
	for (u32 si = 0; si < function_body->statements_count; si++) {
		/* Stop when budget exhausted or earlier phase (pass2) flagged it. */
		if (state->output_truncated || (state->options.max_output_bytes > 0 && out->length >= (size_t)state->options.max_output_bytes)) {
			state->output_truncated = true;
			if (!state->truncation_marker_emitted) {
				state->truncation_marker_emitted = true;
				append_indent (out, state->indent_level);
				_hbc_string_buffer_append (out,
					"// [output truncated: raise 'r2hermes.max_ast'/'r2hermes.max_bytes' (0=unlimited) for full output]\n");
			}
			break;
		}
		/* Skip dead code */
		if (dce && dce[si]) {
			continue;
		}
		TokenString *st = &function_body->statements[si];
		ParsedInstruction *asm_ref = st->assembly;
		if (si < 10) {
			hbc_debug_printf ("[_hbc_output_code] stmt %u: asm_ref=%p\n", si, (void *)asm_ref);
		}
		if (asm_ref) {
			u32 pos = asm_ref->original_pos;
			StructuredCatch *catch_end = structured_catch_at (catch_plans, catch_plan_count, pos, 'm');
			if (catch_end) {
				catch_end->catch_open = false;
				RETURN_IF_ERROR (emit_close_brace (state, out));
			}

			/* Close frames */
			while (frame_end_idx < nf && ob.frame_ends[frame_end_idx] == pos) {
				frame_end_idx++;
				RETURN_IF_ERROR (emit_close_brace (state, out));
			}

			RETURN_IF_ERROR (close_if_blocks (state, out, &ob, pos));

			/* Goto target labels for control flow that does not nest as if-blocks */
			while (label_idx < goto_labels.count && goto_labels.data[label_idx] <= pos) {
				if (!structured_catch_at (catch_plans, catch_plan_count, goto_labels.data[label_idx], 'c')) {
					RETURN_IF_ERROR (emit_label (out, state->options.function_base + goto_labels.data[label_idx], false));
				}
				label_idx++;
			}

			/* Open frames */
			while (frame_start_idx < nf && ob.frame_starts[frame_start_idx] == pos) {
				frame_start_idx++;
				RETURN_IF_ERROR (append_indent (out, state->indent_level));
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, "{\n"));
				state->indent_level++;
			}
			if (structured_catch_at (catch_plans, catch_plan_count, pos, 's')) {
				RETURN_IF_ERROR (append_indent (out, state->indent_level));
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, "try {\n"));
				state->indent_level++;
			}
		}

		if (!st->head) {
			continue;
		}

		Token *head = st->head;
		StructuredCatch *try_end = asm_ref? structured_catch_at (catch_plans, catch_plan_count, asm_ref->original_pos, 'e'): NULL;
		if (try_end && (head->type == TOKEN_TYPE_JUMP_CONDITION || head->type == TOKEN_TYPE_JUMP_NOT_CONDITION) &&
			jump_is_unconditional (head) && jump_target_of (head) == try_end->catch_end) {
			continue;
		}

		StructuredCatch *catch_start = asm_ref? structured_catch_at (catch_plans, catch_plan_count, asm_ref->original_pos, 'c'): NULL;
		if (catch_start) {
			RETURN_IF_ERROR (close_if_blocks (state, out, &ob, UINT32_MAX));
			state->indent_level--;
			RETURN_IF_ERROR (append_indent (out, state->indent_level));
			char cbuf[32];
			snprintf (cbuf, sizeof (cbuf), "} catch (r%d) {\n", catch_start->catch_reg);
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, cbuf));
			state->indent_level++;
			catch_start->catch_open = true;
			continue;
		}

		if (st->head->type == TOKEN_TYPE_CATCH_BLOCK_START) {
			RETURN_IF_ERROR (close_if_blocks (state, out, &ob, UINT32_MAX));
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
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, addr_buf));
			/* Add indentation after offset */
			RETURN_IF_ERROR (append_indent (out, state->indent_level));
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

		bool emitted_statement = false;
		if (head->type == TOKEN_TYPE_SAVE_GENERATOR) {
			u32 ret_si = si + 1;
			while (ret_si < function_body->statements_count && dce && dce[ret_si]) {
				ret_si++;
			}
			TokenString *ret = (ret_si < function_body->statements_count)? &function_body->statements[ret_si]: NULL;
			u32 ret_pos = (ret && ret->assembly)? ret->assembly->original_pos: UINT32_MAX;
			if (ret && ret->head && ret->head->type == TOKEN_TYPE_RETURN_DIRECTIVE && !u32set_contains (&goto_labels, ret_pos)) {
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, "yield"));
				if (ret->head->next) {
					RETURN_IF_ERROR (_hbc_string_buffer_append_char (out, ' '));
					RETURN_IF_ERROR (append_plain_tokens (out, ret->head->next));
				}
				si = ret_si;
				emitted_statement = true;
			}
		}
		if (!emitted_statement && (head->type == TOKEN_TYPE_JUMP_NOT_CONDITION || head->type == TOKEN_TYPE_JUMP_CONDITION)) {
			u32 target_addr = jump_target_of (head);
			/* Jumps that leave the function share a single end label. */
			u32 lbl_rel = (target_addr >= plan_func_sz)? plan_func_sz: target_addr;
			unsigned long long lbl_abs = (unsigned long long) (state->options.function_base + lbl_rel);

			if (jump_is_unconditional (head)) {
				RETURN_IF_ERROR (emit_goto (out, lbl_abs));
				continue;
			}

			RETURN_IF_ERROR (_hbc_string_buffer_append (out, "if ("));

			u32 pos = asm_ref? asm_ref->original_pos: 0;
			bool goto_form = has_catch || target_addr <= pos ||
				(ob.if_block_stack_count > 0 && target_addr > ob.if_block_stack[ob.if_block_stack_count - 1]);
			RETURN_IF_ERROR (append_condition_tokens (out, head->next, goto_form && head->type == TOKEN_TYPE_JUMP_NOT_CONDITION));
			if (goto_form) {
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, ") "));
				RETURN_IF_ERROR (emit_goto (out, lbl_abs));
			} else {
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, ") {\n"));
				RETURN_IF_ERROR (if_block_stack_push (&ob, target_addr));
				state->indent_level++;
			}
			continue;
		} else if (!emitted_statement) {
			/* Emit all tokens, handling nested function expressions */
			bool first_tok = true;
			TokenType prev_type = (TokenType) (-1);
			for (Token *t = st->head; t; t = t->next) {
				if (t->type == TOKEN_TYPE_FUNCTION_TABLE_INDEX) {
					FunctionTableIndexToken *fti = (FunctionTableIndexToken *)t;
					if ((fti->is_closure || fti->is_generator) && !fti->is_builtin) {
						if (!first_tok && token_needs_space (prev_type, TOKEN_TYPE_RAW)) {
							RETURN_IF_ERROR (_hbc_string_buffer_append_char (out, ' '));
						}
						if (should_inline_closure (state, fti)) {
							int saved_indent = state->indent_level;
							state->inlining_function = true;
							RETURN_IF_ERROR (_hbc_decompile_function (state, fti->function_id, fti->parent_environment, fti->environment_id, fti->is_closure, fti->is_generator, fti->is_async));
							state->inlining_function = false;
							state->indent_level = saved_indent;
						} else {
							/* Reference the closure by function ID instead of inlining */
							RETURN_IF_ERROR (_hbc_string_buffer_append (out, "fn_"));
							RETURN_IF_ERROR (_hbc_string_buffer_append_int (out, (int)fti->function_id));
						}
						first_tok = false;
						prev_type = TOKEN_TYPE_RAW;
						continue;
					}
				}
				RETURN_IF_ERROR (append_token_spaced (out, t, first_tok, prev_type));
				first_tok = false;
				prev_type = t->type;
			}
		}

		/* Append r2 comment if available via callback
		 * Only check comments for statements that have assembly references,
		 * as we need the bytecode offset for the lookup. */
		if (state->options.comment_callback && asm_ref) {
			char *comment = state->options.comment_callback (state->options.comment_context, abs_addr);
			if (comment) {
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, " // "));
				RETURN_IF_ERROR (_hbc_string_buffer_append (out, comment));
				free (comment);
			}
		}

		if (is_block_stmt) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, "\n"));
		} else {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, ";\n"));
		}
	}

	RETURN_IF_ERROR (close_if_blocks (state, out, &ob, UINT32_MAX));

	/* Flush any labels whose address sits past the last emitted statement. */
	while (label_idx < goto_labels.count) {
		RETURN_IF_ERROR (emit_label (out, state->options.function_base + goto_labels.data[label_idx], true));
		label_idx++;
	}

	/* Landing label for jumps that exit the function (target >= func_sz). */
	if (end_label_addr != UINT32_MAX) {
		RETURN_IF_ERROR (emit_label (out, state->options.function_base + end_label_addr, true));
	}

	/* Closing brace for all functions (global and non-global) */
	state->indent_level--;
	if (state->options.show_offsets) {
		/* In pd:ho mode, closing brace must start with an offset */
		char addr_buf[24];
		snprintf (addr_buf, sizeof (addr_buf), "0x%08llx: ", (unsigned long long)state->options.function_base);
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, addr_buf));
	} else {
		RETURN_IF_ERROR (append_indent (out, state->indent_level));
	}
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, "}\n"));

	output_buffers_fini (&ob);
	free (dce);
	free (catch_plans);
	u32set_free (&goto_labels);
	return SUCCESS_RESULT ();
}

Result _hbc_decompile_function(HermesDecompiler *state, u32 function_id, Environment *parent_environment, int environment_id, bool is_closure, bool is_generator, bool is_async) {
	if (!state || !state->hbc_reader) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_decompile_function args");
	}
	if (state->output_truncated) {
		return SUCCESS_RESULT ();
	}
	HBCReader *reader = state->hbc_reader;
	if (function_id >= reader->header.functionCount) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "_hbc_decompile_function bad id");
	}

	Result r = SUCCESS_RESULT ();
	bool list_initialized = false;
	bool fb_initialized = false;
	bool function_marked = false;
	ParsedInstructionList list;
	memset (&list, 0, sizeof (list));
	DecompiledFunctionBody fb;

	/* Lazily allocate recursion tracker */
	if (!state->function_in_progress && reader->header.functionCount > 0) {
		state->function_in_progress = (bool *)calloc (reader->header.functionCount, sizeof (bool));
		if (!state->function_in_progress) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate active function tracker");
		}
	}

	if (state->function_in_progress) {
		if (state->function_in_progress[function_id]) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Recursive inlining detected");
		}
		state->function_in_progress[function_id] = true;
		function_marked = true;
	}

	/* Mark function as decompiled to prevent duplicate processing */
	if (state->decompiled_functions) {
		state->decompiled_functions[function_id] = true;
	}

	/* Load bytecode either from state or from file buffer */
	if (state->hbc) {
		r = ensure_function_bytecode_loaded_from_state (state->hbc, &reader->function_headers[function_id], function_id);
	} else {
		r = ensure_function_bytecode_loaded (reader, function_id);
	}
	if (r.code != RESULT_SUCCESS) {
		goto cleanup;
	}

	/* Update function_base for current function (used for offset display) */
	state->options.function_base = reader->function_headers[function_id].offset;
	HBCISA isa = hbc_isa_getv (reader->header.version);

	r = _hbc_parse_function_bytecode (reader, function_id, &list, isa);
	if (r.code != RESULT_SUCCESS) {
		goto cleanup;
	}
	list_initialized = true;

	r = _hbc_function_body_init (&fb, function_id, &reader->function_headers[function_id], function_id == reader->header.globalCodeIndex);
	if (r.code != RESULT_SUCCESS) {
		goto cleanup;
	}
	fb_initialized = true;
	fb.parent_environment = parent_environment;
	fb.environment_id = environment_id;
	fb.is_closure = is_closure;
	fb.is_generator = is_generator;
	fb.is_async = is_async;

	/* Transfer parsed instructions into the function body */
	fb.instructions = list;
	memset (&list, 0, sizeof (list));
	list_initialized = false;

	/* Execute transformation passes (configurable via decompile options) */
	if (!state->options.skip_pass1_metadata) {
		r = _hbc_pass1_set_metadata (state, &fb);
	}
	if (r.code == RESULT_SUCCESS && !state->options.skip_pass2_transform) {
		r = _hbc_pass2_transform_code (state, &fb);
	}
	if (r.code == RESULT_SUCCESS && !state->options.skip_pass3_forin) {
		r = _hbc_pass3_parse_forin_loops (state, &fb);
	}
	if (r.code == RESULT_SUCCESS && !state->options.skip_pass4_closure) {
		r = _hbc_pass4_name_closure_vars (state, &fb);
	}
	if (r.code == RESULT_SUCCESS) {
		r = _hbc_output_code (state, &fb);
	}

cleanup:
	if (fb_initialized) {
		_hbc_function_body_cleanup (&fb);
	}
	if (list_initialized) {
		_hbc_parsed_instruction_list_free (&list);
	}
	if (function_marked && state->function_in_progress) {
		state->function_in_progress[function_id] = false;
	}
	return r;
}

/* removed old stubs (replaced above with real implementations) */
