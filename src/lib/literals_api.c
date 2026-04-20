/* Public literals API: lazy cache, formatting, scanning. See
 * include/hbc/literals.h for the contract. */

#include <hbc/literals.h>
#include <hbc/opcodes.h>
#include <hbc/bytecode.h>
#include <hbc/decompilation/literals.h>
#include "hbc_internal.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ---------- Global toggles ---------- */

static bool g_inline_literals = false;

void hbc_set_inline_literals(bool on) {
	g_inline_literals = on;
}

bool hbc_get_inline_literals(void) {
	return g_inline_literals;
}

/* ---------- Pool accessors ---------- */

u32 hbc_get_pool_paddr(HBC *hbc, HBCLiteralKind kind) {
	if (!hbc) {
		return 0;
	}
	const HBCReader *r = &hbc->reader;
	switch (kind) {
	case HBC_LIT_ARRAY:
		return r->arrays? r->arrays_paddr: 0;
	case HBC_LIT_OBJECT:
		return r->object_keys? r->object_keys_paddr: 0;
	}
	return 0;
}

u32 hbc_get_pool_size(HBC *hbc, HBCLiteralKind kind) {
	if (!hbc) {
		return 0;
	}
	const HBCReader *r = &hbc->reader;
	switch (kind) {
	case HBC_LIT_ARRAY: return r->header.arrayBufferSize;
	case HBC_LIT_OBJECT: return r->header.objKeyBufferSize;
	}
	return 0;
}

u32 hbc_get_object_values_paddr(HBC *hbc) {
	return (hbc && hbc->reader.object_values)? hbc->reader.object_values_paddr: 0;
}

u32 hbc_get_object_values_size(HBC *hbc) {
	return hbc? hbc->reader.header.objValueBufferSize: 0;
}

/* ---------- Formatting ---------- */

static Result format_raw_impl(HBCReader *r, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, char **out) {
	*out = NULL;
	StringBuffer sb;
	Result ir = _hbc_string_buffer_init (&sb, 128);
	if (ir.code != RESULT_SUCCESS) {
		return ir;
	}
	Result fr;
	if (kind == HBC_LIT_ARRAY) {
		fr = _hbc_format_array_literal (r, num_items, primary_id, &sb,
			LITERALS_PRETTY_NEVER, true);
	} else {
		/* For v97+ primary_id is the shape index; the internal formatter
		 * expects that convention already (first arg is "key_count" which is
		 * reinterpreted as shape id when version >= 97). */
		fr = _hbc_format_object_literal (r, num_items, num_items, primary_id,
			secondary_id, &sb, LITERALS_PRETTY_NEVER, true);
	}
	if (fr.code == RESULT_SUCCESS && sb.data && sb.length > 0) {
		*out = strdup (sb.data);
		if (!*out) {
			fr = ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
		}
	}
	_hbc_string_buffer_free (&sb);
	return fr;
}

Result hbc_literals_format_raw(HBC *hbc, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, char **out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	return format_raw_impl (&hbc->reader, kind, num_items, primary_id,
		secondary_id, out);
}

Result hbc_literals_format_for_opcode(HBC *hbc, u8 opcode, u32 arg3, u32 arg4,
	u32 arg5, char **out) {
	if (!hbc || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	switch (opcode) {
	case OP_NewArrayWithBuffer:
	case OP_NewArrayWithBufferLong:
		return hbc_literals_format_raw (hbc, HBC_LIT_ARRAY, arg3, arg4, 0, out);
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
		return hbc_literals_format_raw (hbc, HBC_LIT_OBJECT, arg3, arg4, arg5, out);
	}
	return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT,
		"opcode is not a buffer-literal constructor");
}

/* ---------- Cache ---------- */

static HBCLiteralEntry *cache_find(HBCLiteralCache *c, HBCLiteralKind kind,
	u32 num_items, u32 primary_id, u32 secondary_id) {
	for (u32 i = 0; i < c->count; i++) {
		HBCLiteralEntry *e = &c->entries[i];
		if (e->kind == kind && e->num_items == num_items
			&& e->primary_id == primary_id
			&& e->secondary_id == secondary_id) {
			return e;
		}
	}
	return NULL;
}

static HBCLiteralEntry *cache_alloc(HBCLiteralCache *c) {
	if (c->count == c->cap) {
		u32 nc = c->cap? c->cap * 2: 64;
		HBCLiteralEntry *ne = realloc (c->entries, nc * sizeof (HBCLiteralEntry));
		if (!ne) {
			return NULL;
		}
		c->entries = ne;
		c->cap = nc;
	}
	HBCLiteralEntry *e = &c->entries[c->count++];
	memset (e, 0, sizeof (*e));
	return e;
}

/* Compute paddr for an entry based on its kind/primary_id. For v97+ objects,
 * primary_id is a shape index — resolve via the shape table. */
static u32 entry_paddr(HBC *hbc, HBCLiteralKind kind, u32 primary_id) {
	const HBCReader *r = &hbc->reader;
	if (kind == HBC_LIT_ARRAY) {
		if (!r->arrays) {
			return 0;
		}
		if (primary_id >= r->header.arrayBufferSize) {
			return 0;
		}
		return r->arrays_paddr + primary_id;
	}
	/* object */
	if (r->header.version >= 97 && r->object_shapes
		&& primary_id < r->object_shape_count) {
		u32 key_off = r->object_shapes[primary_id].key_buffer_offset;
		if (r->object_keys && key_off < r->header.objKeyBufferSize) {
			return r->object_keys_paddr + key_off;
		}
		return 0;
	}
	if (!r->object_keys || primary_id >= r->header.objKeyBufferSize) {
		return 0;
	}
	return r->object_keys_paddr + primary_id;
}

static Result cache_get_or_create(HBC *hbc, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, HBCLiteralEntry **out_entry) {
	HBCLiteralEntry *e = cache_find (&hbc->lit_cache, kind, num_items,
		primary_id, secondary_id);
	if (e) {
		*out_entry = e;
		return SUCCESS_RESULT ();
	}
	e = cache_alloc (&hbc->lit_cache);
	if (!e) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
	}
	e->kind = kind;
	e->num_items = num_items;
	e->primary_id = primary_id;
	e->secondary_id = secondary_id;
	e->paddr = entry_paddr (hbc, kind, primary_id);
	/* Format now (lazy across calls, but eager per key once we've decided to
	 * cache it). The formatted string is small and reused on every access. */
	char *txt = NULL;
	Result fr = format_raw_impl (&hbc->reader, kind, num_items, primary_id,
		secondary_id, &txt);
	if (fr.code == RESULT_SUCCESS) {
		e->formatted = txt;
	}
	*out_entry = e;
	return SUCCESS_RESULT ();
}

Result hbc_literals_get(HBC *hbc, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, const char **out_formatted) {
	if (!hbc || !out_formatted) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	HBCLiteralEntry *e;
	Result r = cache_get_or_create (hbc, kind, num_items, primary_id,
		secondary_id, &e);
	if (r.code != RESULT_SUCCESS) {
		return r;
	}
	*out_formatted = e->formatted;
	return SUCCESS_RESULT ();
}

static void xref_add(HBCLiteralEntry *e, u32 from_addr) {
	/* Keep xrefs as a small sorted-by-insertion array. Linear dedup. */
	for (u32 i = 0; i < e->xref_count; i++) {
		if (e->xref_addrs[i] == from_addr) {
			return;
		}
	}
	u32 *na = realloc (e->xref_addrs, (e->xref_count + 1) * sizeof (u32));
	if (!na) {
		return;
	}
	e->xref_addrs = na;
	e->xref_addrs[e->xref_count++] = from_addr;
}

Result hbc_literals_register(HBC *hbc, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, u32 from_addr) {
	if (!hbc) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	HBCLiteralEntry *e;
	Result r = cache_get_or_create (hbc, kind, num_items, primary_id,
		secondary_id, &e);
	if (r.code != RESULT_SUCCESS) {
		return r;
	}
	if (from_addr) {
		xref_add (e, from_addr);
	}
	return SUCCESS_RESULT ();
}

Result hbc_literals_list(HBC *hbc, const HBCLiteralEntry **out, u32 *out_count) {
	if (!hbc || !out || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	*out = hbc->lit_cache.entries;
	*out_count = hbc->lit_cache.count;
	return SUCCESS_RESULT ();
}

u32 hbc_literals_count(HBC *hbc) {
	return hbc? hbc->lit_cache.count: 0;
}

void hbc_literals_reset(HBC *hbc) {
	if (!hbc) {
		return;
	}
	HBCLiteralCache *c = &hbc->lit_cache;
	for (u32 i = 0; i < c->count; i++) {
		free (c->entries[i].formatted);
		free (c->entries[i].xref_addrs);
	}
	free (c->entries);
	c->entries = NULL;
	c->count = 0;
	c->cap = 0;
}

/* ---------- Code-side scan ---------- */

static bool is_buffer_op(u8 opcode, HBCLiteralKind *out_kind) {
	switch (opcode) {
	case OP_NewArrayWithBuffer:
	case OP_NewArrayWithBufferLong:
		*out_kind = HBC_LIT_ARRAY;
		return true;
	case OP_NewObjectWithBuffer:
	case OP_NewObjectWithBufferLong:
		*out_kind = HBC_LIT_OBJECT;
		return true;
	}
	return false;
}

/* Decode opcode immediates into (num_items, primary, secondary), version-aware.
 * Returns false if the opcode is not a buffer-literal constructor or if the
 * buffer would be read out of bounds. */
static bool decode_buffer_op(u8 op, u32 version, const u8 *code, u32 size,
	u32 pc, u32 inst_size, HBCLiteralKind *kind, u32 *num_items, u32 *primary,
	u32 *secondary) {
	if (pc + inst_size > size) {
		return false;
	}
	*secondary = 0;
	if (op == OP_NewArrayWithBuffer) {
		/* reg8 + u16 prealloc + u16 num + u16 id (v<97 AND v97+) */
		*kind = HBC_LIT_ARRAY;
		*num_items = (u32)code[pc + 4] | ((u32)code[pc + 5] << 8);
		*primary = (u32)code[pc + 6] | ((u32)code[pc + 7] << 8);
		return true;
	}
	if (op == OP_NewArrayWithBufferLong) {
		/* reg8 + u16 prealloc + u16 num + u32 id */
		*kind = HBC_LIT_ARRAY;
		*num_items = (u32)code[pc + 4] | ((u32)code[pc + 5] << 8);
		*primary = (u32)code[pc + 6] | ((u32)code[pc + 7] << 8)
			| ((u32)code[pc + 8] << 16) | ((u32)code[pc + 9] << 24);
		return true;
	}
	if (op == OP_NewObjectWithBuffer) {
		*kind = HBC_LIT_OBJECT;
		if (version >= 97) {
			/* reg8 + u16 shape_id + u16 values_id */
			*primary = (u32)code[pc + 2] | ((u32)code[pc + 3] << 8);
			*secondary = (u32)code[pc + 4] | ((u32)code[pc + 5] << 8);
			*num_items = 0; /* resolved via shape table by the formatter */
		} else {
			/* reg8 + u16 prealloc + u16 num + u16 keys + u16 vals */
			*num_items = (u32)code[pc + 4] | ((u32)code[pc + 5] << 8);
			*primary = (u32)code[pc + 6] | ((u32)code[pc + 7] << 8);
			*secondary = (u32)code[pc + 8] | ((u32)code[pc + 9] << 8);
		}
		return true;
	}
	if (op == OP_NewObjectWithBufferLong) {
		*kind = HBC_LIT_OBJECT;
		if (version >= 97) {
			/* reg8 + u32 shape_id + u32 values_id */
			*primary = (u32)code[pc + 2] | ((u32)code[pc + 3] << 8)
				| ((u32)code[pc + 4] << 16) | ((u32)code[pc + 5] << 24);
			*secondary = (u32)code[pc + 6] | ((u32)code[pc + 7] << 8)
				| ((u32)code[pc + 8] << 16) | ((u32)code[pc + 9] << 24);
			*num_items = 0;
		} else {
			/* reg8 + u16 prealloc + u16 num + u32 keys + u32 vals */
			*num_items = (u32)code[pc + 4] | ((u32)code[pc + 5] << 8);
			*primary = (u32)code[pc + 6] | ((u32)code[pc + 7] << 8)
				| ((u32)code[pc + 8] << 16) | ((u32)code[pc + 9] << 24);
			*secondary = (u32)code[pc + 10] | ((u32)code[pc + 11] << 8)
				| ((u32)code[pc + 12] << 16) | ((u32)code[pc + 13] << 24);
		}
		return true;
	}
	return false;
}

Result hbc_literals_scan_code(HBC *hbc, u32 *out_count) {
	if (!hbc) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	u32 nfuncs = hbc->reader.header.functionCount;
	u32 version = hbc->reader.header.version;
	HBCISA isa = hbc_isa_getv (version);
	if (!isa.instructions) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "no isa for version");
	}
	for (u32 fid = 0; fid < nfuncs; fid++) {
		const u8 *code = NULL;
		u32 size = 0;
		if (hbc_get_function_bytecode (hbc, fid, &code, &size).code
			!= RESULT_SUCCESS || !code || size == 0) {
			continue;
		}
		HBCFunc fi;
		u32 fn_paddr = 0;
		if (hbc_get_function_info (hbc, fid, &fi).code == RESULT_SUCCESS) {
			fn_paddr = fi.offset;
		}
		u32 pc = 0;
		while (pc < size) {
			u8 op = code[pc];
			const Instruction *ins = (op < isa.count)? &isa.instructions[op]: NULL;
			if (!ins || !ins->name || ins->binary_size == 0) {
				break;
			}
			HBCLiteralKind kind;
			u32 num_items = 0, primary = 0, secondary = 0;
			if (decode_buffer_op (op, version, code, size, pc, ins->binary_size,
					&kind, &num_items, &primary, &secondary)) {
				u32 call_addr = fn_paddr + pc;
				hbc_literals_register (hbc, kind, num_items, primary, secondary,
					call_addr);
			}
			(void)is_buffer_op; /* retained for tools that need the predicate */
			pc += ins->binary_size;
		}
	}
	if (out_count) {
		*out_count = hbc->lit_cache.count;
	}
	return SUCCESS_RESULT ();
}

/* ---------- Pool-side scan ---------- */

static bool slp_skip_group(const u8 *base, size_t size, size_t *pos,
	u8 *out_tag, u32 *out_length) {
	if (*pos >= size) {
		return false;
	}
	u8 taglen = base[(*pos)++];
	u8 tag = (taglen >> 4) & 0x7;
	u32 length = taglen & 0x0F;
	if (taglen & 0x80) {
		if (*pos >= size) {
			return false;
		}
		length = ((u32)(taglen & 0x0F) << 8) | base[(*pos)++];
	}
	size_t per_value = 0;
	switch (tag) {
	case 0: case 1: case 2: per_value = 0; break; /* null/true/false */
	case 3: per_value = 8; break; /* number */
	case 4: case 7: per_value = 4; break; /* longstr/int */
	case 5: per_value = 2; break; /* shortstr */
	case 6: per_value = 1; break; /* bytestr */
	default: return false;
	}
	if (*pos + per_value * length > size) {
		return false;
	}
	*pos += per_value * length;
	if (out_tag) {
		*out_tag = tag;
	}
	if (out_length) {
		*out_length = length;
	}
	return true;
}

Result hbc_literals_scan_pool(HBC *hbc, HBCLiteralKind kind,
	HBCPoolGroup **out, u32 *out_count) {
	if (!hbc || !out || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "invalid args");
	}
	*out = NULL;
	*out_count = 0;

	/* Object-keys on v97+: enumerate shape table instead of the raw pool. */
	if (kind == HBC_LIT_OBJECT && hbc->reader.header.version >= 97
		&& hbc->reader.object_shapes
		&& hbc->reader.object_shape_count > 0) {
		size_t n = hbc->reader.object_shape_count;
		HBCPoolGroup *arr = calloc (n, sizeof (HBCPoolGroup));
		if (!arr) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
		}
		for (size_t i = 0; i < n; i++) {
			arr[i].pool_offset = hbc->reader.object_shapes[i].key_buffer_offset;
			arr[i].num_items = hbc->reader.object_shapes[i].prop_count;
			arr[i].paddr = hbc->reader.object_keys_paddr + arr[i].pool_offset;
			arr[i].tag = 0xff; /* N/A for a shape row */
		}
		*out = arr;
		*out_count = (u32)n;
		return SUCCESS_RESULT ();
	}

	const u8 *base;
	u32 size;
	u32 paddr;
	if (kind == HBC_LIT_ARRAY) {
		base = hbc->reader.arrays;
		size = hbc->reader.header.arrayBufferSize;
		paddr = hbc->reader.arrays_paddr;
	} else {
		base = hbc->reader.object_keys;
		size = hbc->reader.header.objKeyBufferSize;
		paddr = hbc->reader.object_keys_paddr;
	}
	if (!base || !size) {
		return SUCCESS_RESULT ();
	}

	u32 cap = 64;
	HBCPoolGroup *arr = calloc (cap, sizeof (HBCPoolGroup));
	if (!arr) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom");
	}
	u32 n = 0;
	size_t pos = 0;
	while (pos < size) {
		size_t group_start = pos;
		u8 tag = 0;
		u32 length = 0;
		if (!slp_skip_group (base, size, &pos, &tag, &length)) {
			break;
		}
		if (n == cap) {
			u32 nc = cap * 2;
			HBCPoolGroup *na = realloc (arr, nc * sizeof (HBCPoolGroup));
			if (!na) {
				break;
			}
			arr = na;
			cap = nc;
		}
		arr[n].pool_offset = (u32)group_start;
		arr[n].paddr = paddr + (u32)group_start;
		arr[n].num_items = length;
		arr[n].tag = tag;
		n++;
	}
	*out = arr;
	*out_count = n;
	return SUCCESS_RESULT ();
}
