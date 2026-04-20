/* radare2 - LGPL - Copyright 2025-2026 - pancake */

/* r2 core plugin for Hermes bytecode decompilation */

#include <r_core.h>
#include <hbc/hbc.h>
#include <hbc/literals.h>
#include "utils.inc.c"

#define HBC_VADDR_BASE 0x10000000ULL

/* Plugin registration - need these when HBC_CORE_REGISTER_PLUGINS is enabled */
#ifdef HBC_CORE_REGISTER_PLUGINS
extern const RArchPlugin r_arch_plugin_r2hermes;
extern const RBinPlugin r_bin_plugin_r2hermes;
extern const RAsmPlugin r_asm_plugin_r2hermes;
#endif

typedef struct {
	HBC *hbc;
	RCore *core;
	char *file_path;
} HbcContext;

static const char *safe_errmsg(const char *s) {
	return r_str_get_fail (s, "Unknown error");
}

static ut32 parse_function_id(const char *addr_str) {
	const char *as = r_str_trim_head_ro (addr_str);
	if (*as) {
		ut64 fid = r_num_get (NULL, as);
		if (fid != UT64_MAX && fid < UT32_MAX) {
			return fid & UT32_MAX;
		}
	}
	return 0;
}

/* Comment callback for retrieving r2 comments (CC command) at an address */
static char *r2_comment_callback(void *context, u64 address) {
	RCore *core = (RCore *)context;
	if (core) {
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address);
		return comment? strdup (comment): NULL;
	}
	return NULL;
}

/* Flag callback for retrieving r2 flag/symbol names at an address */
static char *r2_flag_callback(void *context, u64 address) {
	RCore *core = (RCore *)context;
	if (core && core->flags) {
		RFlagItem *fi = r_flag_get_at (core->flags, address, true);
		if (fi && fi->name) {
			return strdup (fi->name);
		}
	}
	return NULL;
}

static const char *current_file_path(RCore *core) {
	if (core && core->bin) {
		RBinInfo *bi = r_bin_get_info (core->bin);
		if (bi) {
			return bi->file;
		}
	}
	return NULL;
}

/* Helper to load the current binary as HBC using provider API */
static Result hbc_load_current_binary(HbcContext *ctx, RCore *core) {
	const char *file_path = current_file_path (core);
	if (R_STR_ISEMPTY (file_path)) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No binary loaded in r2");
	}

	/* Reload if file changed */
	if (ctx->hbc && ctx->file_path && !strcmp (ctx->file_path, file_path)) {
		return SUCCESS_RESULT ();
	}

	/* Clean up old provider */
	hbc_safe_close (&ctx->hbc);
	R_FREE (ctx->file_path);

	/* Get RBinFile from r2 (already parsed by r2) */
	RBinFile *bf = core->bin->cur;
	if (!bf) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No binary file loaded or r2 version incompatible");
	}

	/* Open HBC from buffer */
	Result res = hbc_open_from_buffer (bf->buf, &ctx->hbc);
	if (res.code != RESULT_SUCCESS) {
		return res;
	}

	ctx->core = core;
	ctx->file_path = strdup (file_path);
	if (!ctx->file_path) {
		hbc_safe_close (&ctx->hbc);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}
	return SUCCESS_RESULT ();
}

/* Find function ID at a given offset */
static int find_function_at_offset(HbcContext *ctx, u32 offset, u32 *out_id) {
	if (!out_id || !ctx->hbc) {
		return -1;
	}
	u32 count = hbc_function_count (ctx->hbc);
	for (u32 i = 0; i < count; i++) {
		HBCFunc fi;
		Result res = hbc_get_function_info (ctx->hbc, i, &fi);
		if (res.code == RESULT_SUCCESS) {
			if (offset >= fi.offset && offset < (fi.offset + fi.size)) {
				*out_id = i;
				return 0;
			}
		}
	}
	return -1;
}

/* Create decompile options from radare2 settings */
static HBCDecompOptions make_decompile_options(RCore *core, bool show_offsets, u64 function_base) {
	HBCDecompOptions opts = {
		.pretty_literals = r_config_get_b (core->config, "hbc.pretty_literals"),
		.suppress_comments = r_config_get_b (core->config, "hbc.suppress_comments"),
		.show_offsets = show_offsets || r_config_get_b (core->config, "hbc.show_offsets"),
		.function_base = function_base,
		.comment_callback = r2_comment_callback,
		.comment_context = core,
		.flag_callback = r2_flag_callback,
		.flag_context = core,
		.skip_pass1_metadata = r_config_get_b (core->config, "hbc.skip_pass1"),
		.skip_pass2_transform = r_config_get_b (core->config, "hbc.skip_pass2"),
		.skip_pass3_forin = r_config_get_b (core->config, "hbc.skip_pass3"),
		.skip_pass4_closure = r_config_get_b (core->config, "hbc.skip_pass4"),
		.force_dispatch = r_config_get_b (core->config, "hbc.force_dispatch"),
		.inline_closures = r_config_get_b (core->config, "hbc.inline_closures"),
		.inline_threshold = r_config_get_i (core->config, "hbc.inline_threshold"),
		.max_ast_statements = r_config_get_i (core->config, "hbc.max_ast"),
		.max_output_bytes = r_config_get_i (core->config, "hbc.max_bytes")
	};
	return opts;
}

/* Decompile function at current offset or all functions if not in a function */
static void cmd_decompile_current_ex(HbcContext *ctx, RCore *core, bool show_offsets) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (res.error_message));
		return;
	}

	u32 function_id = 0;
	/* Get current offset from r2 core */
	int found = find_function_at_offset (ctx, (u32)core->addr, &function_id);

	if (found == 0) {
		/* Found function at current offset - get its base address */
		HBCFunc fi;
		Result fres = hbc_get_function_info (ctx->hbc, function_id, &fi);
		u64 func_base = (fres.code == RESULT_SUCCESS)? fi.offset: 0;
		HBCDecompOptions opts = make_decompile_options (core, show_offsets, func_base);
		char *output = NULL;
		res = hbc_decomp_fn (ctx->hbc, function_id, opts, &output);
		if (res.code == RESULT_SUCCESS && output) {
			r_str_trim (output);
			r_cons_println (core->cons, output);
		} else {
			R_LOG_ERROR ("Decompiling function %u: %s", function_id, safe_errmsg (res.error_message));
		}
		free (output);
	} else {
		/* Not in a function, decompile all - use 0 as base since multiple functions */
		HBCDecompOptions opts = make_decompile_options (core, show_offsets, 0);
		char *output = NULL;
		res = hbc_decomp_all (ctx->hbc, opts, &output);
		if (res.code == RESULT_SUCCESS && output) {
			r_str_trim (output);
			r_cons_println (core->cons, output);
		} else {
			R_LOG_ERROR ("Error decompiling: %s", safe_errmsg (res.error_message));
		}
		free (output);
	}
}

/* Decompile all functions */
static void cmd_decompile_all_ex(HbcContext *ctx, RCore *core, bool show_offsets) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (res.error_message));
		return;
	}

	HBCDecompOptions opts = make_decompile_options (core, show_offsets, 0);
	char *output = NULL;
	res = hbc_decomp_all (ctx->hbc, opts, &output);
	if (res.code == RESULT_SUCCESS && output) {
		r_str_trim (output);
		r_cons_println (core->cons, output);
	} else {
		R_LOG_ERROR ("Error decompiling: %s", safe_errmsg (res.error_message));
	}
	free (output);
}

/* Decompile current function by address */
static void cmd_decompile_function_ex(HbcContext *ctx, RCore *core, const char *addr_str, bool show_offsets) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (res.error_message));
		return;
	}
	u32 function_id = parse_function_id (addr_str);
	u32 count = hbc_function_count (ctx->hbc);
	if (function_id >= count) {
		R_LOG_ERROR ("function id %u out of range (count=%u)", function_id, count);
		return;
	}
	/* Get function base address for offset calculation */
	HBCFunc fi;
	Result fres = hbc_get_function_info (ctx->hbc, function_id, &fi);
	u64 func_base = (fres.code == RESULT_SUCCESS)? fi.offset: 0;
	HBCDecompOptions opts = make_decompile_options (core, show_offsets, func_base);
	char *output = NULL;
	res = hbc_decomp_fn (ctx->hbc, function_id, opts, &output);
	if (res.code == RESULT_SUCCESS && output) {
		r_str_trim (output);
		r_cons_println (core->cons, output);
	} else {
		R_LOG_ERROR ("Decompiling function %u: %s", function_id, safe_errmsg (res.error_message));
	}
	free (output);
}

/* List available functions */
static void cmd_list_functions(HbcContext *ctx, RCore *core) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (res.error_message));
		return;
	}

	u32 count = hbc_function_count (ctx->hbc);
	r_cons_printf (core->cons, "Functions (%u):\n", count);

	for (u32 i = 0; i < count; i++) {
		HBCFunc info;
		Result res = hbc_get_function_info (ctx->hbc, i, &info);
		if (res.code == RESULT_SUCCESS) {
			r_cons_printf (core->cons, "  [%3u] %s at 0x%08x size=0x%x params=%u\n", i, r_str_get_fail (info.name, "unknown"), info.offset, info.size, info.param_count);
		}
	}
}

/* Show file information */
static void cmd_file_info(HbcContext *ctx, RCore *core) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (res.error_message));
		return;
	}

	HBCHeader header;
	res = hbc_get_header (ctx->hbc, &header);
	if (res.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("reading header: %s", safe_errmsg (res.error_message));
		return;
	}
	RCons *cons = core->cons;

	r_cons_printf (cons,
		"Hermes Bytecode File Information:\n"
		"  Version: %u\n"
		"  File Length: %u bytes\n"
		"  Functions: %u\n"
		"  Strings: %u\n"
		"  Identifiers: %u\n"
		"  Global Code Index: %u\n"
		"  Static Builtins: %s\n"
		"  Has Async: %s\n",
		header.version,
		header.fileLength,
		header.functionCount,
		header.stringCount,
		header.identifierCount,
		header.globalCodeIndex,
		header.staticBuiltins? "yes": "no",
		header.hasAsync? "yes": "no");

	char hex[41] = { 0 };
	r_hex_bin2str (header.sourceHash, 20, hex);
	r_cons_printf (cons,
		"\nHash Information (for binary patching):\n"
		"  Source Hash (header): %s\n",
		hex);
	const ut64 file_size = r_io_size (core->io);
	const ut64 expected_size = (ut64)header.fileLength + 20;

	r_cons_printf (cons, "  File size: %" PFMT64u " bytes\n", file_size);
	r_cons_printf (cons, "  Header fileLength: %u bytes\n", header.fileLength);

	if (file_size >= expected_size) {
		/* Footer exists or file has extra bytes - read and verify */
		ut8 footer[20] = { 0 };
		r_io_read_at (core->io, header.fileLength, footer, 20);
		r_hex_bin2str (footer, 20, hex);
		r_cons_printf (core->cons, "  Footer Hash (stored): %s\n", hex);

		char *computed = r_core_cmd_strf (core, "ph sha1 %u @0", header.fileLength);
		if (computed) {
			r_str_trim (computed);
			r_cons_printf (core->cons, "  Footer Hash (computed): %s\n", computed);
			bool valid = (strlen (computed) == 40 && !strcmp (computed, hex));
			r_cons_printf (core->cons, "  Status: %s\n", valid? "VALID": "INVALID");
			if (!valid || file_size != expected_size) {
				r_cons_printf (core->cons, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
			}
			if (file_size > expected_size) {
				r_cons_printf (core->cons, "  Warning: File has %" PFMT64u " extra bytes after footer\n", file_size - expected_size);
			}
			free (computed);
		}
	} else if (file_size == (ut64)header.fileLength && file_size >= 20) {
		/* fileLength == file_size: Check if last 20 bytes are a valid footer
		 *(some versions include footer in fileLength) */
		ut64 content_size = file_size - 20;
		ut8 footer[20] = { 0 };
		r_io_read_at (core->io, content_size, footer, 20);
		r_hex_bin2str (footer, 20, hex);

		char *computed = r_core_cmd_strf (core, "ph sha1 %" PFMT64u " @0", content_size);
		if (computed) {
			r_str_trim (computed);
			bool valid = (strlen (computed) == 40 && !strcmp (computed, hex));
			if (valid) {
				r_cons_printf (core->cons, "  Footer Hash (stored): %s\n", hex);
				r_cons_printf (core->cons, "  Footer Hash (computed): %s\n", computed);
				r_cons_printf (core->cons, "  Status: VALID (footer included in fileLength)\n");
			} else {
				r_cons_printf (core->cons, "  Footer: NOT PRESENT (file ends at fileLength)\n");
				r_cons_printf (core->cons, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
			}
			free (computed);
		} else {
			r_cons_printf (core->cons, "  Footer: NOT PRESENT (file ends at fileLength)\n");
			r_cons_printf (core->cons, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
		}
	} else {
		r_cons_printf (core->cons, "  Footer: UNKNOWN (file size mismatch)\n");
		r_cons_printf (core->cons, "  Expected: %" PFMT64u " or %u bytes, got %" PFMT64u "\n", expected_size, header.fileLength, file_size);
		r_cons_printf (core->cons, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
	}
}

/* Emit a JSON error envelope compatible with the {code, annotations, errors} format */
static void emit_json_error(RCore *core, const char *msg) {
	PJ *pj = r_core_pj_new (core);
	pj_o (pj);
	pj_ks (pj, "code", "");
	pj_ka (pj, "annotations");
	pj_end (pj);
	pj_ka (pj, "errors");
	pj_s (pj, msg);
	pj_end (pj);
	pj_end (pj);
	char *s = pj_drain (pj);
	r_cons_println (core->cons, s);
	free (s);
}

typedef struct {
	size_t start;
	size_t end;
	u64 offset;
} LineAnn;

/* JSON output for a function in the codemeta-compatible {code, annotations, errors} shape.
 * Uses show_offsets=true internally and parses the "0xHHHHHHHH: " line prefixes to
 * produce per-line offset annotations, then strips the prefix from the emitted code. */
static void cmd_json(HbcContext *ctx, RCore *core, const char *addr_str) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		emit_json_error (core, safe_errmsg (res.error_message));
		return;
	}

	u32 count = hbc_function_count (ctx->hbc);
	u32 function_id = 0;
	const char *as = r_str_trim_head_ro (addr_str);
	if (*as) {
		function_id = parse_function_id (addr_str);
	} else if (find_function_at_offset (ctx, (u32)core->addr, &function_id) != 0) {
		emit_json_error (core, "No function at current offset");
		return;
	}
	if (function_id >= count) {
		emit_json_error (core, "function id out of range");
		return;
	}

	HBCFunc fi;
	Result fres = hbc_get_function_info (ctx->hbc, function_id, &fi);
	u64 func_base = (fres.code == RESULT_SUCCESS)? fi.offset: 0;

	HBCDecompOptions opts = make_decompile_options (core, true, func_base);
	opts.pretty_literals = true;

	char *output = NULL;
	res = hbc_decomp_fn (ctx->hbc, function_id, opts, &output);
	if (res.code != RESULT_SUCCESS || !output) {
		emit_json_error (core, safe_errmsg (res.error_message));
		free (output);
		return;
	}

	RStrBuf *code_buf = r_strbuf_new ("");
	LineAnn *anns = NULL;
	size_t anns_n = 0, anns_cap = 0;

	const char *p = output;
	while (*p) {
		const char *eol = strchr (p, '\n');
		size_t line_len = eol? (size_t) (eol - p): strlen (p);

		bool has_offset = false;
		u64 line_offset = 0;
		if (line_len >= 12 && p[0] == '0' && p[1] == 'x' && p[10] == ':' && p[11] == ' ') {
			bool valid = true;
			for (int i = 2; i < 10; i++) {
				if (!isxdigit ((unsigned char)p[i])) {
					valid = false;
					break;
				}
			}
			if (valid) {
				char hexbuf[9];
				memcpy (hexbuf, p + 2, 8);
				hexbuf[8] = 0;
				line_offset = strtoull (hexbuf, NULL, 16);
				has_offset = true;
			}
		}

		size_t start = r_strbuf_length (code_buf);
		if (has_offset) {
			r_strbuf_append_n (code_buf, p + 12, line_len - 12);
		} else {
			r_strbuf_append_n (code_buf, p, line_len);
		}
		r_strbuf_append (code_buf, "\n");
		size_t end = r_strbuf_length (code_buf);

		if (has_offset) {
			if (anns_n == anns_cap) {
				anns_cap = anns_cap? anns_cap * 2: 64;
				LineAnn *grown = realloc (anns, anns_cap * sizeof (LineAnn));
				if (!grown) {
					break;
				}
				anns = grown;
			}
			anns[anns_n].start = start;
			anns[anns_n].end = end;
			anns[anns_n].offset = line_offset;
			anns_n++;
		}

		if (!eol) {
			break;
		}
		p = eol + 1;
	}

	char *cleaned = r_strbuf_drain (code_buf);

	PJ *pj = r_core_pj_new (core);
	pj_o (pj);
	pj_ks (pj, "code", cleaned? cleaned: "");
	pj_ka (pj, "annotations");
	for (size_t i = 0; i < anns_n; i++) {
		pj_o (pj);
		pj_ks (pj, "type", "offset");
		pj_kn (pj, "start", anns[i].start);
		pj_kn (pj, "end", anns[i].end);
		pj_kn (pj, "offset", anns[i].offset);
		pj_end (pj);
	}
	pj_end (pj);
	pj_ka (pj, "errors");
	pj_end (pj);
	pj_end (pj);
	char *s = pj_drain (pj);
	r_cons_println (core->cons, s);
	free (s);
	free (cleaned);
	free (anns);
	free (output);
}

/* ==========================================================================
 * Literal-buffer commands (pd:hL*)
 *
 * Work against the lazy HBC literal cache. Registration in r2 is additive:
 * flags (lit.arr.* / lit.obj.*) and CC comments are created at the literal
 * paddr; code→data xrefs are added for every call site. None of this is
 * attempted while plain disasm runs — the cache only populates on demand.
 * ========================================================================== */

static const char *lit_kind_prefix(HBCLiteralKind k) {
	return k == HBC_LIT_ARRAY? "lit.arr.": "lit.obj.";
}

/* Register r2 artifacts for one cache entry. Safe to call repeatedly. */
static void register_r2_artifacts(RCore *core, const HBCLiteralEntry *e) {
	if (!e->paddr) {
		return;
	}
	ut64 vaddr = HBC_VADDR_BASE + (ut64)e->paddr;
	char flag_name[64];
	snprintf (flag_name, sizeof (flag_name), "%s0x%x", lit_kind_prefix (e->kind), e->paddr);
	r_flag_set (core->flags, flag_name, vaddr, 1);
	if (e->formatted && *e->formatted) {
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, vaddr, e->formatted);
	}
	for (u32 i = 0; i < e->xref_count; i++) {
		ut64 from = HBC_VADDR_BASE + (ut64)e->xref_addrs[i];
		r_anal_xrefs_set (core->anal, from, vaddr, R_ANAL_REF_TYPE_DATA);
	}
}

static void register_all_artifacts(RCore *core, HBC *hbc) {
	const HBCLiteralEntry *arr = NULL;
	u32 n = 0;
	if (hbc_literals_list (hbc, &arr, &n).code != RESULT_SUCCESS) {
		return;
	}
	for (u32 i = 0; i < n; i++) {
		register_r2_artifacts (core, &arr[i]);
	}
}

static const char *kind_label(HBCLiteralKind k) {
	return k == HBC_LIT_ARRAY? "array": "object";
}

/* Make sure the current binary is loaded into the core plugin's HbcContext. */
static Result ensure_hbc_loaded(HbcContext *ctx, RCore *core, HBC **out) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code == RESULT_SUCCESS) {
		*out = ctx->hbc;
	}
	return res;
}

static void cmd_lit_list(HbcContext *ctx, RCore *core, bool as_json) {
	HBC *hbc = NULL;
	Result r = ensure_hbc_loaded (ctx, core, &hbc);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (r.error_message));
		return;
	}
	const HBCLiteralEntry *arr = NULL;
	u32 n = 0;
	if (hbc_literals_list (hbc, &arr, &n).code != RESULT_SUCCESS) {
		R_LOG_ERROR ("list failed");
		return;
	}
	if (n == 0) {
		r_cons_println (core->cons, "(cache empty — run pd:hLs to scan)");
		return;
	}
	if (as_json) {
		PJ *pj = r_core_pj_new (core);
		pj_a (pj);
		for (u32 i = 0; i < n; i++) {
			const HBCLiteralEntry *e = &arr[i];
			pj_o (pj);
			pj_ks (pj, "kind", kind_label (e->kind));
			pj_kn (pj, "num_items", e->num_items);
			pj_kn (pj, "primary_id", e->primary_id);
			pj_kn (pj, "secondary_id", e->secondary_id);
			pj_kn (pj, "paddr", e->paddr);
			pj_kn (pj, "vaddr", HBC_VADDR_BASE + e->paddr);
			pj_ks (pj, "formatted", e->formatted? e->formatted: "");
			pj_ka (pj, "xrefs");
			for (u32 j = 0; j < e->xref_count; j++) {
				pj_N (pj, HBC_VADDR_BASE + (ut64)e->xref_addrs[j]);
			}
			pj_end (pj);
			pj_end (pj);
		}
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
		return;
	}
	r_cons_printf (core->cons, "literals: %u\n", n);
	for (u32 i = 0; i < n; i++) {
		const HBCLiteralEntry *e = &arr[i];
		r_cons_printf (core->cons,
			"%-6s n=%-4u id=(%u,%u) paddr=0x%08x xrefs=%u  %s\n",
			kind_label (e->kind), e->num_items, e->primary_id,
			e->secondary_id, e->paddr, e->xref_count,
			e->formatted? e->formatted: "");
	}
}

static void cmd_lit_scan_code(HbcContext *ctx, RCore *core) {
	HBC *hbc = NULL;
	Result r = ensure_hbc_loaded (ctx, core, &hbc);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (r.error_message));
		return;
	}
	u32 n = 0;
	r = hbc_literals_scan_code (hbc, &n);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("scan failed: %s", safe_errmsg (r.error_message));
		return;
	}
	register_all_artifacts (core, hbc);
	r_cons_printf (core->cons, "scanned code, %u distinct literals (flags + xrefs registered)\n", n);
}

static void cmd_lit_scan_pool(HbcContext *ctx, RCore *core, HBCLiteralKind kind) {
	HBC *hbc = NULL;
	Result r = ensure_hbc_loaded (ctx, core, &hbc);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (r.error_message));
		return;
	}
	HBCPoolGroup *groups = NULL;
	u32 n = 0;
	r = hbc_literals_scan_pool (hbc, kind, &groups, &n);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("pool scan failed: %s", safe_errmsg (r.error_message));
		return;
	}
	r_cons_printf (core->cons, "%s pool: %u groups\n", kind_label (kind), n);
	for (u32 i = 0; i < n; i++) {
		r_cons_printf (core->cons,
			"  paddr=0x%08x pool_off=0x%08x n=%-4u tag=%u\n",
			groups[i].paddr, groups[i].pool_offset, groups[i].num_items,
			groups[i].tag);
	}
	free (groups);
}

static void cmd_lit_reset(HbcContext *ctx, RCore *core) {
	HBC *hbc = NULL;
	Result r = ensure_hbc_loaded (ctx, core, &hbc);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (r.error_message));
		return;
	}
	hbc_literals_reset (hbc);
	r_cons_println (core->cons, "literal cache reset (r2 flags/comments/xrefs kept — use 'f- lit.*' to drop)");
}

static void cmd_lit_get(HbcContext *ctx, RCore *core, const char *args) {
	HBC *hbc = NULL;
	Result r = ensure_hbc_loaded (ctx, core, &hbc);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (r.error_message));
		return;
	}
	/* Syntax: pd:hLg a <num> <array_id>        (array)
	 *         pd:hLg o <num> <primary> [<sec>] (object)  */
	char kindc = 0;
	u64 num = 0, primary = 0, secondary = 0;
	if (!args || sscanf (args, " %c %" SCNu64 " %" SCNu64 " %" SCNu64,
			&kindc, &num, &primary, &secondary) < 3) {
		R_LOG_ERROR ("usage: pd:hLg {a|o} <num_items> <primary_id> [<secondary_id>]");
		return;
	}
	HBCLiteralKind kind = (kindc == 'a')? HBC_LIT_ARRAY: HBC_LIT_OBJECT;
	char *text = NULL;
	r = hbc_literals_format_raw (hbc, kind, (u32)num, (u32)primary,
		(u32)secondary, &text);
	if (r.code != RESULT_SUCCESS || !text) {
		R_LOG_ERROR ("format failed: %s", safe_errmsg (r.error_message));
		free (text);
		return;
	}
	r_cons_println (core->cons, text);
	free (text);
}

static void cmd_lit_toggle_inline(RCore *core) {
	bool cur = hbc_get_inline_literals ();
	bool next = !cur;
	hbc_set_inline_literals (next);
	r_config_set_b (core->config, "hbc.inline_buffer_literals", next);
	r_cons_printf (core->cons, "inline buffer literals: %s\n", next? "on": "off");
}

static const char LIT_HELP[] =
	"Usage: pd:hL[subcmd]\n"
	" pd:hL            List cached literals\n"
	" pd:hLj           List as JSON\n"
	" pd:hLs           Scan all code; register literals as flags/xrefs/comments\n"
	" pd:hLp[ao]       Scan SLP pool (default: arrays; a=arrays, o=objects)\n"
	" pd:hLr           Reset literal cache (does not remove r2 flags/comments)\n"
	" pd:hLg <k> <n> <primary> [<sec>]\n"
	"                  Format a literal from raw params (k=a|o)\n"
	" pd:hLi           Toggle inline literal comments in disasm\n"
	" pd:hL?           This help\n";

static void cmd_literals(HbcContext *ctx, RCore *core, const char *arg) {
	while (*arg && isspace ((unsigned char)*arg)) {
		arg++;
	}
	switch (*arg) {
	case 0:
		cmd_lit_list (ctx, core, false);
		break;
	case 'j':
		cmd_lit_list (ctx, core, true);
		break;
	case 's':
		cmd_lit_scan_code (ctx, core);
		break;
	case 'p': {
		char k = arg[1];
		HBCLiteralKind kind = (k == 'o')? HBC_LIT_OBJECT: HBC_LIT_ARRAY;
		cmd_lit_scan_pool (ctx, core, kind);
		break;
	}
	case 'r':
		cmd_lit_reset (ctx, core);
		break;
	case 'g':
		cmd_lit_get (ctx, core, arg + 1);
		break;
	case 'i':
		cmd_lit_toggle_inline (core);
		break;
	case '?':
		r_cons_print (core->cons, LIT_HELP);
		break;
	default:
		R_LOG_ERROR ("Unknown subcommand. Use pd:hL? for help");
		break;
	}
}

/* Show help */
static void cmd_help(RCore *core) {
	r_cons_print (core->cons,
		"Usage: pd:h[subcommand]\n"
		"Hermes bytecode decompiler via libhbc\n\n"
		"Subcommands:\n"
		"  pd:h           - Decompile function at current offset (or all if not in function)\n"
		"  pd:hc [id]     - Decompile function by id\n"
		"  pd:ha          - Decompile all functions\n"
		"  pd:hf          - List all functions\n"
		"  pd:hi          - Show file information\n"
		"  pd:hj [id]     - JSON output for function\n"
		"  pd:ho [id]     - Decompile with offsets (addresses) per statement\n"
		"  pd:hoa         - Decompile all with offsets\n"
		"  pd:hL[?]       - SLP literal cache: list/scan/reset (see pd:hL?)\n"
		"  pd:h?          - Show this help\n"
		"\nNote: r2 comments (CC command) are automatically inlined in decompiler output.\n");
}

/* Main handler for pd:h commands */
static bool cmd_handler(RCorePluginSession *s, const char *input) {
	RCore *core = s? s->core: NULL;

	if (!core || !input) {
		return false;
	}
	if (!r_str_startswith (input, "pd:h")) {
		return false;
	}
	HbcContext *ctx = s->data;
	if (!ctx) {
		return false;
	}

	const char *arg = input + 4;

	switch (*arg) {
	case '\0': /* pd:h */
	case ' ': /* pd:h (with spaces) */
		if (*arg == ' ' && arg[1] != '\0' && !isspace ((unsigned char)arg[1])) {
			R_LOG_ERROR ("Unknown subcommand. Use pd:h? for help");
			break;
		}
		cmd_decompile_current_ex (ctx, core, false);
		break;
	case 'a': /* pd:ha */
		cmd_decompile_all_ex (ctx, core, false);
		break;
	case 'c': /* pd:hc [id] */
		cmd_decompile_function_ex (ctx, core, arg + 1, false);
		break;
	case 'f': /* pd:hf */
		cmd_list_functions (ctx, core);
		break;
	case 'i': /* pd:hi */
		cmd_file_info (ctx, core);
		break;
	case 'j': { /* pd:hj [id] */
		const char *addr_str = arg + 1;
		while (*addr_str && isspace ((unsigned char)*addr_str)) {
			addr_str++;
		}
		cmd_json (ctx, core, addr_str);
		break;
	}
	case 'o': { /* pd:ho [id] or pd:hoa */
		const char *sub = arg + 1;
		if (*sub == 'a') { // "pd:hoa"
			cmd_decompile_all_ex (ctx, core, true);
		} else { // "pd:ho" [id]
			while (*sub && isspace ((unsigned char)*sub)) {
				sub++;
			}
			if (*sub) {
				cmd_decompile_function_ex (ctx, core, sub, true);
			} else {
				cmd_decompile_current_ex (ctx, core, true);
			}
		}
		break;
	}
	case 'L': /* pd:hL* — literal cache / buffer-literal commands */
		cmd_literals (ctx, core, arg + 1);
		break;
	case '?': /* pd:h? */
		cmd_help (core);
		break;
	default:
		R_LOG_ERROR ("Unknown subcommand. Use pd:h? for help");
		break;
	}

	return true;
}

static bool cb_inline_buffer_literals(void *user, void *data) {
	(void)user;
	RConfigNode *node = (RConfigNode *)data;
	hbc_set_inline_literals (node && node->i_value);
	return true;
}

static bool plugin_init(RCorePluginSession *s) {
	RCore *core = s->core;
	RConfig *cfg = core->config;

	HbcContext *ctx = R_NEW0 (HbcContext);
	ctx->core = core;
	s->data = ctx;

#ifdef HBC_CORE_REGISTER_PLUGINS
	/* Register arch, bin and asm plugins when enabled */
	if (core->anal && core->anal->arch) {
		r_arch_plugin_add (core->anal->arch, (RArchPlugin *)&r_arch_plugin_r2hermes);
	}
	if (core->bin) {
		r_bin_plugin_add (core->bin, (RBinPlugin *)&r_bin_plugin_r2hermes);
	}
	if (core->rasm) {
		r_asm_plugin_add (core->rasm, (RAsmPlugin *)&r_asm_plugin_r2hermes);
	}
#endif

	/* Define fix-hbc macro using r2's generic ph and wx commands
	 * 1. Resize file to fileLength+20 (using $ () for nested eval)
	 * 2. Write SHA1 hash of bytes 0 to ($s-20) at offset ($s-20) */
	r_core_cmd0 (core, "'(fix-hbc; ?e Fixing HBC footer hash...; r `?vi $(pv4 @32)+20`; wx `ph sha1 $s-20 @0` @ $s-20)");

	r_config_lock (cfg, false);

	RConfigNode *node = r_config_set (cfg, "hbc.pretty_literals", "true");
	if (node) {
		r_config_node_desc (node, "Format literals nicely (objects, arrays, etc)");
	}

	node = r_config_set (cfg, "hbc.suppress_comments", "false");
	if (node) {
		r_config_node_desc (node, "Omit comments in decompiled output");
	}

	node = r_config_set (cfg, "hbc.show_offsets", "false");
	if (node) {
		r_config_node_desc (node, "Show bytecode offsets for each statement");
	}

	/* Optimization/transformation pass control */
	node = r_config_set (cfg, "hbc.skip_pass1", "false");
	if (node) {
		r_config_node_desc (node, "Skip pass 1: metadata collection (closure/generator/async flags)");
	}

	node = r_config_set (cfg, "hbc.skip_pass2", "false");
	if (node) {
		r_config_node_desc (node, "Skip pass 2: code transformation to tokens and statements");
	}

	node = r_config_set (cfg, "hbc.skip_pass3", "false");
	if (node) {
		r_config_node_desc (node, "Skip pass 3: for-in loop parsing (structural recovery via CFG)");
	}

	node = r_config_set (cfg, "hbc.skip_pass4", "false");
	if (node) {
		r_config_node_desc (node, "Skip pass 4: closure variable naming and environment resolution");
	}

	/* Control flow rendering options */
	node = r_config_set (cfg, "hbc.force_dispatch", "false");
	if (node) {
		r_config_node_desc (node, "Force switch/case dispatch loop even for linear multi-block functions");
	}

	node = r_config_set (cfg, "hbc.inline_closures", "true");
	if (node) {
		r_config_node_desc (node, "Inline closure definitions into parent function (true/false)");
	}

	node = r_config_set (cfg, "hbc.inline_threshold", "0");
	if (node) {
		r_config_node_desc (node, "Max bytecode size (bytes) for closure inlining (0=no limit, -1=never inline)");
	}

	node = r_config_set_i (cfg, "hbc.max_ast", 5000);
	if (node) {
		r_config_node_desc (node, "Abort AST build once N statements per function (0=unlimited)");
	}

	node = r_config_set_i (cfg, "hbc.max_bytes", 262144);
	if (node) {
		r_config_node_desc (node, "Stop decompilation once total output reaches N bytes (0=unlimited)");
	}

	/* Default off: inlining the SLP literal as a disasm-line comment makes
	 * arch.decode O(n) in literal size. Use pd:hL* to inspect literals
	 * without impacting disasm speed. */
	hbc_set_inline_literals (false);
	node = r_config_set_b_cb (cfg, "hbc.inline_buffer_literals", false, cb_inline_buffer_literals);
	if (node) {
		r_config_node_desc (node, "Inline SLP buffer literals as comments in disasm (slow; default off)");
	}

	r_config_lock (cfg, true);
	return true;
}

static bool plugin_fini(RCorePluginSession *s) {
	HbcContext *ctx = s->data;
	if (ctx) {
		hbc_safe_close (&ctx->hbc);
		R_FREE (ctx->file_path);
		free (ctx);
		s->data = NULL;
	}
	return true;
}

/* Plugin initialization */
RCorePlugin r_core_plugin_r2hermes = {
	.meta = {
		.name = "core_hbc",
		.desc = "Hermes bytecode decompiler plugin",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.call = cmd_handler,
	.init = plugin_init,
	.fini = plugin_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = (void *)&r_core_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
