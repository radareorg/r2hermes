/* radare2 - LGPL - Copyright 2025-2026 - pancake */

/* r2 core plugin for Hermes bytecode decompilation */

#include <r_core.h>
#include <hbc/hbc.h>

typedef struct {
	HBC *hbc; /* Cached HBC data provider per file */
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

#define HBC_PRINTF(core, fmt, ...) r_cons_printf(core->cons,(fmt), ## __VA_ARGS__)
#define HBC_PRINT(core, s) r_cons_print(core->cons,(s))

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
	if (ctx->hbc) {
		hbc_free (ctx->hbc);
		ctx->hbc = NULL;
	}
	free (ctx->file_path);
	ctx->file_path = NULL;

	/* Get RBinFile from r2 (already parsed by r2) */
	RBinFile *bf = core->bin->cur;
	if (!bf) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No binary file loaded or r2 version incompatible");
	}

	/* Create provider from r2 RBinFile (NO file I/O) */
	ctx->hbc = hbc_new_r2 (bf);
	if (!ctx->hbc) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to create provider");
	}

	ctx->core = core;
	ctx->file_path = strdup (file_path);
	if (!ctx->file_path) {
		hbc_free (ctx->hbc);
		ctx->hbc = NULL;
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}
	return SUCCESS_RESULT ();
}

/* Find function ID at a given offset */
static int find_function_at_offset(HbcContext *ctx, u32 offset, u32 *out_id) {
	if (!out_id || !ctx->hbc) {
		return -1;
	}
	u32 count;
	Result res = hbc_func_count (ctx->hbc, &count);
	if (res.code == RESULT_SUCCESS) {
		for (u32 i = 0; i < count; i++) {
			HBCFunc fi;
			res = hbc_func_info (ctx->hbc, i, &fi);
			if (res.code == RESULT_SUCCESS) {
				if (offset >= fi.offset && offset < (fi.offset + fi.size)) {
					*out_id = i;
					return 0;
				}
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
		.inline_threshold = r_config_get_i (core->config, "hbc.inline_threshold")
	};
	return opts;
}

/* Decompile function at current offset or all functions if not in a function */
static void cmd_decompile_current_ex(HbcContext *ctx, RCore *core, bool show_offsets) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (res.error_message));
		return;
	}

	u32 function_id = 0;
	/* Get current offset from r2 core */
	int found = find_function_at_offset (ctx, (u32)core->addr, &function_id);

	if (found == 0) {
		/* Found function at current offset - get its base address */
		HBCFunc fi;
		Result fres = hbc_func_info (ctx->hbc, function_id, &fi);
		u64 func_base = (fres.code == RESULT_SUCCESS)? fi.offset: 0;
		HBCDecompOptions opts = make_decompile_options (core, show_offsets, func_base);
		char *output = NULL;
		res = hbc_decomp_fn (ctx->hbc, function_id, opts, &output);
		if (res.code == RESULT_SUCCESS && output) {
			r_str_trim (output);
			HBC_PRINTF (core, "%s\n", output);
		} else {
			HBC_PRINTF (core, "Error decompiling function %u: %s\n", function_id, safe_errmsg (res.error_message));
		}
		free (output);
	} else {
		/* Not in a function, decompile all - use 0 as base since multiple functions */
		HBCDecompOptions opts = make_decompile_options (core, show_offsets, 0);
		char *output = NULL;
		res = hbc_decomp_all (ctx->hbc, opts, &output);
		if (res.code == RESULT_SUCCESS && output) {
			r_str_trim (output);
			HBC_PRINTF (core, "%s\n", output);
		} else {
			HBC_PRINTF (core, "Error decompiling: %s\n", safe_errmsg (res.error_message));
		}
		free (output);
	}
}

/* Decompile all functions */
static void cmd_decompile_all_ex(HbcContext *ctx, RCore *core, bool show_offsets) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (res.error_message));
		return;
	}

	HBCDecompOptions opts = make_decompile_options (core, show_offsets, 0);
	char *output = NULL;
	res = hbc_decomp_all (ctx->hbc, opts, &output);
	if (res.code == RESULT_SUCCESS && output) {
		r_str_trim (output);
		HBC_PRINTF (core, "%s\n", output);
	} else {
		HBC_PRINTF (core, "Error decompiling: %s\n", safe_errmsg (res.error_message));
	}
	free (output);
}

/* Decompile current function by address */
static void cmd_decompile_function_ex(HbcContext *ctx, RCore *core, const char *addr_str, bool show_offsets) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (res.error_message));
		return;
	}
	u32 function_id = parse_function_id (addr_str);
	u32 count;
	res = hbc_func_count (ctx->hbc, &count);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: cannot get function count\n");
		return;
	}
	if (function_id >= count) {
		HBC_PRINTF (core, "Error: function id %u out of range (count=%u)\n", function_id, count);
		return;
	}
	/* Get function base address for offset calculation */
	HBCFunc fi;
	Result fres = hbc_func_info (ctx->hbc, function_id, &fi);
	u64 func_base = (fres.code == RESULT_SUCCESS)? fi.offset: 0;
	HBCDecompOptions opts = make_decompile_options (core, show_offsets, func_base);
	char *output = NULL;
	res = hbc_decomp_fn (ctx->hbc, function_id, opts, &output);
	if (res.code == RESULT_SUCCESS && output) {
		r_str_trim (output);
		HBC_PRINTF (core, "%s\n", output);
	} else {
		HBC_PRINTF (core, "Error decompiling function %u: %s\n", function_id, safe_errmsg (res.error_message));
	}
	free (output);
}

/* List available functions */
static void cmd_list_functions(HbcContext *ctx, RCore *core) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (res.error_message));
		return;
	}

	u32 count;
	res = hbc_func_count (ctx->hbc, &count);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: cannot get function count\n");
		return;
	}
	HBC_PRINTF (core, "Functions (%u):\n", count);

	for (u32 i = 0; i < count; i++) {
		HBCFunc info;
		Result res = hbc_func_info (ctx->hbc, i, &info);
		if (res.code == RESULT_SUCCESS) {
			HBC_PRINTF (core, "  [%3u] %s at 0x%08x size=0x%x params=%u\n", i,
					r_str_get_fail (info.name, "unknown"),
					info.offset, info.size, info.param_count);
		}
	}
}

/* Show file information */
static void cmd_file_info(HbcContext *ctx, RCore *core) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (res.error_message));
		return;
	}

	HBCHeader header;
       	res = hbc_hdr (ctx->hbc, &header);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error reading header: %s\n", safe_errmsg (res.error_message));
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
			"  Source Hash (header): %s\n", hex);
	const ut64 file_size = r_io_size (core->io);
	const ut64 expected_size = (ut64)header.fileLength + 20;

	r_cons_printf (cons, "  File size: %"PFMT64u" bytes\n", file_size);
	r_cons_printf (cons, "  Header fileLength: %u bytes\n", header.fileLength);

	if (file_size >= expected_size) {
		/* Footer exists or file has extra bytes - read and verify */
		ut8 footer[20] = { 0 };
		r_io_read_at (core->io, header.fileLength, footer, 20);
		r_hex_bin2str (footer, 20, hex);
		HBC_PRINTF (core, "  Footer Hash (stored): %s\n", hex);

		char *computed = r_core_cmd_strf (core, "ph sha1 %u @0", header.fileLength);
		if (computed) {
			r_str_trim (computed);
			HBC_PRINTF (core, "  Footer Hash (computed): %s\n", computed);
			bool valid = (strlen (computed) == 40 && !strcmp (computed, hex));
			HBC_PRINTF (core, "  Status: %s\n", valid? "VALID": "INVALID");
			if (!valid || file_size != expected_size) {
				HBC_PRINTF (core, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
			}
			if (file_size > expected_size) {
				HBC_PRINTF (core, "  Warning: File has %"PFMT64u" extra bytes after footer\n",
					file_size - expected_size);
			}
			free (computed);
		}
	} else if (file_size == (ut64)header.fileLength && file_size >= 20) {
		/* fileLength == file_size: Check if last 20 bytes are a valid footer
		 * (some versions include footer in fileLength) */
		ut64 content_size = file_size - 20;
		ut8 footer[20] = { 0 };
		r_io_read_at (core->io, content_size, footer, 20);
		r_hex_bin2str (footer, 20, hex);

		char *computed = r_core_cmd_strf (core, "ph sha1 %"PFMT64u" @0", content_size);
		if (computed) {
			r_str_trim (computed);
			bool valid = (strlen (computed) == 40 && !strcmp (computed, hex));
			if (valid) {
				HBC_PRINTF (core, "  Footer Hash (stored): %s\n", hex);
				HBC_PRINTF (core, "  Footer Hash (computed): %s\n", computed);
				HBC_PRINTF (core, "  Status: VALID (footer included in fileLength)\n");
			} else {
				HBC_PRINTF (core, "  Footer: NOT PRESENT (file ends at fileLength)\n");
				HBC_PRINTF (core, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
			}
			free (computed);
		} else {
			HBC_PRINTF (core, "  Footer: NOT PRESENT (file ends at fileLength)\n");
			HBC_PRINTF (core, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
		}
	} else {
		HBC_PRINTF (core, "  Footer: UNKNOWN (file size mismatch)\n");
		HBC_PRINTF (core, "  Expected: %"PFMT64u" or %u bytes, got %"PFMT64u"\n",
			expected_size, header.fileLength, file_size);
		HBC_PRINTF (core, "  Fix: .(fix-hbc)  or  r2 -wqc '.(fix-hbc)' file.hbc\n");
	}
}

/* JSON output for current function */
static void cmd_json(HbcContext *ctx, RCore *core, const char *addr_str) {
	Result res = hbc_load_current_binary (ctx, core);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "{\"error\":\"%s\"}\n", safe_errmsg (res.error_message));
		return;
	}

	u32 function_id = parse_function_id (addr_str);
	HBCDecompOptions opts = { .pretty_literals = true, .suppress_comments = false };
	u32 count;
	res = hbc_func_count (ctx->hbc, &count);
	if (res.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "{\"error\":\"cannot get function count\"}\n");
		return;
	}
	if (function_id >= count) {
		HBC_PRINTF (core, "{\"function_id\":%u,\"decompilation\":null,\"error\":\"function id out of range\",\"count\":%u}\n", function_id, count);
		return;
	}
	char *output = NULL;
	res = hbc_decomp_fn (ctx->hbc, function_id, opts, &output);

	PJ *pj = r_core_pj_new (core);
	pj_o (pj);
	pj_kn (pj, "function_id", function_id);
	pj_k (pj, "decompilation");
	if (res.code == RESULT_SUCCESS && output) {
		pj_s (pj, output);
	} else {
		pj_null (pj);
	}
	pj_end (pj);
	char *s = pj_drain (pj);
	r_cons_println (core->cons, s);
	free (s);
	free (output);
}

/* Show help */
static void cmd_help(RCore *core) {
	HBC_PRINT (core,
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
			HBC_PRINT (core, "Unknown subcommand. Use pd:h? for help.\n");
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
	case '?': /* pd:h? */
		cmd_help (core);
		break;
	default:
		HBC_PRINT (core, "Unknown subcommand. Use pd:h? for help.\n");
		break;
	}

	return true;
}

static bool plugin_init(RCorePluginSession *s) {
	RCore *core = s->core;
	RConfig *cfg = core->config;

	HbcContext *ctx = R_NEW0 (HbcContext);
	ctx->core = core;
	s->data = ctx;

	/* Define fix-hbc macro using r2's generic ph and wx commands
	 * 1. Resize file to fileLength+20 (using $() for nested eval)
	 * 2. Write SHA1 hash of bytes 0 to ($s-20) at offset ($s-20) */
	r_core_cmd0 (core, "'(fix-hbc; ?e Fixing HBC footer hash...; r `?vi $(pv4 @32)+20`; wx `ph sha1 $s-20 @0` @ $s-20)");

	r_config_lock (cfg, false);

	RConfigNode *node;
	node = r_config_set (cfg, "hbc.pretty_literals", "true");
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

	r_config_lock (cfg, true);
	return true;
}

static bool plugin_fini(RCorePluginSession *s) {
	HbcContext *ctx = s->data;
	if (ctx) {
		hbc_free (ctx->hbc);
		ctx->hbc = NULL;
		ctx->core = NULL;
		R_FREE (ctx->file_path);
		free (ctx);
		s->data = NULL;
	}
	return true;
}

/* Plugin initialization */
static RCorePlugin r_core_plugin_r2hermes = {
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
	.data = &r_core_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
