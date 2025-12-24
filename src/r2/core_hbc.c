/* radare2 - LGPL - Copyright 2025 - pancake */
/* r2 core plugin for Hermes bytecode decompilation */

#include <r_core.h>
#include <r_util.h>
#include <r_lib.h>
#include <hbc/hbc.h>
#include <hbc/data_provider.h>
#include <hbc/decompilation/decompiler.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifndef R2_VERSION
#define R2_VERSION "6.0.3"
#endif

/* r2 functions - weak symbol to handle different r2 versions */
extern RBinFile *r_bin_file_cur(RBin *bin) __attribute__((weak));

/**
 * Safe wrapper for r_bin_file_cur that handles weak symbol resolution.
 * Falls back to directly accessing bin->cur if r_bin_file_cur is not available.
 */
static RBinFile *safe_r_bin_file_cur(RBin *bin) {
	if (r_bin_file_cur) {
		return r_bin_file_cur (bin);
	}
	/* Fallback: use bin->cur directly (available in r_bin_t struct) */
	if (bin) {
		/* struct r_bin_t { const char *file; RBinFile *cur; ... } */
		return ((struct r_bin_t *)bin)->cur;
	}
	return NULL;
}

typedef struct {
	HBCDataProvider *provider; /* Cached provider per file */
	RCore *core;
	char *file_path;
} HbcContext;

static HbcContext hbc_ctx = {
	.provider = NULL,
	.core = NULL,
	.file_path = NULL
};

static const char *safe_errmsg(const char *s) {
	return (s && *s)? s: "Unknown error";
}

static const char *safe_name(const char *s) {
	return (s && *s)? s: "unknown";
}

/* Comment callback for retrieving r2 comments (CC command) at an address */
static char *r2_comment_callback(void *context, u64 address) {
	RCore *core = (RCore *)context;
	if (!core) {
		return NULL;
	}
	const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address);
	if (comment) {
		hbc_debug_printf ("[r2_comment_callback] Found comment at 0x%llx: %s\n", (unsigned long long)address, comment);
	}
	return comment? strdup (comment): NULL;
}

/* Flag callback for retrieving r2 flag/symbol names at an address */
static char *r2_flag_callback(void *context, u64 address) {
	RCore *core = (RCore *)context;
	if (!core || !core->flags) {
		return NULL;
	}
	RFlagItem *fi = r_flag_get_at (core->flags, address, true);
	if (fi && fi->name) {
		return strdup (fi->name);
	}
	return NULL;
}

#define HBC_CONS(core) ((core)->cons)
#define HBC_PRINTF(core, fmt, ...) r_cons_printf(HBC_CONS(core),(fmt), ## __VA_ARGS__)
#define HBC_PRINT(core, s) r_cons_print(HBC_CONS(core),(s))

static const char *current_file_path(RCore *core) {
	if (!core || !core->bin) {
		return NULL;
	}
	RBinInfo *bi = r_bin_get_info (core->bin);
	return bi? bi->file: NULL;
}

/* Helper to load the current binary as HBC using provider API */
static Result hbc_load_current_binary(RCore *core) {
	const char *file_path = current_file_path (core);
	if (!file_path || !*file_path) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No binary loaded in r2");
	}

	/* Reload if file changed */
	if (hbc_ctx.provider && hbc_ctx.file_path && !strcmp (hbc_ctx.file_path, file_path)) {
		return SUCCESS_RESULT ();
	}

	/* Clean up old provider */
	if (hbc_ctx.provider) {
		hbc_free (hbc_ctx.provider);
		hbc_ctx.provider = NULL;
	}
	free (hbc_ctx.file_path);
	hbc_ctx.file_path = NULL;

	/* Get RBinFile from r2 (already parsed by r2) */
	RBinFile *bf = safe_r_bin_file_cur (core->bin);
	if (!bf) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No binary file loaded or r2 version incompatible");
	}

	/* Create provider from r2 RBinFile (NO file I/O) */
	hbc_ctx.provider = hbc_new_r2 (bf);
	if (!hbc_ctx.provider) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to create provider");
	}

	hbc_ctx.core = core;
	hbc_ctx.file_path = strdup (file_path);
	if (!hbc_ctx.file_path) {
		hbc_free (hbc_ctx.provider);
		hbc_ctx.provider = NULL;
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}
	return SUCCESS_RESULT ();
}

/* Find function ID at a given offset */
static int find_function_at_offset(u32 offset, u32 *out_id) {
	if (!out_id || !hbc_ctx.provider) {
		return -1;
	}
	u32 count;
	Result res = hbc_func_count (hbc_ctx.provider, &count);
	if (res.code == RESULT_SUCCESS) {
		for (u32 i = 0; i < count; i++) {
			HBCFunctionInfo fi;
			res = hbc_func_info (hbc_ctx.provider, i, &fi);
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

/* Create decompile options with r2 integration */
static HBCDecompileOptions make_decompile_options(RCore *core, bool show_offsets, u64 function_base) {
	HBCDecompileOptions opts = {
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
static void cmd_decompile_current_ex(RCore *core, bool show_offsets) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	u32 function_id = 0;
	/* Get current offset from r2 core */
	int found = find_function_at_offset ((u32)core->addr, &function_id);

	if (found == 0) {
		/* Found function at current offset - get its base address */
		HBCFunctionInfo fi;
		Result fres = hbc_func_info (hbc_ctx.provider, function_id, &fi);
		u64 func_base = (fres.code == RESULT_SUCCESS)? fi.offset: 0;
		HBCDecompileOptions opts = make_decompile_options (core, show_offsets, func_base);
		StringBuffer output = { 0 };
		_hbc_string_buffer_init (&output, 4096);
		result = _hbc_decompile_function_with_provider (hbc_ctx.provider, function_id, opts, &output);
		if (result.code == RESULT_SUCCESS && output.data) {
			r_str_trim (output.data);
			HBC_PRINTF (core, "%s\n", output.data);
		} else {
			HBC_PRINTF (core, "Error decompiling function %u: %s\n", function_id, safe_errmsg (result.error_message));
		}
		_hbc_string_buffer_free (&output);
	} else {
		/* Not in a function, decompile all - use 0 as base since multiple functions */
		HBCDecompileOptions opts = make_decompile_options (core, show_offsets, 0);
		StringBuffer output = { 0 };
		_hbc_string_buffer_init (&output, 4096);
		result = _hbc_decompile_all_with_provider (hbc_ctx.provider, opts, &output);
		if (result.code == RESULT_SUCCESS && output.data) {
			r_str_trim (output.data);
			HBC_PRINTF (core, "%s\n", output.data);
		} else {
			HBC_PRINTF (core, "Error decompiling: %s\n", safe_errmsg (result.error_message));
		}
		_hbc_string_buffer_free (&output);
	}
}

static void cmd_decompile_current(RCore *core) {
	cmd_decompile_current_ex (core, false);
}

/* Decompile all functions */
static void cmd_decompile_all_ex(RCore *core, bool show_offsets) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	HBCDecompileOptions opts = make_decompile_options (core, show_offsets, 0);
	StringBuffer output = { 0 };
	_hbc_string_buffer_init (&output, 8192);
	result = _hbc_decompile_all_with_provider (hbc_ctx.provider, opts, &output);
	if (result.code == RESULT_SUCCESS && output.data) {
		r_str_trim (output.data);
		HBC_PRINTF (core, "%s\n", output.data);
	} else {
		HBC_PRINTF (core, "Error decompiling: %s\n", safe_errmsg (result.error_message));
	}
	_hbc_string_buffer_free (&output);
}

static void cmd_decompile_all(RCore *core) {
	cmd_decompile_all_ex (core, false);
}

/* Decompile current function by address */
static void cmd_decompile_function_ex(RCore *core, const char *addr_str, bool show_offsets) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	u32 function_id = 0;
	if (addr_str && *addr_str) {
		char *end = NULL;
		unsigned long parsed = strtoul (addr_str, &end, 0);
		if (!end || end == addr_str) {
			HBC_PRINTF (core, "Error: invalid function id '%s'\n", addr_str);
			return;
		}
		function_id = (u32)parsed;
	}

	u32 count;
	result = hbc_func_count (hbc_ctx.provider, &count);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: cannot get function count\n");
		return;
	}
	if (function_id >= count) {
		HBC_PRINTF (core, "Error: function id %u out of range (count=%u)\n", function_id, count);
		return;
	}
	/* Get function base address for offset calculation */
	HBCFunctionInfo fi;
	Result fres = hbc_func_info (hbc_ctx.provider, function_id, &fi);
	u64 func_base = (fres.code == RESULT_SUCCESS)? fi.offset: 0;
	HBCDecompileOptions opts = make_decompile_options (core, show_offsets, func_base);
	StringBuffer output = { 0 };
	_hbc_string_buffer_init (&output, 4096);
	result = _hbc_decompile_function_with_provider (hbc_ctx.provider, function_id, opts, &output);
	if (result.code == RESULT_SUCCESS && output.data) {
		r_str_trim (output.data);
		HBC_PRINTF (core, "%s\n", output.data);
	} else {
		HBC_PRINTF (core, "Error decompiling function %u: %s\n", function_id, safe_errmsg (result.error_message));
	}
	_hbc_string_buffer_free (&output);
}

static void cmd_decompile_function(RCore *core, const char *addr_str) {
	cmd_decompile_function_ex (core, addr_str, false);
}

/* List available functions */
static void cmd_list_functions(RCore *core) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	u32 count;
	result = hbc_func_count (hbc_ctx.provider, &count);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: cannot get function count\n");
		return;
	}
	HBC_PRINTF (core, "Functions (%u):\n", count);

	for (u32 i = 0; i < count; i++) {
		HBCFunctionInfo info;
		Result res = hbc_func_info (hbc_ctx.provider, i, &info);
		if (res.code == RESULT_SUCCESS) {
			HBC_PRINTF (core, "  [%3u] %s at 0x%08x size=0x%x params=%u\n", i, safe_name (info.name), info.offset, info.size, info.param_count);
		}
	}
}

/* Show file information */
static void cmd_file_info(RCore *core) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	HBCHeader header;
	result = hbc_hdr (hbc_ctx.provider, &header);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error reading header: %s\n", safe_errmsg (result.error_message));
		return;
	}

	HBC_PRINTF (core,
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
}

/* JSON output for current function */
static void cmd_json(RCore *core, const char *addr_str) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "{\"error\":\"%s\"}\n", safe_errmsg (result.error_message));
		return;
	}

	u32 function_id = 0;
	if (addr_str && *addr_str) {
		char *end = NULL;
		unsigned long parsed = strtoul (addr_str, &end, 0);
		if (!end || end == addr_str) {
			HBC_PRINT (core, "{\"error\":\"invalid function id\"}\n");
			return;
		}
		function_id = (u32)parsed;
	}

	HBCDecompileOptions opts = { .pretty_literals = true, .suppress_comments = false };
	u32 count;
	result = hbc_func_count (hbc_ctx.provider, &count);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "{\"error\":\"cannot get function count\"}\n");
		return;
	}
	if (function_id >= count) {
		HBC_PRINTF (core, "{\"function_id\":%u,\"decompilation\":null,\"error\":\"function id out of range\",\"count\":%u}\n", function_id, count);
		return;
	}
	StringBuffer output = { 0 };
	_hbc_string_buffer_init (&output, 4096);
	result = _hbc_decompile_function_with_provider (hbc_ctx.provider, function_id, opts, &output);

	RStrBuf *sb = r_strbuf_newf ("{\"function_id\":%u,\"decompilation\":", function_id);
	if (!sb) {
		_hbc_string_buffer_free (&output);
		HBC_PRINT (core, "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (result.code == RESULT_SUCCESS && output.data) {
		r_strbuf_append (sb, "\"");
		for (const char *p = output.data; *p; p++) {
			const unsigned char ch = (unsigned char)*p;
			switch (ch) {
			case '"':
				r_strbuf_append (sb, "\\\"");
				break;
			case '\\':
				r_strbuf_append (sb, "\\\\");
				break;
			case '\n':
				r_strbuf_append (sb, "\\n");
				break;
			case '\r':
				r_strbuf_append (sb, "\\r");
				break;
			case '\t':
				r_strbuf_append (sb, "\\t");
				break;
			default:
				if (ch < 0x20) {
					r_strbuf_appendf (sb, "\\u%04x", (unsigned int)ch);
				} else {
					r_strbuf_appendf (sb, "%c", (char)ch);
				}
				break;
			}
		}
		r_strbuf_append (sb, "\"");
	} else {
		r_strbuf_append (sb, "null");
	}
	r_strbuf_append (sb, "}\n");
	HBC_PRINT (core, r_strbuf_get (sb));
	r_strbuf_free (sb);
	_hbc_string_buffer_free (&output);
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

	const char *arg = input + 4;

	switch (*arg) {
	case '\0': /* pd:h */
	case ' ':  /* pd:h (with spaces) */
		if (*arg == ' ' && arg[1] != '\0' && !isspace ((unsigned char)arg[1])) {
			HBC_PRINT (core, "Unknown subcommand. Use pd:h? for help.\n");
			break;
		}
		cmd_decompile_current (core);
		break;
	case 'a': /* pd:ha */
		cmd_decompile_all (core);
		break;
	case 'c': { /* pd:hc [id] */
		const char *addr_str = arg + 1;
		while (*addr_str && isspace ((unsigned char)*addr_str)) {
			addr_str++;
		}
		cmd_decompile_function (core, addr_str);
		break;
	}
	case 'f': /* pd:hf */
		cmd_list_functions (core);
		break;
	case 'i': /* pd:hi */
		cmd_file_info (core);
		break;
	case 'j': { /* pd:hj [id] */
		const char *addr_str = arg + 1;
		while (*addr_str && isspace ((unsigned char)*addr_str)) {
			addr_str++;
		}
		cmd_json (core, addr_str);
		break;
	}
	case 'o': { /* pd:ho [id] or pd:hoa */
		const char *sub = arg + 1;
		if (*sub == 'a') {
			/* pd:hoa */
			cmd_decompile_all_ex (core, true);
		} else {
			/* pd:ho [id] */
			while (*sub && isspace ((unsigned char)*sub)) {
				sub++;
			}
			if (*sub) {
				cmd_decompile_function_ex (core, sub, true);
			} else {
				cmd_decompile_current_ex (core, true);
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

static bool plugin_init(struct r_core_plugin_session_t *s) {
	RConfig *cfg = s->core->config;
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

static bool plugin_fini(struct r_core_plugin_session_t *s) {
	(void)s;
	if (hbc_ctx.provider) {
		hbc_free (hbc_ctx.provider);
		hbc_ctx.provider = NULL;
	}
	hbc_ctx.core = NULL;
	free (hbc_ctx.file_path);
	hbc_ctx.file_path = NULL;
	return true;
}

/* Plugin initialization */
static RCorePlugin r_core_plugin_hbc = {
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
	.data = &r_core_plugin_hbc,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
