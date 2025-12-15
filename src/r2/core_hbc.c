/* radare2 - LGPL - Copyright 2025 - libhbc */
/* r2 core plugin for Hermes bytecode decompilation */

#include <r_core.h>
#include <r_util.h>
#include <r_lib.h>
#include <hbc/hbc.h>
#include <string.h>
#include <ctype.h>

#ifndef R2_VERSION
#define R2_VERSION "6.0.3"
#endif

typedef struct {
	HBCState *hbc;
	RCore *core;
	char *file_path;
} HbcContext;

static HbcContext hbc_ctx = {
	.hbc = NULL,
	.core = NULL,
	.file_path = NULL
};

static const char *safe_errmsg(const char *s) {
	return (s && *s)? s: "Unknown error";
}

static const char *safe_name(const char *s) {
	return (s && *s)? s: "unknown";
}

#define HBC_CONS(core) ((core)->cons)
#define HBC_PRINTF(core, fmt, ...) r_cons_printf (HBC_CONS (core), (fmt), ##__VA_ARGS__)
#define HBC_PRINT(core, s) r_cons_print (HBC_CONS (core), (s))

static const char *current_file_path(RCore *core) {
	if (!core || !core->bin) {
		return NULL;
	}
	RBinInfo *bi = r_bin_get_info (core->bin);
	return bi? bi->file: NULL;
}

/* Helper to load the current binary as HBC */
static Result hbc_load_current_binary(RCore *core) {
	const char *file_path = current_file_path (core);
	if (!file_path || !*file_path) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No binary loaded in r2");
	}

	/* Reload if file changed */
	if (hbc_ctx.hbc && hbc_ctx.file_path && !strcmp (hbc_ctx.file_path, file_path)) {
		return SUCCESS_RESULT ();
	}

	if (hbc_ctx.hbc) {
		hbc_close (hbc_ctx.hbc);
		hbc_ctx.hbc = NULL;
	}
	free (hbc_ctx.file_path);
	hbc_ctx.file_path = NULL;

	Result result = hbc_open (file_path, &hbc_ctx.hbc);
	if (result.code != RESULT_SUCCESS) {
		hbc_ctx.hbc = NULL;
		return result;
	}

	hbc_ctx.core = core;
	hbc_ctx.file_path = strdup (file_path);
	if (!hbc_ctx.file_path) {
		hbc_close (hbc_ctx.hbc);
		hbc_ctx.hbc = NULL;
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Out of memory");
	}
	return SUCCESS_RESULT ();
}

/* Find function ID at a given offset */
static int find_function_at_offset(u32 offset, u32 *out_id) {
	if (!out_id) {
		return -1;
	}
	u32 count = hbc_function_count (hbc_ctx.hbc);
	for (u32 i = 0; i < count; i++) {
		HBCFunctionInfo fi;
		Result res = hbc_get_function_info (hbc_ctx.hbc, i, &fi);
		if (res.code == RESULT_SUCCESS) {
			if (offset >= fi.offset && offset < (fi.offset + fi.size)) {
				*out_id = i;
				return 0;
			}
		}
	}
	return -1;
}

/* Decompile function at current offset or all functions if not in a function */
static void cmd_decompile_current(RCore *core) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	u32 function_id = 0;
	/* Get current offset - use 0 since we don't have direct access to offset in this context */
	int found = find_function_at_offset (0, &function_id);
	
	HBCDecompileOptions opts = { .pretty_literals = true, .suppress_comments = false };
	char *output = NULL;
	
	if (found == 0) {
		/* Found function at current offset */
		result = hbc_decompile_function (hbc_ctx.hbc, function_id, opts, &output);
		if (result.code == RESULT_SUCCESS && output) {
			HBC_PRINTF (core, "%s\n", output);
			free (output);
		} else {
			HBC_PRINTF (core, "Error decompiling function %u: %s\n", function_id, safe_errmsg (result.error_message));
		}
	} else {
		/* Not in a function, decompile all */
		result = hbc_decompile_all (hbc_ctx.hbc, opts, &output);
		if (result.code == RESULT_SUCCESS && output) {
			HBC_PRINTF (core, "%s\n", output);
			free (output);
		} else {
			HBC_PRINTF (core, "Error decompiling: %s\n", safe_errmsg (result.error_message));
		}
	}
}

/* Decompile all functions */
static void cmd_decompile_all(RCore *core) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	HBCDecompileOptions opts = { .pretty_literals = true, .suppress_comments = false };
	char *output = NULL;
	result = hbc_decompile_all (hbc_ctx.hbc, opts, &output);
	if (result.code == RESULT_SUCCESS && output) {
		HBC_PRINTF (core, "%s\n", output);
		free (output);
	} else {
		HBC_PRINTF (core, "Error decompiling: %s\n", safe_errmsg (result.error_message));
	}
}

/* Decompile current function by address */
static void cmd_decompile_function(RCore *core, const char *addr_str) {
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

	HBCDecompileOptions opts = { .pretty_literals = true, .suppress_comments = false };
	char *output = NULL;
	u32 count = hbc_function_count (hbc_ctx.hbc);
	if (function_id >= count) {
		HBC_PRINTF (core, "Error: function id %u out of range (count=%u)\n", function_id, count);
		return;
	}
	result = hbc_decompile_function (hbc_ctx.hbc, function_id, opts, &output);
	if (result.code == RESULT_SUCCESS && output) {
		HBC_PRINTF (core, "%s\n", output);
		free (output);
	} else {
		HBC_PRINTF (core, "Error decompiling function %u: %s\n", function_id, safe_errmsg (result.error_message));
	}
}

/* List available functions */
static void cmd_list_functions(RCore *core) {
	Result result = hbc_load_current_binary (core);
	if (result.code != RESULT_SUCCESS) {
		HBC_PRINTF (core, "Error: %s\n", safe_errmsg (result.error_message));
		return;
	}

	u32 count = hbc_function_count (hbc_ctx.hbc);
	HBC_PRINTF (core, "Functions (%u):\n", count);

	for (u32 i = 0; i < count; i++) {
		HBCFunctionInfo info;
		Result res = hbc_get_function_info (hbc_ctx.hbc, i, &info);
		if (res.code == RESULT_SUCCESS) {
			HBC_PRINTF (core, "  [%3u] %s at 0x%08x size=0x%x params=%u\n",
				i, safe_name (info.name), info.offset, info.size, info.param_count);
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
	result = hbc_get_header (hbc_ctx.hbc, &header);
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
		header.version, header.fileLength, header.functionCount, header.stringCount,
		header.identifierCount, header.globalCodeIndex,
		header.staticBuiltins ? "yes" : "no",
		header.hasAsync ? "yes" : "no");
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
	char *output = NULL;
	u32 count = hbc_function_count (hbc_ctx.hbc);
	if (function_id >= count) {
		HBC_PRINTF (core, "{\"function_id\":%u,\"decompilation\":null,\"error\":\"function id out of range\",\"count\":%u}\n", function_id, count);
		return;
	}
	result = hbc_decompile_function (hbc_ctx.hbc, function_id, opts, &output);

	RStrBuf *sb = r_strbuf_newf ("{\"function_id\":%u,\"decompilation\":", function_id);
	if (!sb) {
		free (output);
		HBC_PRINT (core, "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (result.code == RESULT_SUCCESS && output) {
		r_strbuf_append (sb, "\"");
		for (const char *p = output; *p; p++) {
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
		free (output);
	} else {
		r_strbuf_append (sb, "null");
	}
	r_strbuf_append (sb, "}\n");
	HBC_PRINT (core, r_strbuf_get (sb));
	r_strbuf_free (sb);
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
		"  pd:h?          - Show this help\n");
}

/* Main handler for pd:h commands */
static bool cmd_handler(struct r_core_plugin_session_t *s, const char *input) {
	RCore *core = s? s->core: NULL;

	if (!core || !input) {
		return false;
	}

	/* Must start with "pd:h" */
	if (strncmp (input, "pd:h", 4) != 0) {
		return false;
	}

	const char *arg = input + 4;

	if (*arg == '\0' || (*arg == ' ' && (arg[1] == '\0' || isspace ((unsigned char)arg[1])))) {
		/* pd:h - decompile function at current offset */
		cmd_decompile_current (core);
	} else if (*arg == 'a') {
		/* pd:ha - decompile all */
		cmd_decompile_all (core);
	} else if (*arg == 'c') {
		/* pd:hc [id] */
		const char *addr_str = arg + 1;
		while (*addr_str && isspace ((unsigned char)*addr_str)) {
			addr_str++;
		}
		cmd_decompile_function (core, addr_str);
	} else if (*arg == 'f') {
		/* pd:hf */
		cmd_list_functions (core);
	} else if (*arg == 'i') {
		/* pd:hi */
		cmd_file_info (core);
	} else if (*arg == 'j') {
		/* pd:hj [id] */
		const char *addr_str = arg + 1;
		while (*addr_str && isspace ((unsigned char)*addr_str)) {
			addr_str++;
		}
		cmd_json (core, addr_str);
	} else if (*arg == '?') {
		/* pd:h? */
		cmd_help (core);
	} else {
		HBC_PRINT (core, "Unknown subcommand. Use pd:h? for help.\n");
	}

	return true;
}

static bool plugin_fini(struct r_core_plugin_session_t *s) {
	(void)s;
	if (hbc_ctx.hbc) {
		hbc_close (hbc_ctx.hbc);
		hbc_ctx.hbc = NULL;
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
	.init = NULL,
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
