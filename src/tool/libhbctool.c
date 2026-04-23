#include <hbc/common.h>
#include <hbc/hbc.h>
#include <hbc/literals.h>
#include <hbc/decompilation/literals.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/disasm.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	bool json, verbose, bytecode, debug, asm_syntax;
	bool pretty_literals, no_pretty_literals, no_comments;
} CliFlags;

typedef struct {
	const char *program_name;
	CliFlags flags;
} CliContext;

typedef Result (*CommandHandler)(const CliContext *ctx, int argc, char **argv);
typedef struct { const char *name; const char *help; CommandHandler handler; } Command;

static void json_print_string(const char *s);

static const struct { const char *lname; char sname; size_t offset; } flag_table[] = {
	{ "json",               'j', offsetof (CliFlags, json) },
	{ "verbose",            'v', offsetof (CliFlags, verbose) },
	{ "bytecode",           'b', offsetof (CliFlags, bytecode) },
	{ "debug",              'd', offsetof (CliFlags, debug) },
	{ "asmsyntax",          0,   offsetof (CliFlags, asm_syntax) },
	{ "pretty-literals",    'P', offsetof (CliFlags, pretty_literals) },
	{ "no-pretty-literals", 'N', offsetof (CliFlags, no_pretty_literals) },
	{ "no-comments",        'C', offsetof (CliFlags, no_comments) },
};
#define FLAG_TABLE_N (sizeof (flag_table) / sizeof (flag_table[0]))

static Result errorf(ResultCode code, const char *fmt, ...) {
	static char buf[256];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf), fmt, ap);
	va_end (ap);
	Result r = { code, buf };
	return r;
}

static void eprintf(const char *fmt, ...) {
	va_list ap;
	fputs ("Error: ", stderr);
	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
	fputc ('\n', stderr);
}

static bool streq(const char *a, const char *b) {
	return a && b && !strcmp (a, b);
}

static bool flag_set(CliFlags *f, const char *lname, char sname) {
	for (size_t i = 0; i < FLAG_TABLE_N; i++) {
		bool m = lname? !strcmp (lname, flag_table[i].lname)
			: (flag_table[i].sname && flag_table[i].sname == sname);
		if (m) {
			*(bool *)((char *)f + flag_table[i].offset) = true;
			return true;
		}
	}
	return false;
}

static Result parse_flags(CliFlags *flags, int *argc, char **argv) {
	int w = 0;
	bool end = false;
	for (int r = 0; r < *argc; r++) {
		const char *a = argv[r];
		if (end || a[0] != '-' || !a[1]) {
			argv[w++] = argv[r];
			continue;
		}
		if (streq (a, "--")) {
			end = true;
			continue;
		}
		if (a[1] == '-') {
			if (!flag_set (flags, a + 2, 0)) {
				return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unknown option: %s", a);
			}
			continue;
		}
		for (const char *p = a + 1; *p; p++) {
			if (!flag_set (flags, NULL, *p)) {
				return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unknown option: -%c", *p);
			}
		}
	}
	*argc = w;
	return SUCCESS_RESULT ();
}

static Result open_hbc(const char *path, HBC **out) {
	*out = NULL;
	Result r = hbc_open (path, out);
	if (r.code != RESULT_SUCCESS || !*out) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", path);
	}
	return SUCCESS_RESULT ();
}

static FILE *open_out(const char *path, const char *mode, Result *err) {
	if (!path) {
		return stdout;
	}
	FILE *f = fopen (path, mode);
	if (!f) {
		*err = errorf (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file: %s", path);
	}
	return f;
}

static Result write_out(const char *path, const u8 *buf, size_t len, bool binary) {
	Result err = SUCCESS_RESULT ();
	FILE *f = open_out (path, binary? "wb": "w", &err);
	if (!f) {
		return err;
	}
	if (len) {
		fwrite (buf, 1, len, f);
	}
	if (f != stdout) {
		fclose (f);
	}
	return SUCCESS_RESULT ();
}

static Result read_entire_file(const char *path, char **out_buf, size_t *out_len) {
	*out_buf = NULL;
	*out_len = 0;
	FILE *f = fopen (path, "rb");
	if (!f) {
		return errorf (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open input file: %s", path);
	}
	fseek (f, 0, SEEK_END);
	long sz = ftell (f);
	rewind (f);
	if (sz < 0) {
		fclose (f);
		return errorf (RESULT_ERROR_PARSING_FAILED, "Failed to size input file: %s", path);
	}
	char *buf = calloc ((size_t)sz + 1, 1);
	if (!buf) {
		fclose (f);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	*out_len = fread (buf, 1, (size_t)sz, f);
	fclose (f);
	buf[*out_len] = '\0';
	*out_buf = buf;
	return SUCCESS_RESULT ();
}

static int hex_nibble(char c) {
	if (c >= '0' && c <= '9') { return c - '0'; }
	if (c >= 'a' && c <= 'f') { return 10 + c - 'a'; }
	if (c >= 'A' && c <= 'F') { return 10 + c - 'A'; }
	return -1;
}

static bool is_hex_sep(char c) {
	return isspace ((unsigned char)c) || c == ',' || c == ':' || c == '-' || c == '_';
}

static Result parse_hex_bytes(const char *s, u8 *out, size_t out_cap, size_t *out_len) {
	*out_len = 0;
	if (!s || !*s) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Empty hex string");
	}
	for (const char *p = s; *p; ) {
		while (*p && is_hex_sep (*p)) { p++; }
		if (!*p) { break; }
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { p += 2; continue; }
		int hi = hex_nibble (*p++);
		if (hi < 0) {
			return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Invalid hex character: '%c'", p[-1]);
		}
		while (*p && is_hex_sep (*p)) { p++; }
		int lo = hex_nibble (*p++);
		if (lo < 0) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Odd number of hex nibbles");
		}
		if (*out_len >= out_cap) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Too many bytes (max 64)");
		}
		out[(*out_len)++] = (u8)((hi << 4) | lo);
	}
	if (!*out_len) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No bytes parsed");
	}
	return SUCCESS_RESULT ();
}

static Result cmd_d(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc != 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: d <input_file>");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	u32 fc = hbc_function_count (hbc);
	printf ("HBC Disassembly Output:\n=====================\n\nTotal functions: %u\n\n", fc);
	for (u32 i = 0; i < fc; i++) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, i, &fi).code != RESULT_SUCCESS) {
			continue;
		}
		printf ("Function %u: %s\n  Offset: 0x%08x\n  Size: %u bytes\n  Params: %u\n\n",
			i, fi.name? fi.name: "unnamed", fi.offset, fi.size, fi.param_count);
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_c(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc != 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: c <input_file>");
	}
	return _hbc_decompile_file (argv[0], NULL);
}

static Result cmd_dis(const CliContext *ctx, int argc, char **argv) {
	if (argc != 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: dis <hexbytes>");
	}
	u8 bytes[64];
	size_t bcount = 0;
	RETURN_IF_ERROR (parse_hex_bytes (argv[0], bytes, sizeof (bytes), &bcount));
	HBCInsnInfo sinfo = { 0 };
	HBCDecodeCtx dec_ctx = {
		.bytes = bytes, .len = bcount, .bytecode_version = 96, .pc = 0,
		.asm_syntax = ctx->flags.asm_syntax, .build_objects = true,
	};
	Result r = hbc_dec (&dec_ctx, &sinfo);
	if (r.code == RESULT_SUCCESS) {
		printf ("%s\n", sinfo.text? sinfo.text: "");
	}
	free (sinfo.text);
	return r;
}

static Result encode_asm(const char *input, bool is_file, const char *output) {
	char *text = NULL;
	size_t len = 0;
	if (is_file) {
		RETURN_IF_ERROR (read_entire_file (input, &text, &len));
	} else {
		text = strdup (input);
		len = text? strlen (input): 0;
	}
	if (!text) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	if (!len) {
		free (text);
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Empty input");
	}
	const size_t cap = 64 * 1024;
	u8 *buffer = malloc (cap);
	if (!buffer) {
		free (text);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	HBCEncBuf eb = { .buffer = buffer, .buffer_size = cap, .bytes_written = 0 };
	Result r = hbc_enc_multi (text, 96, &eb);
	free (text);
	if (r.code == RESULT_SUCCESS) {
		r = write_out (output, buffer, eb.bytes_written, true);
	}
	free (buffer);
	return r;
}

static Result cmd_a(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: a <asm_instruction> [output_file]");
	}
	return encode_asm (argv[0], false, argc == 2? argv[1]: NULL);
}

static Result cmd_asm(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: asm <asm_file> [output_file]");
	}
	return encode_asm (argv[0], true, argc == 2? argv[1]: NULL);
}

static Result cmd_r(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: r <input> [output]");
	}
	return _hbc_generate_r2_script (argv[0], argc == 2? argv[1]: NULL);
}

static Result cmd_v(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: v <input> [output]");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	HBCHeader h;
	Result r = hbc_get_header (hbc, &h);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}
	Result err = SUCCESS_RESULT ();
	FILE *out = open_out (argc == 2? argv[1]: NULL, "w", &err);
	if (!out) {
		hbc_close (hbc);
		return err;
	}
	fprintf (out, "HBC File Validation Report\n===========================\n\n");
	fprintf (out, "%llu (magic)\n%u (version)\n%u functions\n%u strings\n\nFile appears valid.\n",
		(unsigned long long)h.magic, h.version, h.functionCount, h.stringCount);
	if (out != stdout) {
		fclose (out);
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_h(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: h <input> [output]");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	HBCHeader hh;
	Result r = hbc_get_header (hbc, &hh);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}
	Result err = SUCCESS_RESULT ();
	FILE *out = open_out (argc == 2? argv[1]: NULL, "w", &err);
	if (!out) {
		hbc_close (hbc);
		return err;
	}
	fprintf (out, "Hermes Bytecode File Header:\n");
	fprintf (out, "  Magic: 0x%016llx\n", (unsigned long long)hh.magic);
	fprintf (out, "  Version: %u\n", hh.version);
	fprintf (out, "  Source Hash: ");
	for (int i = 0; i < 20; i++) {
		fprintf (out, "%02x", hh.sourceHash[i]);
	}
	fprintf (out, "\n");
	fprintf (out, "  File Length: %u bytes\n", hh.fileLength);
	fprintf (out, "  Global Code Index: %u\n", hh.globalCodeIndex);
	fprintf (out, "  Function Count: %u\n", hh.functionCount);
	fprintf (out, "  String Kind Count: %u\n", hh.stringKindCount);
	fprintf (out, "  Identifier Count: %u\n", hh.identifierCount);
	fprintf (out, "  String Count: %u\n", hh.stringCount);
	fprintf (out, "  Overflow String Count: %u\n", hh.overflowStringCount);
	fprintf (out, "  String Storage Size: %u bytes\n", hh.stringStorageSize);
	if (hh.version >= 87) {
		fprintf (out, "  BigInt Count: %u\n", hh.bigIntCount);
		fprintf (out, "  BigInt Storage Size: %u bytes\n", hh.bigIntStorageSize);
	}
	fprintf (out, "  RegExp Count: %u\n", hh.regExpCount);
	fprintf (out, "  RegExp Storage Size: %u bytes\n", hh.regExpStorageSize);
	if (hh.version >= 97) {
		fprintf (out, "  Literal Value Buffer Size: %u bytes\n", hh.literalValueBufferSize);
	} else {
		fprintf (out, "  Array Buffer Size: %u bytes\n", hh.arrayBufferSize);
	}
	fprintf (out, "  Object Key Buffer Size: %u bytes\n", hh.objKeyBufferSize);
	if (hh.version >= 97) {
		fprintf (out, "  Object Shape Table Count: %u\n", hh.objShapeTableCount);
	} else {
		fprintf (out, "  Object Value Buffer Size: %u bytes\n", hh.objValueBufferSize);
	}
	if (hh.version >= 99) {
		fprintf (out, "  String Switch Instruction Count: %u\n", hh.numStringSwitchImms);
	}
	fprintf (out, "  %s: %u\n  CJS Module Count: %u\n",
		hh.version < 78? "CJS Module Offset": "Segment ID", hh.segmentID, hh.cjsModuleCount);
	if (hh.version >= 84) {
		fprintf (out, "  Function Source Count: %u\n", hh.functionSourceCount);
	}
	fprintf (out, "  Debug Info Offset: %u\n", hh.debugInfoOffset);
	fprintf (out, "  Flags:\n");
	fprintf (out, "    Static Builtins: %s\n", hh.staticBuiltins? "Yes": "No");
	fprintf (out, "    CJS Modules Statically Resolved: %s\n", hh.cjsModulesStaticallyResolved? "Yes": "No");
	fprintf (out, "    Has Async: %s\n", hh.hasAsync? "Yes": "No");
	HBCDebugInfo di = { 0 };
	if (hbc_get_debug_info (hbc, &di).code == RESULT_SUCCESS) {
		fprintf (out, "  Debug Info:\n");
		fprintf (out, "    Present: %s\n", di.has_debug_info? "Yes": "No");
		if (di.has_debug_info) {
			fprintf (out, "    Files: %u (%u bytes)\n", di.filename_count, di.filename_storage_size);
			fprintf (out, "    File Regions: %u\n", di.file_region_count);
			fprintf (out, "    Functions With Debug Info: %u\n", di.functions_with_debug_info);
			fprintf (out, "    Source Locations: %u bytes\n", di.source_locations_size);
			fprintf (out, "    Scope Descriptors: %u bytes\n", di.scope_desc_data_size);
			fprintf (out, "    Textified Callees: %u bytes\n", di.textified_data_size);
			fprintf (out, "    Debug String Table: %u bytes\n", di.string_table_size);
			fprintf (out, "    Debug Data Size: %u bytes\n", di.debug_data_size);
		}
	}
	if (out != stdout) {
		fclose (out);
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_f(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: f <input> [n]");
	}
	u32 n = (argc == 2)? (u32)strtoul (argv[1], NULL, 0): 50;
	if (!n) { n = 50; }
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	u32 fc = hbc_function_count (hbc);
	u32 count = fc < n? fc: n;
	for (u32 i = 0; i < count; i++) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, i, &fi).code != RESULT_SUCCESS) { continue; }
		printf ("id=%u offset=0x%08x size=%u name=%s\n", i, fi.offset, fi.size, fi.name? fi.name: "");
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_sl(const CliContext *ctx, int argc, char **argv) {
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: sl <input> [function_id]");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	HBCSourceLineArray lines = { 0 };
	Result r = hbc_get_source_lines (hbc, &lines);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}

	const bool filter = argc == 2;
	const u32 filter_id = filter? (u32)strtoul (argv[1], NULL, 0): 0;
	const bool json = ctx->flags.json;
	bool first = true;
	if (json) {
		putchar ('[');
	}
	for (u32 i = 0; i < lines.count; i++) {
		const HBCSourceLine *sl = &lines.lines[i];
		if (filter && sl->function_id != filter_id) {
			continue;
		}
		if (json) {
			printf ("%s{\"function\":%u,\"address\":%u,\"offset\":%u,\"line\":%u,\"column\":%u,\"statement\":%u,\"file\":",
				first? "": ",",
				sl->function_id, sl->address, sl->function_address,
				sl->line, sl->column, sl->statement);
			json_print_string (sl->filename);
			putchar ('}');
			first = false;
		} else {
			printf ("0x%08x f=%u +0x%x %s:%u:%u stmt=%u\n",
				sl->address, sl->function_id, sl->function_address,
				sl->filename? sl->filename: "",
				sl->line, sl->column, sl->statement);
		}
	}
	if (json) {
		puts ("]");
	}
	hbc_free_source_lines (&lines);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_cmp(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1 || argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: cmp <input> [n]");
	}
	u32 n = (argc == 2)? (u32)strtoul (argv[1], NULL, 0): 100;
	if (!n) { n = 100; }
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	u32 fc = hbc_function_count (hbc);
	u32 count = fc < n? fc: n;

	FILE *py = fopen ("parser.txt", "r");
	if (!py) {
		hbc_close (hbc);
		return errorf (RESULT_ERROR_FILE_NOT_FOUND, "could not open parser.txt");
	}
	u32 *py_sizes = calloc (count, sizeof (u32));
	u32 *py_offs = calloc (count, sizeof (u32));
	if (!py_sizes || !py_offs) {
		fclose (py);
		hbc_close (hbc);
		free (py_sizes);
		free (py_offs);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	char line[4096];
	while (fgets (line, sizeof (line), py)) {
		char *p = strstr (line, "=> [Function #");
		if (!p) { continue; }
		p += strlen ("=> [Function #");
		char *end = NULL;
		long id = strtol (p, &end, 10);
		if (end == p || id < 0 || (u32)id >= count) { continue; }
		char *ofp = strstr (end, " of ");
		if (!ofp) { continue; }
		long sz = strtol (ofp + 4, &end, 10);
		if (end == ofp + 4 || sz < 0) { continue; }
		char *offp = strstr (end, " at 0x");
		if (!offp) { continue; }
		unsigned int off = 0;
		if (sscanf (offp + 6, "%x", &off) != 1) { continue; }
		py_sizes[id] = (u32)sz;
		py_offs[id] = (u32)off;
	}
	fclose (py);
	for (u32 i = 0; i < count; i++) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, i, &fi).code != RESULT_SUCCESS) { continue; }
		const char *res = (fi.offset == py_offs[i] && fi.size == py_sizes[i])? "OK": "MISMATCH";
		printf ("id=%u C(off=0x%08x,sz=%u) PY(off=0x%08x,sz=%u) => %s\n",
			i, fi.offset, fi.size, py_offs[i], py_sizes[i], res);
	}
	free (py_sizes);
	free (py_offs);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result disasm_function(HBC *hbc, u32 function_id, char **out) {
	const u8 *bytecode = NULL;
	u32 bytecode_size = 0;
	RETURN_IF_ERROR (hbc_get_function_bytecode (hbc, function_id, &bytecode, &bytecode_size));
	HBCHeader hdr;
	RETURN_IF_ERROR (hbc_get_header (hbc, &hdr));
	HBCFunc fi;
	RETURN_IF_ERROR (hbc_get_function_info (hbc, function_id, &fi));

	size_t cap = 4096, len = 0;
	char *buf = malloc (cap);
	if (!buf) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	buf[0] = '\0';
	for (u32 offset = 0; offset < bytecode_size; ) {
		HBCInsnInfo ii = { 0 };
		HBCDecodeCtx dc = {
			.bytes = bytecode + offset, .len = bytecode_size - offset,
			.pc = fi.offset + offset, .bytecode_version = hdr.version,
			.hbc = hbc,
		};
		Result r = hbc_dec (&dc, &ii);
		if (r.code != RESULT_SUCCESS || !ii.size) {
			free (ii.text);
			break;
		}
		const char *text = ii.text? ii.text: "";
		size_t tl = strlen (text);
		if (len + tl + 2 > cap) {
			cap = (len + tl + 2) * 2;
			char *tmp = realloc (buf, cap);
			if (!tmp) {
				free (ii.text);
				free (buf);
				return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
			}
			buf = tmp;
		}
		memcpy (buf + len, text, tl);
		len += tl;
		buf[len++] = '\n';
		buf[len] = '\0';
		free (ii.text);
		offset += ii.size;
	}
	*out = buf;
	return SUCCESS_RESULT ();
}

static Result cmd_cf(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc != 3) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: cf <input> <python_dis_file> <function_id>");
	}
	u32 function_id = (u32)strtoul (argv[2], NULL, 0);
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	if (function_id >= hbc_function_count (hbc)) {
		hbc_close (hbc);
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id %u", function_id);
	}
	char *disasm_str = NULL;
	Result res = disasm_function (hbc, function_id, &disasm_str);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}
	FILE *py = fopen (argv[1], "r");
	if (!py) {
		free (disasm_str);
		hbc_close (hbc);
		return errorf (RESULT_ERROR_FILE_NOT_FOUND, "could not open %s", argv[1]);
	}
	char line_py[2048], line_c[2048];
	size_t cpos = 0;
	while (fgets (line_py, sizeof (line_py), py)) {
		if (strncmp (line_py, ">> ", 3)) { continue; }
		while (disasm_str[cpos] && strncmp (disasm_str + cpos, "==> ", 4)) {
			while (disasm_str[cpos] && disasm_str[cpos] != '\n') { cpos++; }
			if (disasm_str[cpos] == '\n') { cpos++; }
		}
		if (!disasm_str[cpos]) { break; }
		size_t l = 0;
		while (disasm_str[cpos + l] && disasm_str[cpos + l] != '\n' && l < sizeof (line_c) - 1) {
			line_c[l] = disasm_str[cpos + l];
			l++;
		}
		line_c[l] = '\0';
		cpos += l + (disasm_str[cpos + l] == '\n');
		printf ("C: %s\nP: %s\n\n", line_c, line_py);
	}
	fclose (py);
	free (disasm_str);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_s(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc != 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: s <input> <index>");
	}
	long idx = strtol (argv[1], NULL, 10);
	if (idx < 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid index");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	u32 sc = hbc_string_count (hbc);
	if ((u32)idx >= sc) {
		hbc_close (hbc);
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Index out of range (max %u)", sc);
	}
	const char *s = NULL;
	hbc_get_string (hbc, (u32)idx, &s);
	printf ("idx=%ld name=%s\n", idx, s? s: "");
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_fs(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc != 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: fs <input> <needle>");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	u32 sc = hbc_string_count (hbc);
	for (u32 i = 0; i < sc; i++) {
		const char *s = NULL;
		hbc_get_string (hbc, i, &s);
		if (s && strstr (s, argv[1])) {
			printf ("idx=%u name=%s\n", i, s);
		}
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_sm(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc != 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: sm <input> <index>");
	}
	long idx = strtol (argv[1], NULL, 10);
	if (idx < 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid index");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	u32 sc = hbc_string_count (hbc);
	if ((u32)idx >= sc) {
		hbc_close (hbc);
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Index out of range (max %u)", sc);
	}
	HBCStringMeta sm;
	hbc_get_string_meta (hbc, (u32)idx, &sm);
	printf ("idx=%ld isUTF16=%u off=0x%x len=%u\n", idx, sm.isUTF16? 1u: 0u, sm.offset, sm.length);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

/* ---------------------------------------------------------------------------
 * lit: SLP buffer literal inspection
 *   lit list    <file>                                scan code, list cache (-j for JSON)
 *   lit get     <file> {a|o} <num> <primary> [<sec>]  format from raw params
 *   lit pool    <file> [a|o]                          enumerate SLP pool groups
 *   lit xrefs   <file>                                scan code, list xrefs
 * ------------------------------------------------------------------------- */

static const char *lit_kind_name(HBCLiteralKind k) {
	return k == HBC_LIT_ARRAY? "array": "object";
}

static Result lit_scan(const char *input, HBC **out_hbc, const HBCLiteralEntry **arr, u32 *n) {
	RETURN_IF_ERROR (open_hbc (input, out_hbc));
	u32 scanned = 0;
	Result r = hbc_literals_scan_code (*out_hbc, &scanned);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (*out_hbc);
		return r;
	}
	hbc_literals_list (*out_hbc, arr, n);
	return SUCCESS_RESULT ();
}

static Result lit_list_impl(const char *input, bool as_json) {
	HBC *hbc;
	const HBCLiteralEntry *arr = NULL;
	u32 n = 0;
	RETURN_IF_ERROR (lit_scan (input, &hbc, &arr, &n));
	if (as_json) {
		printf ("[");
		for (u32 i = 0; i < n; i++) {
			const HBCLiteralEntry *e = &arr[i];
			printf ("%s{\"kind\":\"%s\",\"num_items\":%u,"
				"\"primary_id\":%u,\"secondary_id\":%u,\"paddr\":%u,"
				"\"xrefs\":%u,\"formatted\":\"",
				i? ",": "", lit_kind_name (e->kind), e->num_items,
				e->primary_id, e->secondary_id, e->paddr, e->xref_count);
			for (const char *p = e->formatted; p && *p; p++) {
				if (*p == '"' || *p == '\\') { putchar ('\\'); }
				putchar (*p);
			}
			printf ("\"}");
		}
		printf ("]\n");
	} else {
		printf ("literals: %u\n", n);
		for (u32 i = 0; i < n; i++) {
			const HBCLiteralEntry *e = &arr[i];
			printf ("%-6s n=%-4u id=(%u,%u) paddr=0x%08x xrefs=%u  %s\n",
				lit_kind_name (e->kind), e->num_items, e->primary_id,
				e->secondary_id, e->paddr, e->xref_count,
				e->formatted? e->formatted: "");
		}
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result lit_get_impl(const char *input, char kindc, u32 num, u32 primary, u32 secondary) {
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (input, &hbc));
	HBCLiteralKind kind = (kindc == 'a')? HBC_LIT_ARRAY: HBC_LIT_OBJECT;
	char *text = NULL;
	Result r = hbc_literals_format_raw (hbc, kind, num, primary, secondary, &text);
	if (r.code == RESULT_SUCCESS && text) {
		puts (text);
	}
	free (text);
	hbc_close (hbc);
	return r;
}

static Result lit_pool_impl(const char *input, HBCLiteralKind kind) {
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (input, &hbc));
	HBCPoolGroup *groups = NULL;
	u32 n = 0;
	Result r = hbc_literals_scan_pool (hbc, kind, &groups, &n);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}
	printf ("%s pool: %u groups\n", lit_kind_name (kind), n);
	for (u32 i = 0; i < n; i++) {
		printf ("  paddr=0x%08x pool_off=0x%08x n=%-4u tag=%u\n",
			groups[i].paddr, groups[i].pool_offset, groups[i].num_items, groups[i].tag);
	}
	free (groups);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result lit_xrefs_impl(const char *input) {
	HBC *hbc;
	const HBCLiteralEntry *arr = NULL;
	u32 n = 0;
	RETURN_IF_ERROR (lit_scan (input, &hbc, &arr, &n));
	for (u32 i = 0; i < n; i++) {
		const HBCLiteralEntry *e = &arr[i];
		for (u32 j = 0; j < e->xref_count; j++) {
			printf ("0x%08x -> %s 0x%08x  (n=%u)\n",
				e->xref_addrs[j], lit_kind_name (e->kind), e->paddr, e->num_items);
		}
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_lit(const CliContext *ctx, int argc, char **argv) {
	if (argc < 2) {
		fprintf (stderr,
			"Usage:\n"
			"  lit list    <file>                 (use -j for JSON)\n"
			"  lit get     <file> {a|o} <num> <primary> [<secondary>]\n"
			"  lit pool    <file> [a|o]           (default: a)\n"
			"  lit xrefs   <file>\n");
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "usage");
	}
	const char *sub = argv[0];
	const char *input = argv[1];
	if (streq (sub, "list")) {
		return lit_list_impl (input, ctx->flags.json);
	}
	if (streq (sub, "pool")) {
		HBCLiteralKind kind = (argc >= 3 && argv[2][0] == 'o')? HBC_LIT_OBJECT: HBC_LIT_ARRAY;
		return lit_pool_impl (input, kind);
	}
	if (streq (sub, "xrefs")) {
		return lit_xrefs_impl (input);
	}
	if (streq (sub, "get")) {
		if (argc < 5) {
			return errorf (RESULT_ERROR_INVALID_ARGUMENT,
				"Usage: lit get <file> {a|o} <num> <primary> [<secondary>]");
		}
		return lit_get_impl (input, argv[2][0],
			(u32)strtoul (argv[3], NULL, 0),
			(u32)strtoul (argv[4], NULL, 0),
			argc > 5? (u32)strtoul (argv[5], NULL, 0): 0);
	}
	return errorf (RESULT_ERROR_INVALID_ARGUMENT, "unknown lit subcommand: %s", sub);
}

static void json_print_string(const char *s) {
	putchar ('"');
	for (const char *p = s? s: ""; *p; p++) {
		if (*p == '"' || *p == '\\') {
			putchar ('\\');
		}
		if (*p == '\n') {
			fputs ("\\n", stdout);
		} else if (*p == '\r') {
			fputs ("\\r", stdout);
		} else if (*p == '\t') {
			fputs ("\\t", stdout);
		} else {
			putchar (*p);
		}
	}
	putchar ('"');
}

static void json_print_nullable_string(const char *s) {
	if (s) {
		json_print_string (s);
	} else {
		fputs ("null", stdout);
	}
}

static const char *binding_type_name(HBCBindingType type) {
	return type == HBC_BINDING_EXPORT? "export": "import";
}

static Result cmd_bind(const CliContext *ctx, int argc, char **argv) {
	if (argc != 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: bind <input>");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	HBCBindings bindings = { 0 };
	Result r = hbc_scan_bindings (hbc, &bindings);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}
	if (ctx->flags.json) {
		putchar ('[');
		for (u32 i = 0; i < bindings.count; i++) {
			HBCBinding *b = &bindings.bindings[i];
			printf ("%s{\"type\":", i? ",": "");
			json_print_string (binding_type_name (b->type));
			printf (",\"kind\":");
			json_print_string (b->kind);
			printf (",\"name\":");
			json_print_string (b->name);
			printf (",\"module\":");
			json_print_string (b->module);
			printf (",\"function_id\":%u,\"offset\":%u,\"string_id\":%u}",
				b->function_id, b->offset, b->string_id);
		}
		puts ("]");
	} else {
		printf ("bindings: %u\n", bindings.count);
		for (u32 i = 0; i < bindings.count; i++) {
			HBCBinding *b = &bindings.bindings[i];
			printf ("%-6s %-7s sid=%-5u fn=%-5u off=0x%08x %s%s%s\n",
				binding_type_name (b->type), b->kind? b->kind: "",
				b->string_id, b->function_id, b->offset,
				b->module? b->module: "", b->module? ":": "",
				b->name? b->name: "");
		}
	}
	hbc_free_bindings (&bindings);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_libs(const CliContext *ctx, int argc, char **argv) {
	if (argc != 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: libs <input>");
	}
	HBC *hbc;
	RETURN_IF_ERROR (open_hbc (argv[0], &hbc));
	HBCModules modules = { 0 };
	Result r = hbc_list_modules (hbc, &modules);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}
	if (ctx->flags.json) {
		putchar ('[');
		for (u32 i = 0; i < modules.count; i++) {
			HBCModule *m = &modules.modules[i];
			printf ("%s{\"kind\":", i? ",": "");
			json_print_string (m->kind);
			printf (",\"name\":");
			json_print_string (m->name);
			printf (",\"path\":");
			json_print_nullable_string (m->path);
			printf (",\"version\":");
			json_print_nullable_string (m->version);
			printf (",\"function_id\":%u,\"offset\":%u,\"string_id\":%u,\"inferred\":%s}",
				m->function_id, m->offset, m->string_id, m->inferred? "true": "false");
		}
		puts ("]");
	} else {
		printf ("libs: %u\n", modules.count);
		for (u32 i = 0; i < modules.count; i++) {
			HBCModule *m = &modules.modules[i];
			printf ("%-8s sid=%-5u fn=%-5u off=0x%08x %-30s",
				m->kind? m->kind: "", m->string_id, m->function_id,
				m->offset, m->name? m->name: "");
			if (m->version && *m->version) {
				printf (" version=%s", m->version);
			}
			if (m->path && *m->path && (!m->name || strcmp (m->path, m->name))) {
				printf (" path=%s", m->path);
			}
			if (m->inferred) {
				printf (" inferred");
			}
			putchar ('\n');
		}
	}
	hbc_free_modules (&modules);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static const Command commands[] = {
	{ "d",   "Disassemble a Hermes bytecode file",       cmd_d   },
	{ "c",   "Decompile a Hermes bytecode file",         cmd_c   },
	{ "dis", "Disassemble raw hex bytes (rasm2-like)",   cmd_dis },
	{ "a",   "Assemble a single instruction",            cmd_a   },
	{ "asm", "Assemble instructions from file",          cmd_asm },
	{ "h",   "Display header information",               cmd_h   },
	{ "v",   "Validate file and show details",           cmd_v   },
	{ "r",   "Generate an r2 script with function flags",cmd_r   },
	{ "f",   "Dump first N function headers",            cmd_f   },
	{ "sl",  "List source-line information",             cmd_sl  },
	{ "cmp", "Compare first N funcs with parser.txt",    cmd_cmp },
	{ "cf",  "Compare one function vs Python disasm",    cmd_cf  },
	{ "s",   "Print a string by index",                  cmd_s   },
	{ "fs",  "Find strings by substring",                cmd_fs  },
	{ "sm",  "Show string entry metadata",               cmd_sm  },
	{ "lit", "SLP buffer literals: list, get, pool, xrefs", cmd_lit },
	{ "bind", "List probable imports/exports/native bindings", cmd_bind },
	{ "libs", "List probable bundled modules/libraries", cmd_libs },
};
#define COMMANDS_N (sizeof (commands) / sizeof (commands[0]))

static void print_usage(const char *program_name) {
	printf ("Usage: %s <command> <args...>\n\nCommands:\n", program_name);
	for (size_t i = 0; i < COMMANDS_N; i++) {
		printf ("  %-5s %s\n", commands[i].name, commands[i].help);
	}
	printf ("\nOptions (may appear anywhere after the command):\n");
	printf ("  --json, -j               JSON output (lit list, bind, libs)\n");
	printf ("  --asmsyntax              CPU-like asm syntax (dis)\n");
	printf ("  --verbose, -v            Verbose output\n");
	printf ("  --bytecode, -b           Include bytecode bytes\n");
	printf ("  --debug, -d              Include debug info\n");
	printf ("  --pretty-literals, -P    Force multi-line literals\n");
	printf ("  --no-pretty-literals, -N Force single-line literals\n");
	printf ("  --no-comments, -C        Suppress comments\n");
	printf ("  --                       End of options marker\n");
}

static const Command *find_command(const char *name) {
	for (size_t i = 0; i < COMMANDS_N; i++) {
		if (streq (name, commands[i].name)) {
			return &commands[i];
		}
	}
	return NULL;
}

int main(int argc, char **argv) {
	CliContext ctx = { argv[0], { 0 } };
	if (argc < 2) {
		print_usage (ctx.program_name);
		return 1;
	}
	const Command *cmd = find_command (argv[1]);
	if (!cmd) {
		print_usage (ctx.program_name);
		eprintf ("Unknown command: %s", argv[1]);
		return 1;
	}
	int rest_argc = argc - 2;
	char **rest_argv = argv + 2;
	Result r = parse_flags (&ctx.flags, &rest_argc, rest_argv);
	if (r.code == RESULT_SUCCESS) {
		r = cmd->handler (&ctx, rest_argc, rest_argv);
	}
	if (r.code != RESULT_SUCCESS) {
		eprintf ("%s", r.error_message[0]? r.error_message: "Unknown error");
		return 1;
	}
	return 0;
}
