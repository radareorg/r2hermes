#include <hbc/common.h>
#include <hbc/hbc.h>
#include <hbc/decompilation/literals.h>
#include <hbc/decompilation/decompiler.h>
#include <hbc/disasm.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	const char *program_name;
} CliContext;

typedef Result(*CommandHandler)(const CliContext *ctx, int argc, char **argv);

typedef struct {
	const char *name;
	const char *help;
	CommandHandler handler;
} Command;

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

static Result write_text(const char *output_path, const char *text) {
	FILE *f = stdout;
	if (output_path) {
		f = fopen (output_path, "w");
		if (!f) {
			return errorf (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file: %s", output_path);
		}
	}
	fputs (text? text: "", f);
	if (output_path) {
		fclose (f);
	}
	return SUCCESS_RESULT ();
}

static Result write_bytes(const char *output_path, const u8 *buf, size_t len) {
	FILE *f = stdout;
	if (output_path) {
		f = fopen (output_path, "wb");
		if (!f) {
			return errorf (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file: %s", output_path);
		}
	}
	if (len) {
		fwrite (buf, 1, len, f);
	}
	if (output_path) {
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
	if (fseek (f, 0, SEEK_END) != 0) {
		fclose (f);
		return errorf (RESULT_ERROR_PARSING_FAILED, "Failed to seek input file: %s", path);
	}
	long sz = ftell (f);
	if (sz < 0) {
		fclose (f);
		return errorf (RESULT_ERROR_PARSING_FAILED, "Failed to get input file size: %s", path);
	}
	if (fseek (f, 0, SEEK_SET) != 0) {
		fclose (f);
		return errorf (RESULT_ERROR_PARSING_FAILED, "Failed to seek input file: %s", path);
	}

	char *buf = (char *)calloc ((size_t)sz + 1, 1);
	if (!buf) {
		fclose (f);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}
	size_t nread = fread (buf, 1, (size_t)sz, f);
	fclose (f);
	buf[nread] = '\0';

	*out_buf = buf;
	*out_len = nread;
	return SUCCESS_RESULT ();
}

static int hex_nibble(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return 10 + (c - 'a');
	}
	if (c >= 'A' && c <= 'F') {
		return 10 + (c - 'A');
	}
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
	const char *p = s;
	while (*p) {
		while (*p && is_hex_sep (*p)) {
			p++;
		}
		if (!*p) {
			break;
		}
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
			p += 2;
			continue;
		}
		int hi = hex_nibble (*p++);
		if (hi < 0) {
			return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Invalid hex character: '%c'", p[-1]);
		}
		while (*p && is_hex_sep (*p)) {
			p++;
		}
		int lo = hex_nibble (*p++);
		if (lo < 0) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Odd number of hex nibbles");
		}
		if (*out_len >= out_cap) {
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Too many bytes (max 64)");
		}
		out[(*out_len)++] = (u8) ((hi << 4) | lo);
	}
	if (*out_len == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "No bytes parsed");
	}
	return SUCCESS_RESULT ();
}

static Result cmd_d(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: %s d <input_file>", ctx->program_name);
	}
	const char *input = argv[0];

	HBC *hbc = NULL;
	Result res = hbc_open (input, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) {
		return ERROR_RESULT (RESULT_ERROR_READ, "Failed to open file: %s");
	}

	// Just dump function info using printf directly since we don't need the complex provider API
	u32 func_count = hbc_function_count (hbc);
	printf ("HBC Disassembly Output:\n");
	printf ("=====================\n\n");
	printf ("Total functions: %u\n\n", func_count);

	for (u32 i = 0; i < func_count; i++) {
		HBCFunc fi;
		res = hbc_get_function_info (hbc, i, &fi);
		if (res.code == RESULT_SUCCESS) {
			printf ("Function %u: %s\n", i, fi.name? fi.name: "unnamed");
			printf ("  Offset: 0x%08x\n", fi.offset);
			printf ("  Size: %u bytes\n", fi.size);
			printf ("  Params: %u\n\n", fi.param_count);
		}
	}

	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_c(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: %s c <input_file>", ctx->program_name);
	}
	const char *input = argv[0];

	// Use the internal API that handles file I/O
	Result res = _hbc_decompile_file (input, NULL);
	return res;
}

static Result cmd_dis(const CliContext *ctx, int argc, char **argv) {
	if (argc < 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: %s dis <hexbytes> [--asmsyntax]", ctx->program_name);
	}
	bool asm_syntax = false;
	for (int i = 1; i < argc; i++) {
		if (streq (argv[i], "--asmsyntax")) {
			asm_syntax = true;
		} else {
			return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unknown option: %s", argv[i]);
		}
	}
	const char *hex = argv[0];
	u8 bytes[64];
	size_t bcount = 0;
	RETURN_IF_ERROR (parse_hex_bytes (hex, bytes, sizeof (bytes), &bcount));

	HBCInsnInfo sinfo;
	memset (&sinfo, 0, sizeof (sinfo));

	HBCDecodeCtx dec_ctx = {
		.bytes = bytes,
		.len = bcount,
		.bytecode_version = 96,
		.pc = 0,
		.asm_syntax = asm_syntax,
		.resolve_string_ids = false,
		.string_tables = NULL,
		.hbc = NULL,
		.build_objects = true
	};

	Result r = hbc_dec (&dec_ctx, &sinfo);
	if (r.code != RESULT_SUCCESS) {
		return r;
	}
	printf ("%s\n", sinfo.text? sinfo.text: "");
	free (sinfo.text);
	return SUCCESS_RESULT ();
}

static Result encode_asm(const char *input, bool is_file, const char *output) {
	char *asm_text = NULL;
	size_t asm_len = 0;

	if (is_file) {
		RETURN_IF_ERROR (read_entire_file (input, &asm_text, &asm_len));
		if (asm_len == 0) {
			free (asm_text);
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Empty input file");
		}
	} else {
		/* Inline assembly */
		asm_text = (char *)malloc (strlen (input) + 1);
		if (!asm_text) {
			return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
		}
		strcpy (asm_text, input);
		asm_len = strlen (input);
	}

	const size_t out_cap = 64 * 1024;
	u8 *buffer = (u8 *)malloc (out_cap);
	if (!buffer) {
		free (asm_text);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}

	HBCEncBuf eb = (HBCEncBuf){ .buffer = buffer, .buffer_size = out_cap, .bytes_written = 0 };
	Result r = hbc_enc_multi (asm_text, 96, &eb);
	free (asm_text);
	if (r.code != RESULT_SUCCESS) {
		free (buffer);
		return r;
	}
	r = write_bytes (output, buffer, eb.bytes_written);
	free (buffer);
	return r;
}

static Result cmd_a(const CliContext *ctx, int argc, char **argv) {
	if (argc < 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: %s a <asm_instruction> [output_file]", ctx->program_name);
	}
	const char *output = (argc >= 2)? argv[1]: NULL;
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}
	return encode_asm (argv[0], false, output);
}

static Result cmd_asm(const CliContext *ctx, int argc, char **argv) {
	if (argc < 1) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: %s asm <asm_file> [output_file]", ctx->program_name);
	}
	const char *output = (argc >= 2)? argv[1]: NULL;
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}
	return encode_asm (argv[0], true, output);
}

static Result cmd_r(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: r <input_file> [output_file]");
	}
	const char *input = argv[0];
	const char *output = (argc >= 2)? argv[1]: NULL;
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}
	return _hbc_generate_r2_script (input, output);
}

static Result cmd_v(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: v <input_file> [output_file]");
	}
	const char *input = argv[0];
	const char *output = (argc >= 2)? argv[1]: NULL;
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}

	HBC *hbc = NULL;
	Result r = hbc_open (input, &hbc);
	if (r.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}

	/* Get header to verify validity */
	HBCHeader header;
	r = hbc_get_header (hbc, &header);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}

	/* Basic validation: check magic and version */
	StringBuffer sb;
	r = _hbc_string_buffer_init (&sb, 1024);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}

	_hbc_string_buffer_append (&sb, "HBC File Validation Report\n");
	_hbc_string_buffer_append (&sb, "===========================\n\n");

	_hbc_string_buffer_append_int (&sb, header.magic);
	_hbc_string_buffer_append (&sb, " (magic)\n");

	_hbc_string_buffer_append_int (&sb, header.version);
	_hbc_string_buffer_append (&sb, " (version)\n");

	_hbc_string_buffer_append_int (&sb, header.functionCount);
	_hbc_string_buffer_append (&sb, " functions\n");

	_hbc_string_buffer_append_int (&sb, header.stringCount);
	_hbc_string_buffer_append (&sb, " strings\n");

	_hbc_string_buffer_append (&sb, "\nFile appears valid.\n");

	r = write_text (output, sb.data);
	_hbc_string_buffer_free (&sb);
	hbc_close (hbc);
	return r;
}

static Result cmd_h(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: h <input_file> [output_file]");
	}
	const char *input = argv[0];
	const char *output = (argc >= 2)? argv[1]: NULL;
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}

	HBC *hbc = NULL;
	Result r = hbc_open (input, &hbc);
	if (r.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}
	HBCHeader hh;
	r = hbc_get_header (hbc, &hh);
	if (r.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return r;
	}

	FILE *out = stdout;
	if (output) {
		out = fopen (output, "w");
		if (!out) {
			hbc_close (hbc);
			return errorf (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open output file: %s", output);
		}
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
	fprintf (out, "  Array Buffer Size: %u bytes\n", hh.arrayBufferSize);
	fprintf (out, "  Object Key Buffer Size: %u bytes\n", hh.objKeyBufferSize);
	fprintf (out, "  Object Value Buffer Size: %u bytes\n", hh.objValueBufferSize);
	fprintf (out, "  %s: %u\n  CJS Module Count: %u\n", (hh.version < 78)? "CJS Module Offset": "Segment ID", hh.segmentID, hh.cjsModuleCount);
	if (hh.version >= 84) {
		fprintf (out, "  Function Source Count: %u\n", hh.functionSourceCount);
	}
	fprintf (out, "  Debug Info Offset: %u\n", hh.debugInfoOffset);
	fprintf (out, "  Flags:\n");
	fprintf (out, "    Static Builtins: %s\n", hh.staticBuiltins? "Yes": "No");
	fprintf (out, "    CJS Modules Statically Resolved: %s\n", hh.cjsModulesStaticallyResolved? "Yes": "No");
	fprintf (out, "    Has Async: %s\n", hh.hasAsync? "Yes": "No");
	if (output) {
		fclose (out);
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_f(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: f <input_file> [n]");
	}
	const char *input = argv[0];
	u32 n = 50;
	if (argc >= 2) {
		n = (u32)strtoul (argv[1], NULL, 0);
		if (!n) {
			n = 50;
		}
	}
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}

	HBC *hbc = NULL;
	Result res = hbc_open (input, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}
	u32 fc = hbc_function_count (hbc);
	u32 count = fc < n? fc: n;
	for (u32 i = 0; i < count; i++) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, i, &fi).code != RESULT_SUCCESS) {
			continue;
		}
		printf ("id=%u offset=0x%08x size=%u name=%s\n", i, fi.offset, fi.size, fi.name? fi.name: "");
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_cmp(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 1) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: cmp <input_file> [n]");
	}
	const char *input = argv[0];
	u32 n = 100;
	if (argc >= 2) {
		n = (u32)strtoul (argv[1], NULL, 0);
		if (!n) {
			n = 100;
		}
	}
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}

	HBC *hbc = NULL;
	Result res = hbc_open (input, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}
	u32 fc = hbc_function_count (hbc);
	u32 count = fc < n? fc: n;

	const char *py_path = "parser.txt";
	FILE *py = fopen (py_path, "r");
	if (!py) {
		hbc_close (hbc);
		return errorf (RESULT_ERROR_FILE_NOT_FOUND, "could not open %s", py_path);
	}

	u32 *py_sizes = (u32 *)calloc (count, sizeof (u32));
	u32 *py_offs = (u32 *)calloc (count, sizeof (u32));
	if (!py_sizes || !py_offs) {
		fclose (py);
		hbc_close (hbc);
		free (py_sizes);
		free (py_offs);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "OOM");
	}

	char line[4096];
	while (fgets (line, sizeof (line), py)) {
		const char *needle = "=> [Function #";
		char *p = strstr (line, needle);
		if (!p) {
			continue;
		}
		p += strlen (needle);
		char *end = NULL;
		long id = strtol (p, &end, 10);
		if (end == p || id < 0 || (u32)id >= count) {
			continue;
		}
		char *ofp = strstr (end, " of ");
		if (!ofp) {
			continue;
		}
		ofp += 4;
		long sz = strtol (ofp, &end, 10);
		if (end == ofp || sz < 0) {
			continue;
		}
		char *offp = strstr (end, " at 0x");
		if (!offp) {
			continue;
		}
		offp += 6;
		unsigned int off = 0;
		if (sscanf (offp, "%x", &off) != 1) {
			continue;
		}
		py_sizes[id] = (u32)sz;
		py_offs[id] = (u32)off;
	}
	fclose (py);

	for (u32 i = 0; i < count; i++) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, i, &fi).code != RESULT_SUCCESS) {
			continue;
		}
		u32 po = py_offs[i];
		u32 ps = py_sizes[i];
		const char *res = (fi.offset == po && fi.size == ps)? "OK": "MISMATCH";
		printf ("id=%u C(off=0x%08x,sz=%u) PY(off=0x%08x,sz=%u) => %s\n", i, fi.offset, fi.size, po, ps, res);
	}
	free (py_sizes);
	free (py_offs);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_cf(const CliContext *ctx, int argc, char **argv) {
	if (argc < 3) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Usage: %s cf <input_file> <python_dis_file> <function_id>", ctx->program_name);
	}
	const char *input = argv[0];
	const char *python_dis_file = argv[1];
	u32 function_id = (u32)strtoul (argv[2], NULL, 0);

	HBC *hbc = NULL;
	Result res = hbc_open (input, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}
	u32 fc = hbc_function_count (hbc);
	if (function_id >= fc) {
		hbc_close (hbc);
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Invalid function id %u", function_id);
	}

	HBCDisOptions opt = (HBCDisOptions){ 0 };
	char *disasm_str = NULL;
	res = hbc_disasm_fn (hbc, function_id, opt, &disasm_str);
	if (res.code != RESULT_SUCCESS) {
		hbc_close (hbc);
		return res;
	}

	FILE *py = fopen (python_dis_file, "r");
	if (!py) {
		free (disasm_str);
		hbc_close (hbc);
		return errorf (RESULT_ERROR_FILE_NOT_FOUND, "could not open %s", python_dis_file);
	}

	char line_py[2048];
	char *cbuf = disasm_str;
	char line_c[2048];
	size_t cpos = 0;
	while (fgets (line_py, sizeof (line_py), py)) {
		if (strncmp (line_py, ">> ", 3) != 0) {
			continue;
		}
		while (cbuf[cpos] && strncmp (&cbuf[cpos], "==> ", 4) != 0) {
			while (cbuf[cpos] && cbuf[cpos] != '\n') {
				cpos++;
			}
			if (cbuf[cpos] == '\n') {
				cpos++;
			}
		}
		if (!cbuf[cpos]) {
			break;
		}
		size_t l = 0;
		while (cbuf[cpos + l] && cbuf[cpos + l] != '\n' && l < sizeof (line_c) - 1) {
			line_c[l] = cbuf[cpos + l];
			l++;
		}
		line_c[l] = '\0';
		cpos += l;
		if (cbuf[cpos] == '\n') {
			cpos++;
		}
		printf ("C: %s\nP: %s\n\n", line_c, line_py);
	}
	fclose (py);
	free (disasm_str);
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_s(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 2) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: s <input_file> <index>");
	}
	const char *input = argv[0];
	long idx = strtol (argv[1], NULL, 10);
	if (idx < 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid index");
	}
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}

	HBC *hbc = NULL;
	Result res = hbc_open (input, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}
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
	if (argc < 2) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: fs <input_file> <needle>");
	}
	const char *input = argv[0];
	const char *needle = argv[1];
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}

	HBC *hbc = NULL;
	Result res = hbc_open (input, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}
	u32 sc = hbc_string_count (hbc);
	for (u32 i = 0; i < sc; i++) {
		const char *s = NULL;
		hbc_get_string (hbc, i, &s);
		if (s && strstr (s, needle)) {
			printf ("idx=%u name=%s\n", i, s);
		}
	}
	hbc_close (hbc);
	return SUCCESS_RESULT ();
}

static Result cmd_sm(const CliContext *ctx, int argc, char **argv) {
	(void)ctx;
	if (argc < 2) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Usage: sm <input_file> <index>");
	}
	const char *input = argv[0];
	long idx = strtol (argv[1], NULL, 10);
	if (idx < 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid index");
	}
	if (argc > 2) {
		return errorf (RESULT_ERROR_INVALID_ARGUMENT, "Unexpected argument: %s", argv[2]);
	}

	HBC *hbc = NULL;
	Result res = hbc_open (input, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) {
		return errorf (RESULT_ERROR_READ, "Failed to open file: %s", input);
	}
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

static const Command commands[] = {
	{ "d", "Disassemble a Hermes bytecode file", cmd_d },
	{ "c", "Decompile a Hermes bytecode file", cmd_c },
	{ "dis", "Disassemble raw hex bytes (rasm2-like)", cmd_dis },
	{ "a", "Assemble a single instruction", cmd_a },
	{ "asm", "Assemble instructions from file", cmd_asm },
	{ "h", "Display header information", cmd_h },
	{ "v", "Validate file and show details", cmd_v },
	{ "r", "Generate an r2 script with function flags", cmd_r },
	{ "f", "Dump first N function headers", cmd_f },
	{ "cmp", "Compare first N funcs with parser.txt", cmd_cmp },
	{ "cf", "Compare one function vs Python disasm", cmd_cf },
	{ "s", "Print a string by index", cmd_s },
	{ "fs", "Find strings by substring", cmd_fs },
	{ "sm", "Show string entry metadata", cmd_sm },
};

static void print_usage(const char *program_name) {
	printf ("Usage: %s <command> <args...>\n\n", program_name);
	printf ("Commands:\n");
	for (size_t i = 0; i < sizeof (commands) / sizeof (commands[0]); i++) {
		printf ("  %-5s %s\n", commands[i].name, commands[i].help);
	}
	printf ("\nOptions:\n");
	printf ("  --verbose, -v            Show detailed metadata (d)\n");
	printf ("  --json, -j               Output in JSON format (d)\n");
	printf ("  --bytecode, -b           Show raw bytecode bytes (d)\n");
	printf ("  --debug, -d              Show debug information (d)\n");
	printf ("  --asmsyntax              Use CPU-like asm syntax (d, dis)\n");
	printf ("  --pretty-literals, -P    Force multi-line literals (c)\n");
	printf ("  --no-pretty-literals, -N Force single-line literals (c)\n");
	printf ("  --no-comments, -C        Suppress comments in output (c)\n");
}

static const Command *find_command(const char *name) {
	for (size_t i = 0; i < sizeof (commands) / sizeof (commands[0]); i++) {
		if (streq (name, commands[i].name)) {
			return &commands[i];
		}
	}
	return NULL;
}

int main(int argc, char **argv) {
	CliContext ctx = { argv[0] };
	if (argc < 2) {
		print_usage (ctx.program_name);
		return 1;
	}

	const char *command_name = argv[1];
	const Command *cmd = find_command (command_name);
	if (!cmd) {
		print_usage (ctx.program_name);
		eprintf ("Unknown command: %s", command_name);
		return 1;
	}

	Result r = cmd->handler (&ctx, argc - 2, argv + 2);
	if (r.code != RESULT_SUCCESS) {
		eprintf ("%s", r.error_message[0]? r.error_message: "Unknown error");
		return 1;
	}
	return 0;
}
