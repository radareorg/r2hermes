#include "common.h"
#include "hermesdec/hermesdec.h"
#include "decompilation/literals.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#define EPRINTF(...) \
	do { \
		fprintf (stderr, "Error: " __VA_ARGS__); \
		fputc ('\n', stderr); \
	} while (0)

static void print_usage(const char *program_name) {
	printf ("Usage: %s <command> <input_file> [output_file]\n\n"
	"Commands:\n"
	"  disassemble, dis, d    Disassemble a Hermes bytecode file\n"
	"  decompile, dec, c      Decompile a Hermes bytecode file\n"
	"  asm                    Disassemble raw bytes (rasm2-like)\n"
	"  header, h              Display the header information only\n"
	"  validate, v            Validate file format and display detailed info\n"
	"  r2script, r2, r        Generate an r2 script with function flags\n"
	"  funcs                  Dump first N function headers (id, offset, size, name)\n"
	"  cmp, compare           Compare first N funcs (offset/size) with parser.txt\n"
	"  cmpfunc                Compare instructions for one function vs Python disasm\n"
	"  str                    Print a string by index (use N as [output_file])\n"
	"  findstr                Find string by substring (use needle as [output_file])\n"
	"  strmeta                Show string entry meta (index -> isUTF16, off, len)\n"
	"\nOptions:\n"
	"  --verbose, -v          Show detailed metadata\n"
	"  --json, -j             Output in JSON format (disassembler only)\n"
	"  --bytecode, -b         Show raw bytecode bytes (disassembler only)\n"
	"  --debug, -d            Show debug information (disassembler only)\n"
	"  --asmsyntax            Use CPU-like asm syntax (mnemonic operands)\n"
	"  --pretty-literals, -P  Force multi-line formatting of array/object literals (decompiler)\n"
	"  --no-pretty-literals, -N  Force single-line formatting of array/object literals (decompiler)\n"
	"  --no-comments, -C      Suppress comments in decompiled output (no headers, no inline)\n",
		program_name);
}

static size_t parse_hex_bytes(const char *hex, u8 *bytes, size_t max_len) {
	size_t len = strlen (hex);
	size_t bcount = 0;
	for (size_t i = 0; i < len && bcount < max_len; i += 2) {
		int n1 = -1, n2 = -1;
		char c1 = hex[i];
		if (c1 >= '0' && c1 <= '9') {
			n1 = c1 - '0';
		} else if (c1 >= 'a' && c1 <= 'f') {
			n1 = 10 + (c1 - 'a');
		} else if (c1 >= 'A' && c1 <= 'F') {
			n1 = 10 + (c1 - 'A');
		} else {
			break;
		}
		if (i + 1 < len) {
			char c2 = hex[i + 1];
			if (c2 >= '0' && c2 <= '9') {
				n2 = c2 - '0';
			} else if (c2 >= 'a' && c2 <= 'f') {
				n2 = 10 + (c2 - 'a');
			} else if (c2 >= 'A' && c2 <= 'F') {
				n2 = 10 + (c2 - 'A');
			} else {
				n2 = -1;
			}
		}
		if (n2 >= 0) {
			bytes[bcount++] = (u8) ((n1 << 4) | n2);
		} else {
			bytes[bcount++] = (u8)n1;
		}
	}
	return bcount;
}

static Result parse_args(int argc, char **argv, char **command, char **input_file, char **output_file, DisassemblyOptions *options) {
	if (argc < 3) {
		print_usage (argv[0]);
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Not enough arguments");
	}
	*command = argv[1];
	*input_file = argv[2];
	*output_file = NULL;
	options->verbose = false;
	options->output_json = false;
	options->show_bytecode = false;
	options->show_debug_info = false;
	options->asm_syntax = false;
	for (int i = 3; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (!strcmp (argv[i], "--verbose") || !strcmp (argv[i], "-v")) {
				options->verbose = true;
			} else if (!strcmp (argv[i], "--json") || !strcmp (argv[i], "-j")) {
				options->output_json = true;
			} else if (!strcmp (argv[i], "--bytecode") || !strcmp (argv[i], "-b")) {
				options->show_bytecode = true;
			} else if (!strcmp (argv[i], "--debug") || !strcmp (argv[i], "-d")) {
				options->show_debug_info = true;
			} else if (!strcmp (argv[i], "--asmsyntax")) {
				options->asm_syntax = true;
			} else if (!strcmp (argv[i], "--pretty-literals") || !strcmp (argv[i], "-P")) {
				set_literals_pretty_policy (LITERALS_PRETTY_ALWAYS);
			} else if (!strcmp (argv[i], "--no-pretty-literals") || !strcmp (argv[i], "-N")) {
				set_literals_pretty_policy (LITERALS_PRETTY_NEVER);
			} else if (!strcmp (argv[i], "--pretty-auto")) {
				set_literals_pretty_policy (LITERALS_PRETTY_AUTO);
			} else if (!strcmp (argv[i], "--no-comments") || !strcmp (argv[i], "-C")) {
				set_decompile_suppress_comments (true);
			} else {
				printf ("Warning: Unknown option '%s'\n", argv[i]);
			}
		} else {
			*output_file = argv[i];
			break;
		}
	}
	return SUCCESS_RESULT ();
}

int main(int argc, char **argv) {
	char *command = NULL, *input_file = NULL, *output_file = NULL;
	DisassemblyOptions options = { 0 };
	Result result = parse_args (argc, argv, &command, &input_file, &output_file, &options);
	if (result.code != RESULT_SUCCESS) {
		EPRINTF ("%s", result.error_message);
		return 1;
	}
	if (options.asm_syntax) {
		fprintf (stderr, "[hermes-dec] ASM syntax mode enabled\n");
	}

	if (!strcmp (command, "asm")) {
		const char *hex = input_file;
		u8 bytes[64];
		size_t bcount = parse_hex_bytes (hex, bytes, sizeof (bytes));
		if (bcount == 0) {
			EPRINTF ("%s", "Invalid or empty hex bytes string");
			return 1;
		}
		char *text = NULL;
		u32 sz = 0;
		u8 opc = 0;
		bool isj = false, isc = false;
		u64 jmp = 0;
		/* Default to version 96 for standalone decoding */
		Result rr = hermesdec_decode_single_instruction (bytes, bcount, 96, 0, true, false, 0, NULL, NULL, 0, &text, &sz, &opc, &isj, &isc, &jmp);
		if (rr.code != RESULT_SUCCESS) {
			EPRINTF ("%s", rr.error_message);
			return 1;
		}
		printf ("%s\n", text? text: "");
		free (text);
		return 0;
	} else if (!strcmp (command, "disassemble") || !strcmp (command, "dis") || !strcmp (command, "d")) {
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("%s", result.error_message);
			return 1;
		}
		StringBuffer out;
		string_buffer_init (&out, 16 * 1024);
		result = hermesdec_disassemble_all_to_buffer (hd, options, &out);
		if (result.code != RESULT_SUCCESS) {
			string_buffer_free (&out);
			hermesdec_close (hd);
			EPRINTF ("%s", result.error_message);
			return 1;
		}
		FILE *f = stdout;
		if (output_file) {
			f = fopen (output_file, "w");
			if (!f) {
				string_buffer_free (&out);
				hermesdec_close (hd);
				EPRINTF ("Failed to open output file");
				return 1;
			}
		}
		fputs (out.data, f);
		if (output_file) {
			fclose (f);
			printf ("\n[+] Disassembly output wrote to \"%s\"\n\n", output_file);
		}
		string_buffer_free (&out);
		hermesdec_close (hd);
	} else if (!strcmp (command, "decompile") || !strcmp (command, "dec") || !strcmp (command, "c")) {
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		StringBuffer out;
		string_buffer_init (&out, 32 * 1024);
		result = hermesdec_decompile_all_to_buffer (hd, &out);
		if (result.code != RESULT_SUCCESS) {
			string_buffer_free (&out);
			hermesdec_close (hd);
			EPRINTF ("Decompilation error: %s", result.error_message);
			return 1;
		}
		FILE *f = stdout;
		if (output_file) {
			f = fopen (output_file, "w");
			if (!f) {
				string_buffer_free (&out);
				hermesdec_close (hd);
				EPRINTF ("Failed to open output file");
				return 1;
			}
		}
		fputs (out.data, f);
		if (output_file) {
			fclose (f);
			printf ("\n[+] Decompilation output wrote to \"%s\"\n\n", output_file);
		}
		string_buffer_free (&out);
		hermesdec_close (hd);
	} else if (!strcmp (command, "r2script") || !strcmp (command, "r2") || !strcmp (command, "r")) {
		result = hermesdec_generate_r2_script (input_file, output_file);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("R2 script generation error: %s", result.error_message);
			return 1;
		}
	} else if (!strcmp (command, "validate") || !strcmp (command, "v")) {
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		StringBuffer sb;
		string_buffer_init (&sb, 4096);
		result = hermesdec_validate_basic (hd, &sb);
		if (result.code != RESULT_SUCCESS) {
			string_buffer_free (&sb);
			hermesdec_close (hd);
			EPRINTF ("Validate error: %s", result.error_message);
			return 1;
		}
		FILE *out = stdout;
		if (output_file) {
			out = fopen (output_file, "w");
			if (!out) {
				string_buffer_free (&sb);
				hermesdec_close (hd);
				EPRINTF ("Failed to open output file");
				return 1;
			}
		}
		fputs (sb.data, out);
		if (output_file) {
			fclose (out);
		}
		string_buffer_free (&sb);
		hermesdec_close (hd);
	} else if (!strcmp (command, "header") || !strcmp (command, "h")) {
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		HermesHeader hh;
		result = hermesdec_get_header (hd, &hh);
		if (result.code != RESULT_SUCCESS) {
			hermesdec_close (hd);
			EPRINTF ("Header error: %s", result.error_message);
			return 1;
		}
		FILE *out = stdout;
		if (output_file) {
			out = fopen (output_file, "w");
			if (!out) {
				hermesdec_close (hd);
				EPRINTF ("Failed to open output file");
				return 1;
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
		if (output_file) {
			fclose (out);
		}
		hermesdec_close (hd);
	} else if (!strcmp (command, "cmp") || !strcmp (command, "compare")) {
		u32 N = 100;
		if (output_file && output_file[0] && isdigit ((unsigned char)output_file[0])) {
			N = (u32)atoi (output_file);
			if (!N) {
				N = 100;
			}
		}
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		u32 fc = hermesdec_function_count (hd);
		u32 count = fc < N? fc: N;
		const char *py_path = "parser.txt";
		FILE *py = fopen (py_path, "r");
		if (!py) {
			hermesdec_close (hd);
			EPRINTF ("could not open %s", py_path);
			return 1;
		}
		u32 *py_sizes = (u32 *)calloc (count, sizeof (u32));
		u32 *py_offs = (u32 *)calloc (count, sizeof (u32));
		if (!py_sizes || !py_offs) {
			fclose (py);
			hermesdec_close (hd);
			free (py_sizes);
			free (py_offs);
			EPRINTF ("%s", "OOM");
			return 1;
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
			char *offp = strstr (end, " offset ");
			if (!offp) {
				continue;
			}
			offp += 8;
			unsigned int off = 0;
			if (sscanf (offp, "%x", &off) != 1) {
				continue;
			}
			py_sizes[id] = (u32)sz;
			py_offs[id] = (u32)off;
		}
		fclose (py);
		for (u32 i = 0; i < count; i++) {
			const char *name;
			u32 co = 0, cs = 0, argc = 0;
			hermesdec_get_function_info (hd, i, &name, &co, &cs, &argc);
			u32 po = py_offs[i];
			u32 ps = py_sizes[i];
			const char *res = (co == po && cs == ps)? "OK": "MISMATCH";
			printf ("id=%u C(off=0x%08x,sz=%u) PY(off=0x%08x,sz=%u) => %s\n", i, co, cs, po, ps, res);
		}
		free (py_sizes);
		free (py_offs);
		hermesdec_close (hd);
	} else if (!strcmp (command, "cmpfunc")) {
		if (argc < 5) {
			EPRINTF ("Usage: %s cmpfunc <input_file> <python_dis_file> <function_id>", argv[0]);
			return 1;
		}
		const char *python_dis_file = argv[3];
		u32 function_id = (u32)strtoul (argv[4], NULL, 0);
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		if (function_id >= hermesdec_function_count (hd)) {
			hermesdec_close (hd);
			EPRINTF ("Invalid function id %u", function_id);
			return 1;
		}
		DisassemblyOptions opt = (DisassemblyOptions){ 0 };
		StringBuffer out;
		string_buffer_init (&out, 8192);
		hermesdec_disassemble_function_to_buffer (hd, function_id, opt, &out);
		FILE *py = fopen (python_dis_file, "r");
		if (!py) {
			string_buffer_free (&out);
			hermesdec_close (hd);
			EPRINTF ("could not open %s", python_dis_file);
			return 1;
		}
		char line_py[2048];
		char *cbuf = out.data;
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
		string_buffer_free (&out);
		hermesdec_close (hd);
	} else if (!strcmp (command, "str")) {
		if (!output_file) {
			EPRINTF ("Usage: %s str <input_file> <index>", argv[0]);
			return 1;
		}
		long idx = strtol (output_file, NULL, 10);
		if (idx < 0) {
			EPRINTF ("%s", "Invalid index");
			return 1;
		}
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		u32 sc = hermesdec_string_count (hd);
		if ((u32)idx >= sc) {
			hermesdec_close (hd);
			EPRINTF ("Index out of range (max %u)", sc);
			return 1;
		}
		const char *s = NULL;
		hermesdec_get_string (hd, (u32)idx, &s);
		printf ("idx=%ld name=%s\n", idx, s? s: "");
		hermesdec_close (hd);
	} else if (!strcmp (command, "findstr")) {
		if (!output_file) {
			EPRINTF ("Usage: %s findstr <input_file> <needle>", argv[0]);
			return 1;
		}
		const char *needle = output_file;
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		for (u32 i = 0; i < hermesdec_string_count (hd); i++) {
			const char *s = NULL;
			hermesdec_get_string (hd, i, &s);
			if (!s) {
				continue;
			}
			if (strstr (s, needle)) {
				printf ("idx=%u name=%s\n", i, s);
			}
		}
		hermesdec_close (hd);
	} else if (!strcmp (command, "strmeta")) {
		if (!output_file) {
			EPRINTF ("Usage: %s strmeta <input_file> <index>", argv[0]);
			return 1;
		}
		long idx = strtol (output_file, NULL, 10);
		if (idx < 0) {
			EPRINTF ("Invalid index");
			return 1;
		}
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		u32 sc = hermesdec_string_count (hd);
		if ((u32)idx >= sc) {
			hermesdec_close (hd);
			EPRINTF ("Index out of range (max %u)", sc);
			return 1;
		}
		HermesStringMeta sm;
		hermesdec_get_string_meta (hd, (u32)idx, &sm);
		printf ("idx=%ld isUTF16=%u off=0x%x len=%u\n", idx, sm.isUTF16? 1u: 0u, sm.offset, sm.length);
		hermesdec_close (hd);
	} else if (!strcmp (command, "funcs")) {
		const u32 N = 50;
		HermesDec *hd = NULL;
		result = hermesdec_open (input_file, &hd);
		if (result.code != RESULT_SUCCESS) {
			EPRINTF ("Open error: %s", result.error_message);
			return 1;
		}
		u32 fc = hermesdec_function_count (hd);
		u32 count = fc < N? fc: N;
		for (u32 i = 0; i < count; i++) {
			const char *name = NULL;
			u32 off = 0, size = 0, argc = 0;
			hermesdec_get_function_info (hd, i, &name, &off, &size, &argc);
			printf ("C  id=%u offset=0x%08x size=%u name=%s\n", i, off, size, name? name: "");
		}
		hermesdec_close (hd);
	} else {
		print_usage (argv[0]);
		EPRINTF ("Unknown command: %s", command);
		return 1;
	}
	return 0;
}
