#include "common.h"
#include "hermesdec/hermesdec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void print_usage(const char* program_name) {
    printf("Usage: %s <command> <input_file> [output_file]\n\n", program_name);
    printf("Commands:\n");
    printf("  disassemble, dis, d    Disassemble a Hermes bytecode file\n");
    printf("  decompile, dec, c      Decompile a Hermes bytecode file\n");
    printf("  header, h              Display the header information only\n");
    printf("  validate, v            Validate file format and display detailed info\n");
    printf("  r2script, r2, r        Generate an r2 script with function flags\n");
    printf("  funcs                  Dump first N function headers (id, offset, size, name)\n");
    printf("  cmp, compare           Compare first N funcs (offset/size) with parser.txt\n");
    printf("  cmpfunc                Compare instructions for one function vs Python disasm\n");
    printf("  str                    Print a string by index (use N as [output_file])\n");
    printf("  findstr                Find string by substring (use needle as [output_file])\n");
    printf("  strmeta                Show string entry meta (index -> isUTF16, off, len)\n");
    printf("\nOptions:\n");
    printf("  --verbose, -v          Show detailed metadata\n");
    printf("  --json, -j             Output in JSON format (disassembler only)\n");
    printf("  --bytecode, -b         Show raw bytecode bytes (disassembler only)\n");
    printf("  --debug, -d            Show debug information (disassembler only)\n");
}

static Result parse_args(int argc, char** argv, char** command, char** input_file, char** output_file, DisassemblyOptions* options) {
    if (argc < 3) {
        print_usage(argv[0]);
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Not enough arguments");
    }
    *command = argv[1];
    *input_file = argv[2];
    *output_file = NULL;
    options->verbose = false;
    options->output_json = false;
    options->show_bytecode = false;
    options->show_debug_info = false;
    for (int i = 3; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) options->verbose = true;
            else if (!strcmp(argv[i], "--json") || !strcmp(argv[i], "-j")) options->output_json = true;
            else if (!strcmp(argv[i], "--bytecode") || !strcmp(argv[i], "-b")) options->show_bytecode = true;
            else if (!strcmp(argv[i], "--debug") || !strcmp(argv[i], "-d")) options->show_debug_info = true;
            else printf("Warning: Unknown option '%s'\n", argv[i]);
        } else { *output_file = argv[i]; break; }
    }
    return SUCCESS_RESULT();
}

int main(int argc, char** argv) {
    char* command = NULL; char* input_file = NULL; char* output_file = NULL; DisassemblyOptions options; Result result;
    result = parse_args(argc, argv, &command, &input_file, &output_file, &options);
    if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Error: %s\n", result.error_message); return 1; }

    if (!strcmp(command, "disassemble") || !strcmp(command, "dis") || !strcmp(command, "d")) {
        HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        StringBuffer out; string_buffer_init(&out, 16 * 1024);
        result = hermesdec_disassemble_all_to_buffer(hd, options, &out);
        if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Disassembly error: %s\n", result.error_message); string_buffer_free(&out); hermesdec_close(hd); return 1; }
        FILE* f = stdout; if (output_file) { f = fopen(output_file, "w"); if (!f) { perror("fopen"); string_buffer_free(&out); hermesdec_close(hd); return 1; }}
        fputs(out.data, f);
        if (output_file) { fclose(f); printf("\n[+] Disassembly output wrote to \"%s\"\n\n", output_file); }
        string_buffer_free(&out); hermesdec_close(hd);
    } else if (!strcmp(command, "decompile") || !strcmp(command, "dec") || !strcmp(command, "c")) {
        result = hermesdec_decompile_file(input_file, output_file);
        if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Decompilation error: %s\n", result.error_message); return 1; }
    } else if (!strcmp(command, "r2script") || !strcmp(command, "r2") || !strcmp(command, "r")) {
        result = hermesdec_generate_r2_script(input_file, output_file);
        if (result.code != RESULT_SUCCESS) { fprintf(stderr, "R2 script generation error: %s\n", result.error_message); return 1; }
    } else if (!strcmp(command, "validate") || !strcmp(command, "v")) {
        HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        StringBuffer sb; string_buffer_init(&sb, 4096);
        result = hermesdec_validate_basic(hd, &sb);
        if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Validate error: %s\n", result.error_message); string_buffer_free(&sb); hermesdec_close(hd); return 1; }
        FILE* out = stdout; if (output_file) { out = fopen(output_file, "w"); if (!out) { perror("fopen"); string_buffer_free(&sb); hermesdec_close(hd); return 1; }}
        fputs(sb.data, out); if (output_file) fclose(out);
        string_buffer_free(&sb); hermesdec_close(hd);
    } else if (!strcmp(command, "header") || !strcmp(command, "h")) {
        HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        HermesHeader hh; result = hermesdec_get_header(hd, &hh); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Header error: %s\n", result.error_message); hermesdec_close(hd); return 1; }
        FILE* out = stdout; if (output_file) { out = fopen(output_file, "w"); if (!out) { perror("fopen"); hermesdec_close(hd); return 1; }}
        fprintf(out, "Hermes Bytecode File Header:\n");
        fprintf(out, "  Magic: 0x%016llx\n", (unsigned long long)hh.magic);
        fprintf(out, "  Version: %u\n", hh.version);
        fprintf(out, "  Source Hash: "); for (int i = 0; i < 20; i++) fprintf(out, "%02x", hh.sourceHash[i]); fprintf(out, "\n");
        fprintf(out, "  File Length: %u bytes\n  Global Code Index: %u\n  Function Count: %u\n  String Kind Count: %u\n  Identifier Count: %u\n  String Count: %u\n  Overflow String Count: %u\n  String Storage Size: %u bytes\n",
                hh.fileLength, hh.globalCodeIndex, hh.functionCount, hh.stringKindCount, hh.identifierCount, hh.stringCount, hh.overflowStringCount, hh.stringStorageSize);
        if (hh.version >= 87) fprintf(out, "  BigInt Count: %u\n  BigInt Storage Size: %u bytes\n", hh.bigIntCount, hh.bigIntStorageSize);
        fprintf(out, "  RegExp Count: %u\n  RegExp Storage Size: %u bytes\n  Array Buffer Size: %u bytes\n  Object Key Buffer Size: %u bytes\n  Object Value Buffer Size: %u bytes\n",
                hh.regExpCount, hh.regExpStorageSize, hh.arrayBufferSize, hh.objKeyBufferSize, hh.objValueBufferSize);
        fprintf(out, "  %s: %u\n  CJS Module Count: %u\n", (hh.version < 78) ? "CJS Module Offset" : "Segment ID", hh.segmentID, hh.cjsModuleCount);
        if (hh.version >= 84) fprintf(out, "  Function Source Count: %u\n", hh.functionSourceCount);
        fprintf(out, "  Debug Info Offset: %u\n  Flags:\n    Static Builtins: %s\n    CJS Modules Statically Resolved: %s\n    Has Async: %s\n",
                hh.debugInfoOffset, hh.staticBuiltins ? "Yes" : "No", hh.cjsModulesStaticallyResolved ? "Yes" : "No", hh.hasAsync ? "Yes" : "No");
        if (output_file) fclose(out); hermesdec_close(hd);
    } else if (!strcmp(command, "cmp") || !strcmp(command, "compare")) {
        u32 N = 100; if (output_file && output_file[0] && isdigit((unsigned char)output_file[0])) { N = (u32)atoi(output_file); if (!N) N = 100; }
        HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        u32 fc = hermesdec_function_count(hd); u32 count = fc < N ? fc : N;
        const char *py_path = "parser.txt"; FILE *py = fopen(py_path, "r"); if (!py) { fprintf(stderr, "Error: could not open %s\n", py_path); hermesdec_close(hd); return 1; }
        u32 *py_sizes = (u32*)calloc(count, sizeof(u32)); u32 *py_offs = (u32*)calloc(count, sizeof(u32));
        if (!py_sizes || !py_offs) { fprintf(stderr, "Error: OOM\n"); fclose(py); hermesdec_close(hd); free(py_sizes); free(py_offs); return 1; }
        char line[4096]; while (fgets(line, sizeof(line), py)) { const char *needle = "=> [Function #"; char *p = strstr(line, needle); if (!p) continue; p += strlen(needle); char *end=NULL; long id = strtol(p, &end, 10); if (end==p || id<0 || (u32)id>=count) continue; char *ofp = strstr(end, " of "); if (!ofp) continue; ofp += 4; long sz = strtol(ofp, &end, 10); if (end==ofp || sz<0) continue; char *offp = strstr(end, " offset "); if (!offp) continue; offp += 8; unsigned int off=0; if (sscanf(offp, "%x", &off) != 1) continue; py_sizes[id] = (u32)sz; py_offs[id] = (u32)off; }
        fclose(py);
        for (u32 i = 0; i < count; i++) { const char* name; u32 co=0, cs=0, argc=0; hermesdec_get_function_info(hd, i, &name, &co, &cs, &argc); u32 po = py_offs[i]; u32 ps = py_sizes[i]; const char *res = (co == po && cs == ps) ? "OK" : "MISMATCH"; printf("id=%u C(off=0x%08x,sz=%u) PY(off=0x%08x,sz=%u) => %s\n", i, co, cs, po, ps, res); }
        free(py_sizes); free(py_offs); hermesdec_close(hd);
    } else if (!strcmp(command, "cmpfunc")) {
        if (argc < 5) { fprintf(stderr, "Usage: %s cmpfunc <input_file> <python_dis_file> <function_id>\n", argv[0]); return 1; }
        const char* python_dis_file = argv[3]; u32 function_id = (u32)strtoul(argv[4], NULL, 0);
        HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        if (function_id >= hermesdec_function_count(hd)) { fprintf(stderr, "Invalid function id %u\n", function_id); hermesdec_close(hd); return 1; }
        DisassemblyOptions opt = (DisassemblyOptions){0}; StringBuffer out; string_buffer_init(&out, 8192); hermesdec_disassemble_function_to_buffer(hd, function_id, opt, &out);
        FILE* py = fopen(python_dis_file, "r"); if (!py) { fprintf(stderr, "Error: could not open %s\n", python_dis_file); string_buffer_free(&out); hermesdec_close(hd); return 1; }
        char line_py[2048]; char* cbuf = out.data; char line_c[2048]; size_t cpos = 0;
        while (fgets(line_py, sizeof(line_py), py)) { if (strncmp(line_py, ">> ", 3) != 0) continue; while (cbuf[cpos] && strncmp(&cbuf[cpos], "==> ", 4) != 0) { while (cbuf[cpos] && cbuf[cpos] != '\n') cpos++; if (cbuf[cpos] == '\n') cpos++; } if (!cbuf[cpos]) break; size_t l = 0; while (cbuf[cpos + l] && cbuf[cpos + l] != '\n' && l < sizeof(line_c)-1) { line_c[l] = cbuf[cpos + l]; l++; } line_c[l] = '\0'; cpos += l; if (cbuf[cpos] == '\n') cpos++; printf("C: %s\nP: %s\n\n", line_c, line_py); }
        fclose(py); string_buffer_free(&out); hermesdec_close(hd);
    } else if (!strcmp(command, "str")) {
        if (!output_file) { fprintf(stderr, "Usage: %s str <input_file> <index>\n", argv[0]); return 1; }
        long idx = strtol(output_file, NULL, 10); if (idx < 0) { fprintf(stderr, "Invalid index\n"); return 1; }
        HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        u32 sc = hermesdec_string_count(hd); if ((u32)idx >= sc) { fprintf(stderr, "Index out of range (max %u)\n", sc); hermesdec_close(hd); return 1; }
        const char* s = NULL; hermesdec_get_string(hd, (u32)idx, &s); printf("idx=%ld name=%s\n", idx, s ? s : ""); hermesdec_close(hd);
    } else if (!strcmp(command, "findstr")) {
        if (!output_file) { fprintf(stderr, "Usage: %s findstr <input_file> <needle>\n", argv[0]); return 1; }
        const char* needle = output_file; HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        for (u32 i = 0; i < hermesdec_string_count(hd); i++) { const char *s = NULL; hermesdec_get_string(hd, i, &s); if (!s) continue; if (strstr(s, needle)) { printf("idx=%u name=%s\n", i, s); } }
        hermesdec_close(hd);
    } else if (!strcmp(command, "strmeta")) {
        if (!output_file) { fprintf(stderr, "Usage: %s strmeta <input_file> <index>\n", argv[0]); return 1; }
        long idx = strtol(output_file, NULL, 10); if (idx < 0) { fprintf(stderr, "Invalid index\n"); return 1; }
        HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        u32 sc = hermesdec_string_count(hd); if ((u32)idx >= sc) { fprintf(stderr, "Index out of range (max %u)\n", sc); hermesdec_close(hd); return 1; }
        HermesStringMeta sm; hermesdec_get_string_meta(hd, (u32)idx, &sm); printf("idx=%ld isUTF16=%u off=0x%x len=%u\n", idx, sm.isUTF16 ? 1u : 0u, sm.offset, sm.length); hermesdec_close(hd);
    } else if (!strcmp(command, "funcs")) {
        const u32 N = 50; HermesDec* hd = NULL; result = hermesdec_open(input_file, &hd); if (result.code != RESULT_SUCCESS) { fprintf(stderr, "Open error: %s\n", result.error_message); return 1; }
        u32 fc = hermesdec_function_count(hd); u32 count = fc < N ? fc : N;
        for (u32 i = 0; i < count; i++) { const char* name = NULL; u32 off=0, size=0, argc=0; hermesdec_get_function_info(hd, i, &name, &off, &size, &argc); printf("C  id=%u offset=0x%08x size=%u name=%s\n", i, off, size, name ? name : ""); }
        hermesdec_close(hd);
    } else { fprintf(stderr, "Unknown command: %s\n", command); print_usage(argv[0]); return 1; }
    return 0;
}

