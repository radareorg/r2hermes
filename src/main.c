#include "../include/common.h"
#include "../include/parsers/hbc_file_parser.h"
#include "../include/disassembly/hbc_disassembler.h"
#include "../include/parsers/hbc_bytecode_parser.h"
#include "../include/decompilation/decompiler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Print usage information */
static void print_usage(const char* program_name) {
    printf("Usage: %s <command> <input_file> [output_file]\n\n", program_name);
    printf("Commands:\n");
    printf("  disassemble, dis, d    Disassemble a Hermes bytecode file\n");
    printf("  decompile, dec, c      Decompile a Hermes bytecode file\n");
    printf("  header, h              Display the header information only\n");
    printf("  validate, v            Validate file format and display detailed info\n");
    printf("  r2script, r2, r        Generate an r2 script with function flags\n");
    printf("  funcs                  Dump first N function headers (id, nameIdx, offset, size)\n");
    printf("  cmp, compare           Compare first N funcs (offset/size) with parser.txt\n");
    printf("  cmpfunc                Compare instructions for one function vs Python disasm\n");
    printf("  str                    Print a string by index (use N as [output_file])\n");
    printf("  findstr                Find string by substring (use needle as [output_file])\n");
    printf("  strmeta                Show string entry meta (index -> isUTF16, off, len)\n");
    printf("\n");
    printf("Options:\n");
    printf("  --verbose, -v          Show detailed metadata\n");
    printf("  --json, -j             Output in JSON format (disassembler only)\n");
    printf("  --bytecode, -b         Show raw bytecode bytes (disassembler only)\n");
    printf("  --debug, -d            Show debug information (disassembler only)\n");
    printf("\n");
    printf("If no output file is specified, output will be written to stdout.\n");
}

/* Parse command line arguments */
static Result parse_args(int argc, char** argv, 
                       char** command, 
                       char** input_file, 
                       char** output_file,
                       DisassemblyOptions* options) {
    if (argc < 3) {
        print_usage(argv[0]);
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Not enough arguments");
    }

    /* Set command */
    *command = argv[1];
    *input_file = argv[2];
    *output_file = NULL;
    
    /* Default options */
    options->verbose = false;
    options->output_json = false;
    options->show_bytecode = false;
    options->show_debug_info = false;
    
    /* Parse remaining arguments */
    for (int i = 3; i < argc; i++) {
        if (argv[i][0] == '-') {
            /* This is an option */
            if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
                options->verbose = true;
            } 
            else if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
                options->output_json = true;
            }
            else if (strcmp(argv[i], "--bytecode") == 0 || strcmp(argv[i], "-b") == 0) {
                options->show_bytecode = true;
            }
            else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
                options->show_debug_info = true;
            }
            else {
                printf("Warning: Unknown option '%s'\n", argv[i]);
            }
        } 
        else {
            /* This is the output file */
            *output_file = argv[i];
            /* Any remaining arguments are ignored */
            break;
        }
    }
    
    return SUCCESS_RESULT();
}

int main(int argc, char** argv) {
    char* command = NULL;
    char* input_file = NULL;
    char* output_file = NULL;
    DisassemblyOptions options;
    Result result;

    /* Parse command line arguments */
    result = parse_args(argc, argv, &command, &input_file, &output_file, &options);
    if (result.code != RESULT_SUCCESS) {
        fprintf(stderr, "Error: %s\n", result.error_message);
        return 1;
    }
    
    /* Execute the requested command */
    if (strcmp(command, "disassemble") == 0 || 
        strcmp(command, "dis") == 0 || 
        strcmp(command, "d") == 0) {
        
        result = disassemble_file(input_file, output_file, options);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Disassembly error: %s\n", result.error_message);
            return 1;
        }
    }
    else if (strcmp(command, "decompile") == 0 || 
             strcmp(command, "dec") == 0 || 
             strcmp(command, "c") == 0) {
        
        result = decompile_file(input_file, output_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Decompilation error: %s\n", result.error_message);
            return 1;
        }
    }
    else if (strcmp(command, "r2script") == 0 || 
             strcmp(command, "r2") == 0 || 
             strcmp(command, "r") == 0) {
        
        result = generate_r2_script(input_file, output_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "R2 script generation error: %s\n", result.error_message);
            return 1;
        }
    }
    else if (strcmp(command, "header") == 0 || 
             strcmp(command, "h") == 0 ||
             strcmp(command, "validate") == 0 ||
             strcmp(command, "v") == 0) {
        
        /* Initialize HBC reader */
        HBCReader reader;
        result = hbc_reader_init(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error initializing HBC reader: %s\n", result.error_message);
            return 1;
        }
        
        /* Read and parse the header */
        result = hbc_reader_read_file(&reader, input_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading file: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        
        result = hbc_reader_read_header(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading header: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        
        /* For validation command, add more detailed checks */
        if (strcmp(command, "validate") == 0 || strcmp(command, "v") == 0) {
            fprintf(stdout, "File size: %zu bytes\n", reader.file_buffer.size);
            fprintf(stdout, "Current position after header read: %zu\n", reader.file_buffer.position);
            
            /* Sanity check on reported file length */
            if (reader.header.fileLength != reader.file_buffer.size) {
                fprintf(stdout, "Warning: Reported file length (%u) doesn't match actual file size (%zu)\n", 
                    reader.header.fileLength, reader.file_buffer.size);
            }
            
            /* Validate function count */
            fprintf(stdout, "Functions count: %u\n", reader.header.functionCount);
            size_t min_bytes_needed = reader.header.functionCount * 16; /* Minimum bytes for function headers */
            if (min_bytes_needed > reader.file_buffer.size - reader.file_buffer.position) {
                fprintf(stdout, "Warning: File appears to be too small for reported function count!\n");
                fprintf(stdout, "Need at least %zu more bytes for function headers.\n", min_bytes_needed);
            } else {
                fprintf(stdout, "Function data fits within file size (needs %zu bytes).\n", min_bytes_needed);
            }
            
            /* Check for binary layout */
            fprintf(stdout, "\nBinary structure validation:\n");
            u8 first_bytes[16];
            size_t saved_pos = reader.file_buffer.position;
            
            /* Try reading from where function data should start */
            if (reader.file_buffer.position + 16 <= reader.file_buffer.size) {
                memcpy(first_bytes, reader.file_buffer.data + reader.file_buffer.position, 16);
                fprintf(stdout, "First 16 bytes at function data position: ");
                for (int i = 0; i < 16; i++) {
                    fprintf(stdout, "%02x ", first_bytes[i]);
                }
                fprintf(stdout, "\n");
            }
            
            /* Reset position */
            reader.file_buffer.position = saved_pos;
        }
        
        /* Open output file if specified */
        FILE* out = stdout;
        if (output_file) {
            out = fopen(output_file, "w");
            if (!out) {
                fprintf(stderr, "Error opening output file: %s\n", output_file);
                hbc_reader_cleanup(&reader);
                return 1;
            }
        }
        
        /* Print header information */
        fprintf(out, "Hermes Bytecode File Header:\n");
        fprintf(out, "  Magic: 0x%016llx\n", (unsigned long long)reader.header.magic);
        fprintf(out, "  Version: %u\n", reader.header.version);
        fprintf(out, "  Source Hash: ");
        for (int i = 0; i < SHA1_NUM_BYTES; i++) {
            fprintf(out, "%02x", reader.header.sourceHash[i]);
        }
        fprintf(out, "\n");
        fprintf(out, "  File Length: %u bytes\n", reader.header.fileLength);
        fprintf(out, "  Global Code Index: %u\n", reader.header.globalCodeIndex);
        fprintf(out, "  Function Count: %u\n", reader.header.functionCount);
        fprintf(out, "  String Kind Count: %u\n", reader.header.stringKindCount);
        fprintf(out, "  Identifier Count: %u\n", reader.header.identifierCount);
        fprintf(out, "  String Count: %u\n", reader.header.stringCount);
        fprintf(out, "  Overflow String Count: %u\n", reader.header.overflowStringCount);
        fprintf(out, "  String Storage Size: %u bytes\n", reader.header.stringStorageSize);
        
        if (reader.header.version >= 87) {
            fprintf(out, "  BigInt Count: %u\n", reader.header.bigIntCount);
            fprintf(out, "  BigInt Storage Size: %u bytes\n", reader.header.bigIntStorageSize);
        }
        
        fprintf(out, "  RegExp Count: %u\n", reader.header.regExpCount);
        fprintf(out, "  RegExp Storage Size: %u bytes\n", reader.header.regExpStorageSize);
        fprintf(out, "  Array Buffer Size: %u bytes\n", reader.header.arrayBufferSize);
        fprintf(out, "  Object Key Buffer Size: %u bytes\n", reader.header.objKeyBufferSize);
        fprintf(out, "  Object Value Buffer Size: %u bytes\n", reader.header.objValueBufferSize);
        
        if (reader.header.version < 78) {
            fprintf(out, "  CJS Module Offset: %u\n", reader.header.segmentID);
        } else {
            fprintf(out, "  Segment ID: %u\n", reader.header.segmentID);
        }
        
        fprintf(out, "  CJS Module Count: %u\n", reader.header.cjsModuleCount);
        
        if (reader.header.version >= 84) {
            fprintf(out, "  Function Source Count: %u\n", reader.header.functionSourceCount);
        }
        
        fprintf(out, "  Debug Info Offset: %u\n", reader.header.debugInfoOffset);
        fprintf(out, "  Flags:\n");
        fprintf(out, "    Static Builtins: %s\n", reader.header.staticBuiltins ? "Yes" : "No");
        fprintf(out, "    CJS Modules Statically Resolved: %s\n", reader.header.cjsModulesStaticallyResolved ? "Yes" : "No");
        fprintf(out, "    Has Async: %s\n", reader.header.hasAsync ? "Yes" : "No");
        
        if (output_file) {
            fclose(out);
        }
        
        hbc_reader_cleanup(&reader);
    }
    else if (strcmp(command, "cmp") == 0 || strcmp(command, "compare") == 0) {
        /* Compare first N function headers (offset/size) against parser.txt */
        u32 N = 100; /* default count */
        if (output_file && output_file[0] && isdigit((unsigned char)output_file[0])) {
            N = (u32)atoi(output_file);
            if (N == 0) N = 100;
        }

        /* Initialize HBC reader */
        HBCReader reader;
        Result result = hbc_reader_init(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error: %s\n", result.error_message);
            return 1;
        }

        /* Read whole file */
        result = hbc_reader_read_whole_file(&reader, input_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading file: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }

        u32 count = reader.header.functionCount < N ? reader.header.functionCount : N;

        /* Load Python parser output from parser.txt in current dir */
        const char *py_path = "parser.txt";
        FILE *py = fopen(py_path, "r");
        if (!py) {
            fprintf(stderr, "Error: could not open %s for comparison\n", py_path);
            hbc_reader_cleanup(&reader);
            return 1;
        }

        /* Prepare arrays for Python offsets/sizes */
        u32 *py_sizes = (u32*)calloc(count, sizeof(u32));
        u32 *py_offs  = (u32*)calloc(count, sizeof(u32));
        if (!py_sizes || !py_offs) {
            fprintf(stderr, "Error: memory allocation failure\n");
            fclose(py);
            hbc_reader_cleanup(&reader);
            free(py_sizes); free(py_offs);
            return 1;
        }

        /* Parse lines like: => [Function #ID name of SIZE bytes]: ... @ offset 0xHEX */
        char line[4096];
        while (fgets(line, sizeof(line), py)) {
            const char *needle = "=> [Function #";
            char *p = strstr(line, needle);
            if (!p) continue;
            p += strlen(needle);
            char *end = NULL;
            long id = strtol(p, &end, 10);
            if (end == p || id < 0) continue;
            if ((u32)id >= count) continue;

            /* Find " of " then number then " bytes]" */
            char *ofp = strstr(end, " of ");
            if (!ofp) continue;
            ofp += 4;
            long sz = strtol(ofp, &end, 10);
            if (end == ofp || sz < 0) continue;

            /* Find " offset " then hex */
            char *offp = strstr(end, " offset ");
            if (!offp) continue;
            offp += 8;
            unsigned int off = 0;
            if (sscanf(offp, "%x", &off) != 1) continue;

            py_sizes[id] = (u32)sz;
            py_offs[id]  = (u32)off;
        }
        fclose(py);

        /* Compare and print compact report */
        for (u32 i = 0; i < count; i++) {
            FunctionHeader *fh = &reader.function_headers[i];
            u32 co = fh->offset;
            u32 cs = fh->bytecodeSizeInBytes;
            u32 po = py_offs[i];
            u32 ps = py_sizes[i];
            const char *res = (co == po && cs == ps) ? "OK" : "MISMATCH";
            printf("id=%u C(off=0x%08x,sz=%u) PY(off=0x%08x,sz=%u) => %s\n", i, co, cs, po, ps, res);
        }

        /* Cleanup */
        free(py_sizes);
        free(py_offs);
        hbc_reader_cleanup(&reader);
    }
    else if (strcmp(command, "cmpfunc") == 0) {
        /* Compare instruction stream for a single function against Python's disassembly file */
        if (argc < 5) {
            fprintf(stderr, "Usage: %s cmpfunc <input_file> <python_dis_file> <function_id>\n", argv[0]);
            return 1;
        }
        const char* python_dis_file = argv[3];
        u32 function_id = (u32)strtoul(argv[4], NULL, 0);

        /* Initialize HBC reader */
        HBCReader reader;
        Result result = hbc_reader_init(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error: %s\n", result.error_message);
            return 1;
        }

        /* Read whole file and strings */
        result = hbc_reader_read_whole_file(&reader, input_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading file: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }

        /* Ensure function bytecode is loaded */
        if (function_id >= reader.header.functionCount) {
            fprintf(stderr, "Invalid function id %u (max %u)\n", function_id, reader.header.functionCount);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        FunctionHeader* fh = &reader.function_headers[function_id];
        if (fh->bytecode == NULL && fh->bytecodeSizeInBytes > 0) {
            if (fh->offset + fh->bytecodeSizeInBytes <= reader.file_buffer.size) {
                fh->bytecode = (u8*)malloc(fh->bytecodeSizeInBytes);
                if (!fh->bytecode) {
                    fprintf(stderr, "OOM allocating bytecode buffer (%u bytes)\n", fh->bytecodeSizeInBytes);
                    hbc_reader_cleanup(&reader);
                    return 1;
                }
                size_t saved = reader.file_buffer.position;
                Result sr = buffer_reader_seek(&reader.file_buffer, fh->offset);
                if (sr.code != RESULT_SUCCESS) {
                    fprintf(stderr, "Seek failure reading bytecode\n");
                    free(fh->bytecode); fh->bytecode = NULL;
                    hbc_reader_cleanup(&reader);
                    return 1;
                }
                sr = buffer_reader_read_bytes(&reader.file_buffer, fh->bytecode, fh->bytecodeSizeInBytes);
                buffer_reader_seek(&reader.file_buffer, saved);
                if (sr.code != RESULT_SUCCESS) {
                    fprintf(stderr, "Read failure reading bytecode\n");
                    free(fh->bytecode); fh->bytecode = NULL;
                    hbc_reader_cleanup(&reader);
                    return 1;
                }
            }
        }

        /* Parse function bytecode in C */
        ParsedInstructionList cilist;
        result = parsed_instruction_list_init(&cilist, 64);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error init instruction list: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        result = parse_function_bytecode(&reader, function_id, &cilist);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error parsing function #%u: %s\n", function_id, result.error_message);
            parsed_instruction_list_free(&cilist);
            hbc_reader_cleanup(&reader);
            return 1;
        }

        /* Read Python disassembly file and extract function block */
        FILE* pf = fopen(python_dis_file, "r");
        if (!pf) {
            fprintf(stderr, "Error opening Python disassembly file: %s\n", python_dis_file);
            parsed_instruction_list_free(&cilist);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        char* line = NULL;
        size_t n = 0;
        ssize_t len;
        char func_hdr[64];
        snprintf(func_hdr, sizeof(func_hdr), "=> [Function #%u ", function_id);

        /* Find header */
        int in_func = 0;
        int in_listing = 0;
        typedef struct { u32 off; char name[64]; } PyInst;
        PyInst* py = NULL; size_t pycap = 0; size_t pycnt = 0;

        while ((len = getline(&line, &n, pf)) != -1) {
            if (!in_func) {
                if (strstr(line, func_hdr)) {
                    in_func = 1;
                }
                continue;
            }
            if (!in_listing) {
                if (strstr(line, "Bytecode listing:")) {
                    in_listing = 1;
                }
                continue;
            }
            if (strncmp(line, "==>", 3) != 0) {
                if (in_listing && line[0] == '=') break; /* reached separator */
                /* skip blank lines until we actually start reading instructions */
                if (in_listing && pycnt > 0 && line[0] == '\n') break; /* end of block */
                continue;
            }
            /* Parse: ==> 0000000d: <MNEMONIC>: ... */
            char offhex[16] = {0};
            char mnem[64] = {0};
            unsigned offu = 0;
            if (sscanf(line, "==> %8[^:]: <%63[^>]>:", offhex, mnem) == 2) {
                offu = (unsigned)strtoul(offhex, NULL, 16);
                if (pycnt == pycap) {
                    pycap = pycap ? pycap * 2 : 128;
                    py = (PyInst*)realloc(py, pycap * sizeof(PyInst));
                    if (!py) { fprintf(stderr, "OOM reading python disasm\n"); break; }
                }
                py[pycnt].off = offu;
                strncpy(py[pycnt].name, mnem, sizeof(py[pycnt].name)-1);
                py[pycnt].name[sizeof(py[pycnt].name)-1] = '\0';
                pycnt++;
            }
        }
        if (line) free(line);
        fclose(pf);

        if (pycnt == 0) {
            fprintf(stderr, "No Python listing found for function #%u\n", function_id);
            parsed_instruction_list_free(&cilist);
            hbc_reader_cleanup(&reader);
            free(py);
            return 1;
        }

        /* Compare streams */
        size_t i = 0, j = 0; int mismatch = 0;
        while (i < cilist.count && j < pycnt) {
            ParsedInstruction* ci = &cilist.instructions[i];
            const char* cname = ci->inst ? ci->inst->name : "?";
            if (ci->original_pos != py[j].off || strcmp(cname, py[j].name) != 0) {
                fprintf(stderr, "Mismatch at index %zu: C(off=%08x,name=%s) vs PY(off=%08x,name=%s)\n",
                        i, ci->original_pos, cname, py[j].off, py[j].name);
                /* Print a small window */
                fprintf(stderr, "Context (C):\n");
                size_t s = (i>3? i-3:0), e = (i+3<cilist.count? i+3:cilist.count-1);
                for (size_t k=s; k<=e; k++) {
                    fprintf(stderr, "  [%zu] %08x %s\n", k, cilist.instructions[k].original_pos, cilist.instructions[k].inst?cilist.instructions[k].inst->name:"?");
                }
                fprintf(stderr, "Context (PY):\n");
                s = (j>3? j-3:0); e = (j+3<pycnt? j+3:pycnt-1);
                for (size_t k=s; k<=e; k++) {
                    fprintf(stderr, "  [%zu] %08x %s\n", k, py[k].off, py[k].name);
                }
                mismatch = 1;
                break;
            }
            i++; j++;
        }
        if (!mismatch && (i != cilist.count || j != pycnt)) {
            fprintf(stderr, "Length mismatch: C=%u instructions, PY=%zu instructions\n", cilist.count, pycnt);
            mismatch = 1;
        }
        if (!mismatch) {
            fprintf(stderr, "cmpfunc: Function #%u streams match (%u instrs).\n", function_id, cilist.count);
        }

        free(py);
        parsed_instruction_list_free(&cilist);
        hbc_reader_cleanup(&reader);
    }
    else if (strcmp(command, "str") == 0) {
        /* Print string by index passed in output_file param */
        if (!output_file) {
            fprintf(stderr, "Usage: %s str <input_file> <index>\n", argv[0]);
            return 1;
        }
        long idx = strtol(output_file, NULL, 10);
        if (idx < 0) {
            fprintf(stderr, "Invalid index\n");
            return 1;
        }

        HBCReader reader;
        Result result = hbc_reader_init(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error: %s\n", result.error_message);
            return 1;
        }
        result = hbc_reader_read_whole_file(&reader, input_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading file: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }

        if ((u32)idx >= reader.header.stringCount) {
            fprintf(stderr, "Index out of range (max %u)\n", reader.header.stringCount);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        const char *s = reader.strings[idx];
        printf("idx=%ld kind=%u name=%s\n", idx, (unsigned)reader.string_kinds[idx], s ? s : "");
        hbc_reader_cleanup(&reader);
    }
    else if (strcmp(command, "findstr") == 0) {
        if (!output_file) {
            fprintf(stderr, "Usage: %s findstr <input_file> <needle>\n", argv[0]);
            return 1;
        }
        const char *needle = output_file;
        HBCReader reader;
        Result result = hbc_reader_init(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error: %s\n", result.error_message);
            return 1;
        }
        result = hbc_reader_read_whole_file(&reader, input_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading file: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        for (u32 i = 0; i < reader.header.stringCount; i++) {
            const char *s = reader.strings[i];
            if (!s) continue;
            if (strstr(s, needle)) {
                printf("idx=%u kind=%u name=%s\n", i, (unsigned)reader.string_kinds[i], s);
            }
        }
        hbc_reader_cleanup(&reader);
    }
    else if (strcmp(command, "strmeta") == 0) {
        if (!output_file) {
            fprintf(stderr, "Usage: %s strmeta <input_file> <index>\n", argv[0]);
            return 1;
        }
        long idx = strtol(output_file, NULL, 10);
        if (idx < 0) {
            fprintf(stderr, "Invalid index\n");
            return 1;
        }
        HBCReader reader;
        Result result = hbc_reader_init(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error: %s\n", result.error_message);
            return 1;
        }
        result = hbc_reader_read_whole_file(&reader, input_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading file: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        if ((u32)idx >= reader.header.stringCount) {
            fprintf(stderr, "Index out of range (max %u)\n", reader.header.stringCount);
            hbc_reader_cleanup(&reader);
            return 1;
        }
        u32 is_utf16 = reader.small_string_table[idx].isUTF16;
        u32 length = reader.small_string_table[idx].length;
        u32 off = reader.small_string_table[idx].offset;
        if (length == 0xFF) {
            u32 oi = off;
            off = reader.overflow_string_table[oi].offset;
            length = reader.overflow_string_table[oi].length;
        }
        /* Also recompute raw entry directly from file to inspect discrepancies */
        BufferReader *br = &reader.file_buffer;
        size_t saved = br->position;
        buffer_reader_seek(br, sizeof(HBCHeader));
        buffer_reader_align(br, 4); /* after header */
        /* skip function headers */
        buffer_reader_seek(br, br->position + reader.header.functionCount * 16);
        buffer_reader_align(br, 4);
        /* skip string kinds */
        buffer_reader_seek(br, br->position + reader.header.stringKindCount * 4);
        buffer_reader_align(br, 4);
        /* skip identifier hashes */
        buffer_reader_seek(br, br->position + reader.header.identifierCount * 4);
        buffer_reader_align(br, 4);
        /* small string table start */
        buffer_reader_seek(br, br->position + (size_t)idx * 4);
        u32 raw_entry = 0;
        buffer_reader_read_u32(br, &raw_entry);
        br->position = saved;

        u32 calc_off = (raw_entry >> 1) & 0x7FFFFF;
        u32 calc_len = (raw_entry >> 24) & 0xFF;
        u32 calc_utf16 = raw_entry & 1;
        printf("idx=%ld isUTF16=%u off=0x%x len=%u raw_entry=0x%08x calc(isUTF16=%u, off=0x%x, len=%u)\n",
               idx, is_utf16, off, length, raw_entry, calc_utf16, calc_off, calc_len);
        hbc_reader_cleanup(&reader);
    }
    else if (strcmp(command, "funcs") == 0) {
        /* Dump first N function headers for comparison */
        const u32 N = 50; /* default count */

        /* Initialize HBC reader */
        HBCReader reader;
        Result result = hbc_reader_init(&reader);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error: %s\n", result.error_message);
            return 1;
        }

        /* Read whole file so strings are available */
        result = hbc_reader_read_whole_file(&reader, input_file);
        if (result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error reading file: %s\n", result.error_message);
            hbc_reader_cleanup(&reader);
            return 1;
        }

        u32 count = reader.header.functionCount < N ? reader.header.functionCount : N;
        for (u32 i = 0; i < count; i++) {
            FunctionHeader *fh = &reader.function_headers[i];
            const char *fname = (fh->functionName < reader.header.stringCount && reader.strings && reader.strings[fh->functionName]) ?
                reader.strings[fh->functionName] : "";
            printf("C  id=%u nameIdx=%u offset=0x%08x size=%u name=%s\n",
                   i, fh->functionName, fh->offset, fh->bytecodeSizeInBytes, fname);
        }

        hbc_reader_cleanup(&reader);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
