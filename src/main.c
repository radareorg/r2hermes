#include "../include/common.h"
#include "../include/parsers/hbc_file_parser.h"
#include "../include/disassembly/hbc_disassembler.h"
#include "../include/decompilation/decompiler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Print usage information */
static void print_usage(const char* program_name) {
    printf("Usage: %s <command> <input_file> [output_file]\n\n", program_name);
    printf("Commands:\n");
    printf("  disassemble, dis, d    Disassemble a Hermes bytecode file\n");
    printf("  decompile, dec, c      Decompile a Hermes bytecode file\n");
    printf("  header, h              Display the header information only\n");
    printf("  validate, v            Validate file format and display detailed info\n");
    printf("  r2script, r2, r        Generate an r2 script with function flags\n");
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
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}

