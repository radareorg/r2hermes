/* radare2 - LGPL - Copyright 2025 - hermes-dec */

#include <r_bin.h>
#include <r_lib.h>

// Include hermesdec headers
#include "../include/hermesdec/hermesdec.h"
#include "../include/common.h"

#define HEADER_MAGIC 0x1f1903c103bc1fc6ULL

static bool check(RBinFile *bf, RBuffer *b) {
    if (r_buf_size (b) >= 8) {
        ut64 magic;
        r_buf_read_at (b, 0, (ut8 *)&magic, sizeof (magic));
        return magic == HEADER_MAGIC;
    }
    return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
    return check (bf, buf);
}

static ut64 get_entrypoint(RBuffer *buf) {
    // For Hermes bytecode, the entrypoint is typically the global code index
    // We need to parse the header to find it
    if (r_buf_size (buf) >= 32) {
        ut32 global_code_index;
        r_buf_read_at (buf, 16, (ut8 *)&global_code_index, sizeof (global_code_index));
        return global_code_index;
    }
    return 0;
}

// Get entrypoint using the hermesdec library
static ut64 get_entrypoint_from_file(const char *file_path) {
    if (!file_path) {
        return 0;
    }

    HermesDec *hd = NULL;
    Result result = hermesdec_open(file_path, &hd);
    if (result.code != RESULT_SUCCESS) {
        return 0;
    }

    HermesHeader hh;
    result = hermesdec_get_header(hd, &hh);
    if (result.code != RESULT_SUCCESS) {
        hermesdec_close(hd);
        return 0;
    }

    ut64 entrypoint = hh.globalCodeIndex;
    hermesdec_close(hd);
    return entrypoint;
}

static RBinInfo *info(RBinFile *bf) {
    RBinInfo *ret = R_NEW0 (RBinInfo);
    if (!ret) {
        return NULL;
    }

    // Try to use the hermesdec library to parse the file
    if (bf->file) {
        HermesDec *hd = NULL;
        Result result = hermesdec_open(bf->file, &hd);
        if (result.code == RESULT_SUCCESS) {
            HermesHeader hh;
            result = hermesdec_get_header(hd, &hh);
            if (result.code == RESULT_SUCCESS) {
                ret->file = strdup (bf->file);
                ret->type = r_str_newf ("Hermes bytecode v%d", hh.version);
                ret->bclass = strdup ("Hermes bytecode");
                ret->rclass = strdup ("hermes");
                ret->arch = strdup ("hermes");
                ret->machine = r_str_newf ("Hermes VM v%d", hh.version);
                ret->os = strdup ("any");
                ret->bits = 32; // Hermes bytecode is typically 32-bit
                ret->cpu = r_str_newf ("%d", hh.version);
                hermesdec_close(hd);
                return ret;
            }
            hermesdec_close(hd);
        }
    }

    // Fallback to manual parsing
    if (r_buf_size (bf->buf) >= 32) {
        ut64 magic;
        ut32 version;
        r_buf_read_at (bf->buf, 0, (ut8 *)&magic, sizeof (magic));
        r_buf_read_at (bf->buf, 8, (ut8 *)&version, sizeof (version));

        if (magic == HEADER_MAGIC) {
            ret->file = strdup (bf->file);
            ret->type = r_str_newf ("Hermes bytecode v%d", version);
            ret->bclass = strdup ("Hermes bytecode");
            ret->rclass = strdup ("hermes");
            ret->arch = strdup ("hermes");
            ret->machine = r_str_newf ("Hermes VM v%d", version);
            ret->os = strdup ("any");
            ret->bits = 32;
            ret->cpu = r_str_newf ("%d", version);
            return ret;
        }
    }

    // Fallback
    ret->file = strdup (bf->file);
    ret->type = strdup ("Hermes bytecode");
    ret->bclass = strdup ("Hermes bytecode");
    ret->rclass = strdup ("hermes");
    ret->arch = strdup ("hermes");
    ret->machine = strdup ("Hermes VM");
    ret->os = strdup ("any");
    ret->bits = 32;
    ret->cpu = strdup ("unknown");

    return ret;
}

static RList *sections(RBinFile *bf) {
    RList *sections = r_list_newf ((RListFree)free);
    if (!sections) {
        return NULL;
    }

    // For now, create a basic section for the entire file
    RBinSection *section = R_NEW0 (RBinSection);
    if (section) {
        section->name = strdup ("hermes_bytecode");
        section->size = r_buf_size (bf->buf);
        section->vsize = section->size;
        section->paddr = 0;
        section->vaddr = 0;
        section->perm = R_PERM_R;
        r_list_append (sections, section);
    }

    return sections;
}

static ut64 get_entrypoint_from_symbols(const char *file_path) {
    if (!file_path) {
        return 0;
    }

    HermesDec *hd = NULL;
    Result result = hermesdec_open(file_path, &hd);
    if (result.code != RESULT_SUCCESS) {
        return 0;
    }

    u32 func_count = hermesdec_function_count(hd);
    for (u32 i = 0; i < func_count; i++) {
        const char *name = NULL;
        u32 offset = 0, size = 0, param_count = 0;
        Result func_result = hermesdec_get_function_info(hd, i, &name, &offset, &size, &param_count);
        if (func_result.code == RESULT_SUCCESS && name && strcmp(name, "MainAppContent") == 0) {
            hermesdec_close(hd);
            return offset;
        }
    }

    hermesdec_close(hd);
    return 0;
}

static RList *entries(RBinFile *bf) {
    RList *entries = r_list_newf ((RListFree)free);
    if (!entries) {
        return NULL;
    }

    RBinAddr *addr = R_NEW0 (RBinAddr);
    if (!addr) {
        r_list_free (entries);
        return NULL;
    }

    ut64 entrypoint = 0;

    // First, try to find MainAppContent symbol
    if (bf->file) {
        entrypoint = get_entrypoint_from_symbols(bf->file);
    }

    // If not found, try to get entrypoint using the library
    if (entrypoint == 0 && bf->file) {
        entrypoint = get_entrypoint_from_file(bf->file);
    }

    // Fallback to buffer parsing
    if (entrypoint == 0) {
        entrypoint = get_entrypoint(bf->buf);
    }

    // Ensure entrypoint is valid: within file boundaries and first 8 bytes are not all zeros
    if (entrypoint != 0) {
        ut64 file_size = r_buf_size(bf->buf);
        if (entrypoint >= file_size || entrypoint + 8 > file_size) {
            entrypoint = 0; // Invalid: out of bounds
        } else {
            ut8 bytes[8];
            if (r_buf_read_at(bf->buf, entrypoint, bytes, 8) == 8) {
                bool all_zeros = true;
                for (int i = 0; i < 8; i++) {
                    if (bytes[i] != 0) {
                        all_zeros = false;
                        break;
                    }
                }
                if (all_zeros) {
                    entrypoint = 0; // Invalid: first 8 bytes are zeros
                }
            } else {
                entrypoint = 0; // Invalid: couldn't read
            }
        }
    }

    // If entrypoint is still invalid, try to find any valid function offset
    if (entrypoint == 0 && bf->file) {
        HermesDec *hd = NULL;
        Result result = hermesdec_open(bf->file, &hd);
        if (result.code == RESULT_SUCCESS) {
            u32 func_count = hermesdec_function_count(hd);
            if (func_count > 0) {
                const char *name = NULL;
                u32 offset = 0, size = 0, param_count = 0;
                Result func_result = hermesdec_get_function_info(hd, 0, &name, &offset, &size, &param_count);
                if (func_result.code == RESULT_SUCCESS && offset != 0) {
                    // Check if this offset is also valid
                    ut64 file_size = r_buf_size(bf->buf);
                    if (offset < file_size && offset + 8 <= file_size) {
                        ut8 bytes[8];
                        if (r_buf_read_at(bf->buf, offset, bytes, 8) == 8) {
                            bool all_zeros = true;
                            for (int i = 0; i < 8; i++) {
                                if (bytes[i] != 0) {
                                    all_zeros = false;
                                    break;
                                }
                            }
                            if (!all_zeros) {
                                entrypoint = offset;
                            }
                        }
                    }
                }
            }
            hermesdec_close(hd);
        }
    }

    addr->paddr = entrypoint;
    addr->vaddr = entrypoint;
    r_list_append (entries, addr);

    return entries;
}

static ut64 baddr(RBinFile *bf) {
    return 0;
}

static RList *symbols(RBinFile *bf) {
	RList *symbols = r_list_newf ((RListFree)free);
	if (!symbols) {
		return NULL;
	}

	// Try to parse the file and extract function symbols using the library
	if (bf->file) {
		HermesDec *hd = NULL;
		Result result = hermesdec_open(bf->file, &hd);
		if (result.code == RESULT_SUCCESS) {
			u32 func_count = hermesdec_function_count(hd);

			for (u32 i = 0; i < func_count; i++) {
				const char *name = NULL;
				u32 offset = 0, size = 0, param_count = 0;
				Result func_result = hermesdec_get_function_info(hd, i, &name, &offset, &size, &param_count);
				if (func_result.code == RESULT_SUCCESS) {
					RBinSymbol *symbol = R_NEW0 (RBinSymbol);
					if (!symbol) {
						break;
					}

					/* Build a unique, sanitized name: [container__]base + _0x<offset> */
					const char *base = (name && *name) ? name : NULL;
					char *tmpbase = NULL;
					if (!base) {
						tmpbase = r_str_newf("func_%u", i);
						base = tmpbase;
					}
					/* sanitize to be a valid flag/symbol name */
					char *san = r_name_filter_dup(base);
					if (!san || !*san) {
						free(san);
						san = r_str_newf("func_%u", i);
					}
					/* optional container/source prefix if available */
					const char *src = NULL;
					if (hermesdec_get_function_source(hd, i, &src).code == RESULT_SUCCESS && src && *src) {
						char *sp = r_name_filter_dup(src);
						if (sp && *sp) {
							char *withpref = r_str_newf("%s__%s", sp, san);
							free(san);
							san = withpref;
						}
						free(sp);
					}
					char *final = r_str_newf("%s_0x%08x", san, offset);
					symbol->name = r_bin_name_new(final);
					/* Also store filtered (flag) name explicitly */
					r_bin_name_filtered(symbol->name, final);
					free(final);
					free(san);
					free(tmpbase);

					symbol->paddr = offset;
					symbol->vaddr = offset;
					symbol->size = size;
					symbol->ordinal = i;
					symbol->type = R_BIN_TYPE_FUNC_STR;
					symbol->bits = 32;
					r_list_append (symbols, symbol);
				}
			}

			hermesdec_close(hd);
		}
	}

	return symbols;
}

static RList *strings(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)free);
	if (!ret) {
		return NULL;
	}

	if (bf->file) {
		HermesDec *hd = NULL;
		Result result = hermesdec_open(bf->file, &hd);
		if (result.code == RESULT_SUCCESS) {
			u32 string_count = hermesdec_string_count(hd);

			for (u32 i = 0; i < string_count; i++) {
				const char *str = NULL;
				Result str_result = hermesdec_get_string(hd, i, &str);
				if (str_result.code == RESULT_SUCCESS && str) {
					HermesStringMeta meta;
					Result meta_result = hermesdec_get_string_meta(hd, i, &meta);
					if (meta_result.code == RESULT_SUCCESS) {
						RBinString *ptr = R_NEW0 (RBinString);
						if (!ptr) {
							break;
						}

						size_t str_len = strlen(str);
						if (str_len > 0 && str_len < R_BIN_SIZEOF_STRINGS) {
							ptr->string = strdup(str);
							if (!ptr->string) {
								free(ptr);
								break;
							}
							ptr->paddr = meta.offset;
							ptr->vaddr = meta.offset;
							ptr->size = str_len;
							ptr->length = str_len;
							ptr->ordinal = i;
							r_list_append(ret, ptr);
						} else {
							free(ptr);
						}
					}
				}
			}

			hermesdec_close(hd);
		}
	}

	return ret;
}

RBinPlugin r_bin_plugin_hermes = {
	.meta = {
		.name = "hbc",
		.author = "pancake",
		.desc = "Hermes bytecode format",
		.license = "MIT",
	},
	.info = &info,
	.load = &load,
	.check = &check,
	.entries = &entries,
	.sections = &sections,
	.baddr = &baddr,
	.symbols = &symbols,
	.strings = &strings,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_BIN,
    .data = &r_bin_plugin_hermes,
    .version = R2_VERSION
};
#endif
