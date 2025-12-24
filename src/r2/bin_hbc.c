/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_bin.h>
#include <hbc/hbc.h>

#define HEADER_MAGIC 0x1f1903c103bc1fc6ULL

static bool check(RBinFile *bf R_UNUSED, RBuffer *b) {
	if (r_buf_size (b) >= 8) {
		ut64 magic = 0;
		r_buf_read_at (b, 0, (ut8 *)&magic, sizeof (magic));
		return magic == HEADER_MAGIC;
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr R_UNUSED) {
	if (!check (bf, buf)) {
		return false;
	}
	/* Ensure bf->buf and bf->rbin are set for provider access */
	if (bf) {
		bf->buf = buf;
		/* bf->rbin would be set by r2 core, but ensure it's not NULL
		 * If it is, the provider will still work with just buf */
		if (!bf->rbin && bf->rbin == NULL) {
			/* r2 should set this, but if not, we note it */
		}
	}
	return true;
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
	if (file_path) {
		HBCDataProvider *provider = hbc_new_file (file_path);
		if (provider) {
			HBCHeader hh;
			Result result = hbc_hdr (provider, &hh);
			ut64 entrypoint = 0;
			if (result.code == RESULT_SUCCESS) {
				entrypoint = hh.globalCodeIndex;
			}
			hbc_free (provider);
			return entrypoint;
		}
	}
	return 0;
}

static void fill_info(RBinInfo *ret, const char *file_path, bool has_version, ut32 version) {
	ret->file = file_path? strdup (file_path): NULL;
	ret->bclass = strdup ("Hermes bytecode");
	ret->rclass = strdup ("hermes");
	ret->arch = strdup ("hbc");
	ret->os = strdup ("any");
	ret->bits = 32;
	ret->type = strdup ("Hermes bytecode");
	ret->machine = strdup ("Hermes VM");
	if (has_version) {
		ret->cpu = r_str_newf ("%u", version);
	} else {
		ret->cpu = strdup ("unknown");
	}
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	bool has_version = false;
	ut32 version = 0;

	if (bf->file) {
		HBCDataProvider *provider = hbc_new_file (bf->file);
		if (provider) {
			HBCHeader hh;
			Result result = hbc_hdr (provider, &hh);
			if (result.code == RESULT_SUCCESS) {
				has_version = true;
				version = hh.version;
			}
			hbc_free (provider);
		}
	}

	if (!has_version && r_buf_size (bf->buf) >= 32) {
		ut64 magic;
		r_buf_read_at (bf->buf, 0, (ut8 *)&magic, sizeof (magic));
		if (magic == HEADER_MAGIC) {
			r_buf_read_at (bf->buf, 8, (ut8 *)&version, sizeof (version));
			has_version = true;
		}
	}

	fill_info (ret, bf->file, has_version, version);
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *sections = r_list_newf ((RListFree)free);
	if (!sections) {
		return NULL;
	}

	/* Create a section for the entire HBC file mapped at 0x10000000.
	 * This high address prevents accidental address collisions and ensures
	 * that only valid string references point to the string storage area. */
	RBinSection *section = R_NEW0 (RBinSection);
	section->name = strdup ("hermes_bytecode");
	section->size = r_buf_size (bf->buf);
	section->vsize = section->size;
	section->paddr = 0;
	section->vaddr = 0x10000000; /* Map file at high virtual address */
	section->perm = R_PERM_R;
	r_list_append (sections, section);

	return sections;
}

static ut64 get_entrypoint_from_symbols(const char *file_path) {
	if (!file_path) {
		return 0;
	}

	HBCDataProvider *provider = hbc_new_file (file_path);
	if (!provider) {
		return 0;
	}

	u32 func_count;
	Result result = hbc_func_count (provider, &func_count);
	if (result.code != RESULT_SUCCESS) {
		hbc_free (provider);
		return 0;
	}

	for (u32 i = 0; i < func_count; i++) {
		HBCFunctionInfo fi;
		Result func_result = hbc_func_info (provider, i, &fi);
		if (func_result.code == RESULT_SUCCESS && fi.name && strcmp (fi.name, "MainAppContent") == 0) {
			hbc_free (provider);
			return fi.offset;
		}
	}

	hbc_free (provider);
	return 0;
}

static RList *entries(RBinFile *bf) {
	RList *entries = r_list_newf ((RListFree)free);
	if (!entries) {
		return NULL;
	}

	RBinAddr *addr = R_NEW0 (RBinAddr);
	ut64 entrypoint = 0;

	// First, try to find MainAppContent symbol
	if (bf->file) {
		entrypoint = get_entrypoint_from_symbols (bf->file);
	}

	// If not found, try to get entrypoint using the library
	if (entrypoint == 0 && bf->file) {
		entrypoint = get_entrypoint_from_file (bf->file);
	}

	// Fallback to buffer parsing
	if (entrypoint == 0) {
		entrypoint = get_entrypoint (bf->buf);
	}

	// Ensure entrypoint is valid: within file boundaries and first 8 bytes are not all zeros
	if (entrypoint != 0) {
		ut64 file_size = r_buf_size (bf->buf);
		if (entrypoint >= file_size || entrypoint + 8 > file_size) {
			entrypoint = 0; // Invalid: out of bounds
		} else {
			ut8 bytes[8];
			if (r_buf_read_at (bf->buf, entrypoint, bytes, 8) == 8) {
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
		HBCDataProvider *provider = hbc_new_file (bf->file);
		if (provider) {
			u32 func_count;
			Result result = hbc_func_count (provider, &func_count);
			if (result.code == RESULT_SUCCESS && func_count > 0) {
				HBCFunctionInfo fi;
				Result func_result = hbc_func_info (provider, 0, &fi);
				if (func_result.code == RESULT_SUCCESS && fi.offset != 0) {
					// Check if this offset is also valid
					ut64 file_size = r_buf_size (bf->buf);
					if (fi.offset < file_size && fi.offset + 8 <= file_size) {
						ut8 bytes[8];
						if (r_buf_read_at (bf->buf, fi.offset, bytes, 8) == 8) {
							bool all_zeros = true;
							for (int i = 0; i < 8; i++) {
								if (bytes[i] != 0) {
									all_zeros = false;
									break;
								}
							}
							if (!all_zeros) {
								entrypoint = fi.offset;
							}
						}
					}
				}
			}
			hbc_free (provider);
		}
	}

	addr->paddr = entrypoint;
	addr->vaddr = entrypoint;
	r_list_append (entries, addr);

	return entries;
}

static ut64 baddr(RBinFile *bf R_UNUSED) {
	/* Use a non-zero base address to avoid overlap between physical and virtual addresses.
	 * This ensures that when we refer to file offsets (paddr) in string_storage_offset,
	 * they don't collide with virtual address mappings. We use 0x1000 (4KB) as the base. */
	return 0x10000000;
}

static RList *symbols(RBinFile *bf) {
	RList *symbols = r_list_newf ((RListFree)free);
	if (!symbols) {
		return NULL;
	}

	// Try to parse the file and extract function symbols using the library
	if (bf->file) {
		HBCDataProvider *provider = hbc_new_file (bf->file);
		if (provider) {
			u32 func_count;
			Result result = hbc_func_count (provider, &func_count);
			if (result.code == RESULT_SUCCESS) {
				for (u32 i = 0; i < func_count; i++) {
					HBCFunctionInfo fi;
					Result func_result = hbc_func_info (provider, i, &fi);
					if (func_result.code == RESULT_SUCCESS) {
						RBinSymbol *symbol = R_NEW0 (RBinSymbol);
						/* Build a unique, sanitized name: [container__]base + _0x<offset> */
						const char *base = (fi.name && *fi.name)? fi.name: NULL;
						char *tmpbase = NULL;
						if (!base) {
							tmpbase = r_str_newf ("func_%u", i);
							base = tmpbase;
						}
						/* sanitize to be a valid flag/symbol name */
						char *san = r_name_filter_dup (base);
						if (!san || !*san) {
							free (san);
							san = r_str_newf ("func_%u", i);
						}
						/* optional container/source prefix if available */
						const char *src = NULL;
						if (hbc_src (provider, i, &src).code == RESULT_SUCCESS && src && *src) {
							char *sp = r_name_filter_dup (src);
							if (sp && *sp) {
								char *withpref = r_str_newf ("%s__%s", sp, san);
								free (san);
								san = withpref;
							}
							free (sp);
						}
						char *final = r_str_newf ("%s_0x%08x", san, fi.offset);
						symbol->name = r_bin_name_new (final);
						/* Also store filtered (flag) name explicitly */
						r_bin_name_filtered (symbol->name, final);
						free (final);
						free (san);
						free (tmpbase);

						symbol->paddr = fi.offset;
						symbol->vaddr = fi.offset;
						symbol->size = fi.size;
						symbol->ordinal = i;
						symbol->type = R_BIN_TYPE_FUNC_STR;
						symbol->bits = 32;
						r_list_append (symbols, symbol);
					}
				}
			}

			hbc_free (provider);
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
		HBCDataProvider *provider = hbc_new_file (bf->file);
		if (provider) {
			u32 string_count;
			Result result = hbc_str_count (provider, &string_count);
			if (result.code == RESULT_SUCCESS) {
				for (u32 i = 0; i < string_count; i++) {
					const char *str = NULL;
					Result str_result = hbc_str (provider, i, &str);
					if (str_result.code == RESULT_SUCCESS && str) {
						HBCStringMeta meta;
						Result meta_result = hbc_str_meta (provider, i, &meta);
						if (meta_result.code == RESULT_SUCCESS) {
							RBinString *ptr = R_NEW0 (RBinString);
							size_t str_len = strlen (str);
							if (str_len > 0 && str_len < R_BIN_SIZEOF_STRINGS) {
								ptr->string = strdup (str);
								if (!ptr->string) {
									free (ptr);
									break;
								}
								ptr->paddr = meta.offset;
								/* Map string to virtual address at base + offset */
								ptr->vaddr = 0x10000000 + meta.offset;
								ptr->size = str_len;
								ptr->length = str_len;
								ptr->ordinal = i;
								r_list_append (ret, ptr);
							} else {
								free (ptr);
							}
						}
					}
				}
			}

			hbc_free (provider);
		}
	}

	return ret;
}

RBinPlugin r_bin_plugin_hermes = {
	.meta = {
		.name = "hbc.bin",
		.author = "pancake",
		.desc = "Hermes bytecode format",
		.license = "BSD",
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
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
