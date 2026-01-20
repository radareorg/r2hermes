/* radare2 - LGPL - Copyright 2025-2026 - pancake */

#include <r_bin.h>
#include <hbc/hbc.h>

#define HEADER_MAGIC 0x1f1903c103bc1fc6ULL
#define HBC_VADDR_BASE 0x10000000

typedef struct {
	HBC *hbc;
} HBCBinObj;

static bool check(RBinFile *R_UNUSED bf, RBuffer *b) {
	if (r_buf_size (b) >= 8) {
		ut64 magic = 0;
		r_buf_read_at (b, 0, (ut8 *)&magic, sizeof (magic));
		return magic == HEADER_MAGIC;
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 R_UNUSED loadaddr) {
	if (check (bf, buf) && bf->file) {
		HBC *hbc = hbc_new_file (bf->file);
		if (hbc) {
			HBCBinObj *bo = R_NEW0 (HBCBinObj);
			bo->hbc = hbc;
			bf->bo->bin_obj = bo;
			bf->buf = buf;
			return true;
		}
	}
	return false;
}

static void destroy(RBinFile *bf) {
	HBCBinObj *bo = bf->bo->bin_obj;
	if (bo) {
		hbc_free (bo->hbc);
		free (bo);
	}
}

static HBC *get_provider(RBinFile *bf) {
	HBCBinObj *hbo = R_UNWRAP3 (bf, bo, bin_obj);
	return hbo? hbo->hbc: NULL;
}

/* Check if entrypoint offset is valid: in bounds and not all zeros */
static bool is_valid_entrypoint(RBuffer *buf, ut64 offset) {
	ut64 file_size = r_buf_size (buf);
	if (offset == 0 || offset >= file_size || offset + 8 > file_size) {
		return false;
	}

	ut8 bytes[8];
	if (r_buf_read_at (buf, offset, bytes, 8) != 8) {
		return false;
	}

	for (int i = 0; i < 8; i++) {
		if (bytes[i] != 0) {
			return true; /* Found non-zero byte, valid */
		}
	}
	return false; /* All zeros, invalid */
}

/* Unified entrypoint resolution with fallback chain */
static ut64 resolve_entrypoint(RBinFile *bf, HBC *provider) {
	if (!provider) {
		return 0;
	}
	/* Try 1: Find MainAppContent symbol */
	u32 func_count;
	if (hbc_func_count (provider, &func_count).code == RESULT_SUCCESS) {
		for (u32 i = 0; i < func_count; i++) {
			HBCFunc fi;
			if (hbc_func_info (provider, i, &fi).code == RESULT_SUCCESS) {
				if (fi.name && strcmp (fi.name, "MainAppContent") == 0) {
					if (is_valid_entrypoint (bf->buf, fi.offset)) {
						return fi.offset;
					}
				}
			}
		}
	}

	/* Try 2: Use header globalCodeIndex */
	HBCHeader hh;
	if (hbc_hdr (provider, &hh).code == RESULT_SUCCESS) {
		if (is_valid_entrypoint (bf->buf, hh.globalCodeIndex)) {
			return hh.globalCodeIndex;
		}
	}

	/* Try 3: Use first function's offset */
	if (func_count > 0) {
		HBCFunc fi;
		if (hbc_func_info (provider, 0, &fi).code == RESULT_SUCCESS) {
			if (is_valid_entrypoint (bf->buf, fi.offset)) {
				return fi.offset;
			}
		}
	}

	/* Try 4: Direct buffer parsing (offset 16 = globalCodeIndex in header) */
	if (r_buf_size (bf->buf) >= 32) {
		ut32 offset;
		r_buf_read_at (bf->buf, 16, (ut8 *)&offset, sizeof (offset));
		if (is_valid_entrypoint (bf->buf, offset)) {
			return offset;
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
	ret->cpu = has_version? r_str_newf ("%u", version): strdup ("unknown");
}

static RBinInfo *bininfo(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	bool has_version = false;
	ut32 version = 0;

	HBC *provider = get_provider (bf);
	if (provider) {
		HBCHeader hh;
		if (hbc_hdr (provider, &hh).code == RESULT_SUCCESS) {
			has_version = true;
			version = hh.version;
		}
	}

	/* Fallback: parse version directly from buffer */
	if (!has_version && r_buf_size (bf->buf) >= 16) {
		ut64 magic = 0;
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

	RBinSection *section = R_NEW0 (RBinSection);
	section->name = strdup ("hermes_bytecode");
	section->size = r_buf_size (bf->buf);
	section->vsize = section->size;
	section->paddr = 0;
	section->vaddr = HBC_VADDR_BASE;
	section->perm = R_PERM_R;
	r_list_append (sections, section);

	return sections;
}

static RList *entries(RBinFile *bf) {
	RList *entries = r_list_newf ((RListFree)free);
	if (!entries) {
		return NULL;
	}

	RBinAddr *addr = R_NEW0 (RBinAddr);
	HBC *provider = get_provider (bf);
	ut64 entrypoint = resolve_entrypoint (bf, provider);

	addr->paddr = entrypoint;
	addr->vaddr = HBC_VADDR_BASE + entrypoint;
	r_list_append (entries, addr);

	return entries;
}

static ut64 baddr(RBinFile *bf R_UNUSED) {
	return HBC_VADDR_BASE;
}

static RList *symbols(RBinFile *bf) {
	RList *symbols = r_list_newf ((RListFree)free);
	HBC *provider = get_provider (bf);
	if (!provider) {
		return symbols;
	}

	u32 func_count;
	if (hbc_func_count (provider, &func_count).code != RESULT_SUCCESS) {
		return symbols;
	}

	for (u32 i = 0; i < func_count; i++) {
		HBCFunc fi;
		if (hbc_func_info (provider, i, &fi).code != RESULT_SUCCESS) {
			continue;
		}

		RBinSymbol *symbol = R_NEW0 (RBinSymbol);

		/* Build name: [container__]base_0x<offset> */
		const char *base = (fi.name && *fi.name)? fi.name: NULL;
		char *san = base? r_name_filter_dup (base): NULL;
		if (!san || !*san) {
			free (san);
			san = r_str_newf ("func_%u", i);
		}

		/* Add container prefix if available */
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
		r_bin_name_filtered (symbol->name, final);

		symbol->paddr = fi.offset;
		symbol->vaddr = HBC_VADDR_BASE + fi.offset;
		symbol->size = fi.size;
		symbol->ordinal = i;
		symbol->type = R_BIN_TYPE_FUNC_STR;
		symbol->bits = 32;

		r_list_append (symbols, symbol);
		free (final);
		free (san);
	}

	return symbols;
}

static RList *strings(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)free);
	HBC *provider = get_provider (bf);
	if (!provider) {
		return ret;
	}

	u32 string_count;
	if (hbc_str_count (provider, &string_count).code != RESULT_SUCCESS) {
		return ret;
	}

	for (u32 i = 0; i < string_count; i++) {
		const char *str = NULL;
		if (hbc_str (provider, i, &str).code != RESULT_SUCCESS || !str) {
			continue;
		}

		HBCStringMeta meta;
		if (hbc_str_meta (provider, i, &meta).code != RESULT_SUCCESS) {
			continue;
		}

		size_t str_len = strlen (str);
		if (str_len == 0 || str_len >= R_BIN_SIZEOF_STRINGS) {
			continue;
		}

		RBinString *ptr = R_NEW0 (RBinString);
		ptr->string = strdup (str);
		if (!ptr->string) {
			free (ptr);
			break;
		}

		ptr->paddr = meta.offset;
		ptr->vaddr = HBC_VADDR_BASE + meta.offset;
		ptr->size = str_len;
		ptr->length = str_len;
		ptr->ordinal = i;
		r_list_append (ret, ptr);
	}

	return ret;
}

const RBinPlugin r_bin_plugin_r2hermes = {
	.meta = {
		.name = "hbc.bin",
		.author = "pancake",
		.desc = "Hermes bytecode format",
		.license = "BSD",
	},
	.info = &bininfo,
	.load = &load,
	.destroy = &destroy,
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
	.data = (void *)&r_bin_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
