/* radare2 - LGPL - Copyright 2025-2026 - pancake */

#include <r_bin.h>
#include <r_bin_dwarf.h>
#include <hbc/hbc.h>
#include <hbc/literals.h>
#include "utils.inc.c"

#define HEADER_MAGIC 0x1f1903c103bc1fc6ULL
#define HBC_VADDR_BASE 0x10000000

typedef struct {
	HBC *hbc;
} HBCBinObj;

static bool check(RBinFile *bf, RBuffer *b) {
	(void)bf;
	if (r_buf_size (b) >= 8) {
		ut64 magic = 0;
		r_buf_read_at (b, 0, (ut8 *)&magic, sizeof (magic));
		return magic == HEADER_MAGIC;
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 R_UNUSED loadaddr) {
	if (check (bf, buf)) {
		HBC *hbc = NULL;
		if (hbc_open_from_buffer (buf, &hbc).code == RESULT_SUCCESS) {
			HBCBinObj *bo = R_NEW0 (HBCBinObj);
			if (bo) {
				bo->hbc = hbc;
				bf->bo->bin_obj = bo;
				bf->buf = buf;
				return true;
			}
			hbc_safe_close (&hbc);
		}
	}
	return false;
}

static void destroy(RBinFile *bf) {
	HBCBinObj *bo = bf->bo->bin_obj;
	if (bo) {
		hbc_safe_close (&bo->hbc);
		free (bo);
	}
}

static HBC *get_hbc(RBinFile *bf) {
	HBCBinObj *hbo = R_UNWRAP3 (bf, bo, bin_obj);
	return hbo? hbo->hbc: NULL;
}

static int bin_limit(RBinFile *bf) {
	return bf && bf->rbin? bf->rbin->options.limit: 0;
}

static u32 clamp_count_with_warning(const char *kind, u32 count, int limit) {
	if (limit > 0 && count > (u32)limit) {
		R_LOG_WARN ("hbc.bin: bin.limit reached for %s (%u > %d)", kind, count, limit);
		return (u32)limit;
	}
	return count;
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
static ut64 resolve_entrypoint(RBinFile *bf, HBC *hbc) {
	if (!hbc) {
		return 0;
	}
	/* Try 1: Find MainAppContent symbol */
	u32 func_count = hbc_function_count (hbc);
	for (u32 i = 0; i < func_count; i++) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, i, &fi).code == RESULT_SUCCESS) {
			if (fi.name && strcmp (fi.name, "MainAppContent") == 0) {
				if (is_valid_entrypoint (bf->buf, fi.offset)) {
					return fi.offset;
				}
			}
		}
	}

	/* Try 2: Use header globalCodeIndex */
	HBCHeader hh;
	if (hbc_get_header (hbc, &hh).code == RESULT_SUCCESS) {
		if (is_valid_entrypoint (bf->buf, hh.globalCodeIndex)) {
			return hh.globalCodeIndex;
		}
	}

	/* Try 3: Use first function's offset */
	if (func_count > 0) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, 0, &fi).code == RESULT_SUCCESS) {
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

static void fill_info(RBinInfo *ret, const char *file_path, bool has_version, ut32 version, bool has_source_lines) {
	ret->file = file_path? strdup (file_path): NULL;
	ret->bclass = strdup ("Hermes bytecode");
	ret->rclass = strdup ("hermes");
	ret->arch = strdup ("hbc");
	ret->os = strdup ("any");
	ret->bits = 32;
	ret->type = strdup ("Hermes bytecode");
	ret->machine = strdup ("Hermes VM");
	ret->cpu = has_version? r_str_newf ("%u", version): strdup ("unknown");
	ret->has_va = true;
	ret->dbg_info = has_source_lines? R_BIN_DBG_LINENUMS: R_BIN_DBG_STRIPPED;
}

static RBinInfo *bininfo(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	bool has_version = false;
	ut32 version = 0;
	bool has_source_lines = false;

	HBC *hbc = get_hbc (bf);
	if (hbc) {
		HBCHeader hh;
		if (hbc_get_header (hbc, &hh).code == RESULT_SUCCESS) {
			has_version = true;
			version = hh.version;
		}
		/* Cheap: answered from the DebugInfoHeader parsed at load time.
		 * Reflects file truth (does this file carry source lines?) regardless
		 * of bin.dbginfo — that setting only gates whether we decode them. */
		has_source_lines = hbc_has_source_lines (hbc);
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

	fill_info (ret, bf->file, has_version, version, has_source_lines);
	return ret;
}

/* Helper: append a section if the pool is present. Owns no strings — `name`
 * is duplicated into a heap-allocated section name via strdup. */
static void add_pool_section(RList *list, const char *name, ut64 paddr, ut64 size) {
	if (!size || !paddr) {
		return;
	}
	RBinSection *s = R_NEW0 (RBinSection);
	if (!s) {
		return;
	}
	s->name = strdup (name);
	s->size = size;
	s->vsize = size;
	s->paddr = paddr;
	s->vaddr = HBC_VADDR_BASE + paddr;
	s->perm = R_PERM_R;
	s->add = true;
	r_list_append (list, s);
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
	section->perm = R_PERM_RX;
	section->add = true;
	r_list_append (sections, section);

	/* SLP pool subsections — gives `iS` a quick map of where the buffer
	 * literals live, and lets users `s` / `pd @` straight into them. */
	HBC *hbc = get_hbc (bf);
	if (hbc) {
		add_pool_section (sections, "slp.arrays",
			hbc_get_pool_paddr (hbc, HBC_LIT_ARRAY),
			hbc_get_pool_size (hbc, HBC_LIT_ARRAY));
		add_pool_section (sections, "slp.object_keys",
			hbc_get_pool_paddr (hbc, HBC_LIT_OBJECT),
			hbc_get_pool_size (hbc, HBC_LIT_OBJECT));
		add_pool_section (sections, "slp.object_values",
			hbc_get_object_values_paddr (hbc),
			hbc_get_object_values_size (hbc));
	}

	return sections;
}

static RList *entries(RBinFile *bf) {
	RList *entries = r_list_newf ((RListFree)free);
	if (!entries) {
		return NULL;
	}

	RBinAddr *addr = R_NEW0 (RBinAddr);
	HBC *hbc = get_hbc (bf);
	ut64 entrypoint = resolve_entrypoint (bf, hbc);

	addr->paddr = entrypoint;
	addr->vaddr = HBC_VADDR_BASE + entrypoint;
	r_list_append (entries, addr);

	return entries;
}

static ut64 baddr(RBinFile *bf R_UNUSED) {
	return HBC_VADDR_BASE;
}

static void append_binding_symbols(RList *symbols, HBC *hbc) {
	HBCBindings bindings = { 0 };
	if (hbc_scan_bindings (hbc, &bindings).code != RESULT_SUCCESS) {
		return;
	}
	for (u32 i = 0; i < bindings.count; i++) {
		HBCBinding *b = &bindings.bindings[i];
		if (b->type != HBC_BINDING_EXPORT) {
			continue;
		}
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		char *nm = r_str_newf ("hbc.export.%s.%s", b->kind? b->kind: "js", b->name);
		sym->name = r_bin_name_new (nm);
		r_bin_name_filtered (sym->name, nm);
		sym->paddr = b->offset;
		sym->vaddr = HBC_VADDR_BASE + b->offset;
		sym->size = 1;
		sym->ordinal = b->string_id;
		sym->type = R_BIN_TYPE_OBJECT_STR;
		sym->bind = R_BIN_BIND_GLOBAL_STR;
		sym->bits = 32;
		r_list_append (symbols, sym);
		free (nm);
	}
	hbc_free_bindings (&bindings);
}

static RList *symbols(RBinFile *bf) {
	RList *symbols = r_list_newf ((RListFree)r_bin_symbol_free);
	HBC *hbc = get_hbc (bf);
	if (!hbc) {
		return symbols;
	}

	int limit = bin_limit (bf);
	u32 func_count = clamp_count_with_warning ("symbols", hbc_function_count (hbc), limit);
	for (u32 i = 0; i < func_count; i++) {
		HBCFunc fi;
		if (hbc_get_function_info (hbc, i, &fi).code != RESULT_SUCCESS) {
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
		if (hbc_get_function_source (hbc, i, &src).code == RESULT_SUCCESS && src && *src) {
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

	/* SLP pool groups as symbols — one per group discovered by the
	 * pool-side linear scan. Lets users see `lit.arr.* / lit.obj.*` in `is`
	 * without needing to run pd:hLs. The scan is linear in pool size and
	 * runs at RBin load time. */
	for (int k = 0; k < 2; k++) {
		HBCLiteralKind kind = k? HBC_LIT_OBJECT: HBC_LIT_ARRAY;
		const char *prefix = k? "lit.obj.": "lit.arr.";
		HBCPoolGroup *groups = NULL;
		u32 n = 0;
		if (hbc_literals_scan_pool (hbc, kind, &groups, &n).code
				!= RESULT_SUCCESS || !groups) {
			continue;
		}
		for (u32 i = 0; i < n; i++) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			char *nm = r_str_newf ("%s0x%x", prefix, groups[i].paddr);
			sym->name = r_bin_name_new (nm);
			r_bin_name_filtered (sym->name, nm);
			sym->paddr = groups[i].paddr;
			sym->vaddr = HBC_VADDR_BASE + groups[i].paddr;
			sym->size = 1;
			sym->type = R_BIN_TYPE_OBJECT_STR;
			sym->bits = 32;
			r_list_append (symbols, sym);
			free (nm);
		}
		free (groups);
	}

	append_binding_symbols (symbols, hbc);
	return symbols;
}

static RList *imports(RBinFile *bf) {
	RList *imports = r_list_newf ((RListFree)r_bin_import_free);
	HBC *hbc = get_hbc (bf);
	if (!imports || !hbc) {
		return imports;
	}
	HBCBindings bindings = { 0 };
	if (hbc_scan_bindings (hbc, &bindings).code != RESULT_SUCCESS) {
		return imports;
	}
	for (u32 i = 0; i < bindings.count; i++) {
		HBCBinding *b = &bindings.bindings[i];
		if (b->type != HBC_BINDING_IMPORT) {
			continue;
		}
		RBinImport *imp = R_NEW0 (RBinImport);
		char *nm = r_str_newf ("%s.%s", b->kind? b->kind: "js", b->name);
		imp->name = r_bin_name_new (nm);
		r_bin_name_filtered (imp->name, nm);
		imp->libname = strdup (b->module? b->module: "hermes");
		imp->bind = "NONE";
		imp->type = "FUNC";
		imp->ordinal = b->string_id;
		imp->is_imported = true;
		r_list_append (imports, imp);
		free (nm);
	}
	hbc_free_bindings (&bindings);
	return imports;
}

static R_UNOWNED RList *lines(RBinFile *bf) {
	HBC *hbc = get_hbc (bf);
	if (!hbc) {
		return NULL;
	}
	/* Respect bin.dbginfo=false — return early so the lazy debug-info parse
	 * (triggered by hbc_get_source_lines) never runs for users who opted out. */
	if (bf->rbin && !bf->rbin->want_dbginfo) {
		return NULL;
	}
	HBCSourceLineArray lines = { 0 };
	RList *ret = NULL;
	if (hbc_get_source_lines (hbc, &lines).code != RESULT_SUCCESS || !lines.count) {
		goto done;
	}
	ret = r_list_newf (free);
	if (!ret) {
		goto done;
	}
	const bool has_al = bf->addrline.al_add && bf->addrline.al_get;
	for (u32 i = 0; i < lines.count; i++) {
		HBCSourceLine *sl = &lines.lines[i];
		ut64 addr = HBC_VADDR_BASE + sl->address;
		const char *file = sl->filename? sl->filename: "";
		if (has_al) {
			bf->addrline.al_add (&bf->addrline, addr, file, NULL, sl->line, sl->column);
		}
		RBinAddrline *row = R_NEW0 (RBinAddrline);
		if (!row) {
			continue;
		}
		const RBinAddrline *stored = has_al? bf->addrline.al_get (&bf->addrline, addr): NULL;
		if (stored) {
			*row = *stored;
		} else {
			row->addr = addr;
			row->file = UT32_MAX;
			row->path = UT32_MAX;
			row->line = sl->line;
			row->column = sl->column;
		}
		r_list_append (ret, row);
	}
done:
	hbc_free_source_lines (&lines);
	return ret;
}

static RList *strings(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)r_bin_string_free);
	HBC *hbc = get_hbc (bf);
	if (!hbc) {
		return ret;
	}

	int limit = bin_limit (bf);
	u32 string_count = clamp_count_with_warning ("strings", hbc_string_count (hbc), limit);
	for (u32 i = 0; i < string_count; i++) {
		const char *str = NULL;
		if (hbc_get_string (hbc, i, &str).code != RESULT_SUCCESS || !str) {
			continue;
		}

		HBCStringMeta meta;
		if (hbc_get_string_meta (hbc, i, &meta).code != RESULT_SUCCESS) {
			continue;
		}
		const size_t str_len = strlen (str);
		if (str_len == 0) {
			continue;
		}

		RBinString *ptr = R_NEW0 (RBinString);
		if (str_len >= R_BIN_SIZEOF_STRINGS) {
			char *trunc = r_str_ndup (str, R_BIN_SIZEOF_STRINGS - 4);
			ptr->string = r_str_newf ("%s...", trunc? trunc: "");
			free (trunc);
		} else {
			ptr->string = r_str_ndup (str, str_len);
		}
		if (!ptr->string) {
			free (ptr);
			break;
		}

		ptr->paddr = meta.offset;
		ptr->vaddr = HBC_VADDR_BASE + meta.offset;
		ptr->size = meta.isUTF16? (meta.length * 2): meta.length;
		ptr->length = meta.length;
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
	.imports = &imports,
	.lines = &lines,
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
