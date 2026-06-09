/* radare2 - BSD - Copyright 2025-2026 - pancake */

/* CycloneDX SBOM generation for Hermes bytecode.
 *
 * Strategy:
 *   - Force a code scan so the SLP literal cache is populated.
 *   - Walk every cached object literal; keep the ones whose formatted JS
 *     text mentions "typescript" — that catches the package.json-style
 *     dependency maps (dependencies / devDependencies / peerDependencies).
 *   - The literal formatter prints valid JS identifiers as bare keys
 *     ({foo: "1.2.3"}), which is not strict JSON. We rewrite bare keys
 *     into quoted ones, then parse with r_json so we don't hand-roll a
 *     key/value parser.
 *   - For each name -> string-version pair, emit a CycloneDX component.
 *
 * Output formats:
 *   r2hermes-S    plaintext  (one "name version" per line)
 *   r2hermes-Sj   CycloneDX JSON (built via PJ)
 */

#include <hbc/literals.h>

typedef struct {
	char *name;
	char *version;
} SbomComp;

typedef struct {
	SbomComp *items;
	size_t count;
	size_t cap;
} SbomCompList;

static bool sbom_push(SbomCompList *list, const char *name, const char *version) {
	if (!name || !version) {
		return false;
	}
	if (list->count == list->cap) {
		size_t ncap = list->cap? list->cap * 2: 16;
		SbomComp *grown = realloc (list->items, ncap * sizeof (SbomComp));
		if (!grown) {
			return false;
		}
		list->items = grown;
		list->cap = ncap;
	}
	list->items[list->count].name = strdup (name);
	list->items[list->count].version = strdup (version);
	if (!list->items[list->count].name || !list->items[list->count].version) {
		free (list->items[list->count].name);
		free (list->items[list->count].version);
		return false;
	}
	list->count++;
	return true;
}

static void sbom_free(SbomCompList *list) {
	for (size_t i = 0; i < list->count; i++) {
		free (list->items[i].name);
		free (list->items[i].version);
	}
	free (list->items);
	list->items = NULL;
	list->count = 0;
	list->cap = 0;
}

/* Quote bare identifier keys so the result is parsable as JSON.
 * Skips over double-quoted strings (with escape handling) so we never
 * touch content inside string literals. Bare 'true'/'false'/'null' are
 * left alone since they may legitimately appear as values. */
static char *jsobj_to_json(const char *src) {
	if (!src) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	const char *p = src;
	while (*p) {
		if (*p == '"') {
			const char *start = p++;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1]) {
					p += 2;
				} else {
					p++;
				}
			}
			if (*p == '"') {
				p++;
			}
			r_strbuf_append_n (sb, start, (int)(p - start));
			continue;
		}
		unsigned char c = (unsigned char)*p;
		if (isalpha (c) || c == '_' || c == '$') {
			const char *start = p;
			while (*p && (isalnum ((unsigned char)*p) || *p == '_' || *p == '$')) {
				p++;
			}
			int len = (int)(p - start);
			const char *q = p;
			while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') {
				q++;
			}
			bool is_key = (*q == ':');
			bool is_literal = (len == 4 && !memcmp (start, "true", 4))
				|| (len == 5 && !memcmp (start, "false", 5))
				|| (len == 4 && !memcmp (start, "null", 4));
			if (is_key && !is_literal) {
				r_strbuf_append (sb, "\"");
				r_strbuf_append_n (sb, start, len);
				r_strbuf_append (sb, "\"");
			} else {
				r_strbuf_append_n (sb, start, len);
			}
			continue;
		}
		char one[2] = { *p, 0 };
		r_strbuf_append (sb, one);
		p++;
	}
	return r_strbuf_drain (sb);
}

/* Extract every name -> string-version pair from one candidate literal. */
static void sbom_harvest(const char *formatted, SbomCompList *out) {
	char *jsonstr = jsobj_to_json (formatted);
	if (!jsonstr) {
		return;
	}
	RJson *js = r_json_parsedup (jsonstr);
	free (jsonstr);
	if (!js) {
		return;
	}
	if (js->type == R_JSON_OBJECT) {
		for (RJson *kid = js->children.first; kid; kid = kid->next) {
			if (kid->type == R_JSON_STRING && kid->key && kid->str_value) {
				sbom_push (out, kid->key, kid->str_value);
			}
		}
	}
	r_json_free (js);
}

static int sbom_comp_cmp(const void *a, const void *b) {
	const SbomComp *ca = a;
	const SbomComp *cb = b;
	int r = strcmp (ca->name, cb->name);
	return r? r: strcmp (ca->version, cb->version);
}

/* Drop duplicate (name,version) pairs in-place. List must be sorted. */
static void sbom_dedup(SbomCompList *list) {
	if (list->count < 2) {
		return;
	}
	size_t w = 1;
	for (size_t i = 1; i < list->count; i++) {
		if (sbom_comp_cmp (&list->items[w - 1], &list->items[i]) == 0) {
			free (list->items[i].name);
			free (list->items[i].version);
		} else {
			list->items[w++] = list->items[i];
		}
	}
	list->count = w;
}

static void sbom_emit_text(RCore *core, const SbomCompList *list) {
	if (list->count == 0) {
		r_cons_println (core->cons, "(no SBOM candidates: no SLP object literal mentions \"typescript\")");
		return;
	}
	r_cons_printf (core->cons, "# SBOM (%zu components)\n", list->count);
	for (size_t i = 0; i < list->count; i++) {
		r_cons_printf (core->cons, "%s %s\n", list->items[i].name, list->items[i].version);
	}
}

static void sbom_emit_json(RCore *core, const SbomCompList *list) {
	PJ *pj = r_core_pj_new (core);
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ks (pj, "bomFormat", "CycloneDX");
	pj_ks (pj, "specVersion", "1.5");
	pj_ki (pj, "version", 1);
	pj_ka (pj, "components");
	for (size_t i = 0; i < list->count; i++) {
		const SbomComp *c = &list->items[i];
		pj_o (pj);
		pj_ks (pj, "type", "library");
		pj_ks (pj, "name", c->name);
		pj_ks (pj, "version", c->version);
		char *purl = r_str_newf ("pkg:npm/%s@%s", c->name, c->version);
		if (purl) {
			pj_ks (pj, "purl", purl);
			free (purl);
		}
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	char *s = pj_drain (pj);
	if (s) {
		r_cons_println (core->cons, s);
		free (s);
	}
}

static const char SBOM_HELP[] =
	"Usage: r2hermes-S[jr?]\n"
	" r2hermes-S       Emit SBOM as plaintext (name + version per line)\n"
	" r2hermes-Sj      Emit CycloneDX 1.5 SBOM as JSON\n"
	" r2hermes-Sr      Dump the raw matched SLP literal text (pre-JSON)\n"
	" r2hermes-S?      Show this help\n";

typedef enum {
	SBOM_FMT_TEXT,
	SBOM_FMT_JSON,
	SBOM_FMT_RAW
} SbomFormat;

static void cmd_sbom(HbcContext *ctx, RCore *core, const char *arg) {
	while (*arg && isspace ((unsigned char)*arg)) {
		arg++;
	}
	if (*arg == '?') {
		r_cons_print (core->cons, SBOM_HELP);
		return;
	}
	SbomFormat fmt = SBOM_FMT_TEXT;
	if (*arg == 'j') {
		fmt = SBOM_FMT_JSON;
	} else if (*arg == 'r') {
		fmt = SBOM_FMT_RAW;
	}

	HBC *hbc = NULL;
	Result r = ensure_hbc_loaded (ctx, core, &hbc);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("%s", safe_errmsg (r.error_message));
		return;
	}

	u32 nscanned = 0;
	r = hbc_literals_scan_code (hbc, &nscanned);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("literal scan failed: %s", safe_errmsg (r.error_message));
		return;
	}

	const HBCLiteralEntry *arr = NULL;
	u32 n = 0;
	if (hbc_literals_list (hbc, &arr, &n).code != RESULT_SUCCESS || !arr) {
		R_LOG_ERROR ("literal list unavailable");
		return;
	}

	SbomCompList comps = { 0 };
	u32 matched = 0;
	for (u32 i = 0; i < n; i++) {
		const HBCLiteralEntry *e = &arr[i];
		if (e->kind != HBC_LIT_OBJECT || !e->formatted) {
			continue;
		}
		if (!strstr (e->formatted, "typescript")) {
			continue;
		}
		matched++;
		if (fmt == SBOM_FMT_RAW) {
			r_cons_printf (core->cons, "# paddr=0x%08x xrefs=%u\n%s\n", e->paddr, e->xref_count, e->formatted);
		} else {
			sbom_harvest (e->formatted, &comps);
		}
	}

	if (fmt == SBOM_FMT_RAW) {
		if (matched == 0) {
			r_cons_println (core->cons, "(no SLP object literal mentions \"typescript\")");
		}
		return;
	}

	if (comps.count > 1) {
		qsort (comps.items, comps.count, sizeof (SbomComp), sbom_comp_cmp);
		sbom_dedup (&comps);
	}

	if (fmt == SBOM_FMT_JSON) {
		sbom_emit_json (core, &comps);
	} else {
		sbom_emit_text (core, &comps);
	}

	sbom_free (&comps);
}
