/* radare2 - BSD - Copyright 2025-2026 - pancake */

/* CycloneDX SBOM generation for Hermes bytecode.
 *
 * Strategy:
 *   - Scan object literal constructors only; arrays cannot carry package
 *     metadata in the current extractor.
 *   - Visit object keys before formatting values, so most UI/data literals are
 *     discarded without allocating their reconstructed JS text.
 *   - Keep package.json-style metadata objects ({name,version}) and flat
 *     dependency maps ({package: version}).
 *   - Emit each recovered package name and version as a CycloneDX component.
 *
 * Output formats:
 *   r2hermes-S    plaintext (one "name version" per line)
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

static bool sbom_is_npm_name(const char *s) {
	if (R_STR_ISEMPTY (s) || !strcmp (s, "name") || !strcmp (s, "version")) {
		return false;
	}
	bool scoped = *s == '@';
	bool slash = false;
	const char *p = scoped? s + 1: s;
	while (*p) {
		unsigned char c = (unsigned char)*p;
		if (c == '/') {
			if (!scoped || slash || p == s + 1 || !p[1]) {
				return false;
			}
			slash = true;
		} else if (!islower (c) && !isdigit (c) && !strchr ("-_.~", c)) {
			return false;
		}
		p++;
	}
	return !scoped || slash;
}

static bool sbom_is_dep_name(const char *s) {
	if (!sbom_is_npm_name (s)) {
		return false;
	}
	return strchr (s, '/') || strchr (s, '-') || !strcmp (s, "react") || !strcmp (s, "semver") ||
		!strcmp (s, "eslint") || !strcmp (s, "jest") || !strcmp (s, "knip") || !strcmp (s, "madge") ||
		!strcmp (s, "prettier") || !strcmp (s, "typescript") || !strcmp (s, "coveralls") ||
		!strcmp (s, "mocha") || !strcmp (s, "nyc") || !strcmp (s, "rollup");
}

static bool sbom_is_version_spec(const char *version) {
	if (R_STR_ISEMPTY (version)) {
		return false;
	}
	static const char *prefixes[] = {
		"catalog:",
		"file:",
		"github:",
		"link:",
		"npm:",
		"patch:",
		"portal:",
		"workspace:",
	};
	for (size_t i = 0; i < sizeof (prefixes) / sizeof (prefixes[0]); i++) {
		if (r_str_startswith (version, prefixes[i])) {
			return true;
		}
	}
	if (!strcmp (version, "latest") || !strcmp (version, "next") || !strcmp (version, "canary")) {
		return true;
	}
	const char *v = version;
	while (*v && isspace ((unsigned char)*v)) {
		v++;
	}
	if (*v == '^' || *v == '~' || *v == '=' || *v == '<' || *v == '>') {
		v++;
		if (*v == '=' || (*v == '>' && v[-1] == '<')) {
			v++;
		}
	}
	if (!isdigit ((unsigned char)*v) && *v != '*') {
		return false;
	}
	bool digit = false;
	bool mark = false;
	bool wildcard = false;
	for (const char *p = version; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (isdigit (c)) {
			digit = true;
		} else if (c == '*') {
			wildcard = true;
		} else if (strchr (".xX~^<>=", c)) {
			mark = true;
		} else if (!isalpha (c) && !strchr ("-_+|, ", c) && !isspace (c)) {
			return false;
		}
	}
	return wildcard || (digit && mark);
}

static bool sbom_is_manifest_key(const char *key) {
	return !strcmp (key, "description") || !strcmp (key, "license") || !strcmp (key, "main") ||
		!strcmp (key, "module") || !strcmp (key, "repository") || !strcmp (key, "dependencies") ||
		!strcmp (key, "devDependencies") || !strcmp (key, "peerDependencies");
}

static bool sbom_is_strong_dep_key(const char *s) {
	return strchr (s, '/') || !strcmp (s, "react") || !strcmp (s, "semver") ||
		!strcmp (s, "eslint") || !strcmp (s, "jest") || !strcmp (s, "knip") || !strcmp (s, "madge") ||
		!strcmp (s, "prettier") || !strcmp (s, "typescript") || !strcmp (s, "coveralls") ||
		!strcmp (s, "mocha") || !strcmp (s, "nyc") || !strcmp (s, "rollup");
}

static bool sbom_key_may_match(const char *key, void *user) {
	bool *may_match = user;
	if (sbom_is_manifest_key (key) || (sbom_is_npm_name (key) && sbom_is_strong_dep_key (key))) {
		*may_match = true;
		return false;
	}
	return true;
}

static bool sbom_object_may_match(HBC *hbc, const HBCLiteralEntry *e) {
	bool may_match = false;
	Result r = hbc_literals_visit_object_keys (hbc, e->num_items, e->primary_id, sbom_key_may_match, &may_match);
	return r.code != RESULT_SUCCESS || may_match;
}

static char *sbom_dup_range(const char *s, size_t n) {
	char *out = malloc (n + 1);
	if (!out) {
		return NULL;
	}
	memcpy (out, s, n);
	out[n] = 0;
	return out;
}

static void sbom_skip_ws(const char **pp) {
	while (**pp && isspace ((unsigned char)**pp)) {
		(*pp)++;
	}
}

static char *sbom_parse_quoted(const char **pp) {
	const char *p = *pp;
	if (*p != '"') {
		return NULL;
	}
	p++;
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	while (*p && *p != '"') {
		if (*p == '\\' && p[1]) {
			p++;
		}
		r_strbuf_append_n (sb, p, 1);
		p++;
	}
	if (*p == '"') {
		p++;
	}
	*pp = p;
	return r_strbuf_drain (sb);
}

static char *sbom_parse_key(const char **pp) {
	sbom_skip_ws (pp);
	const char *p = *pp;
	if (*p == '"') {
		return sbom_parse_quoted (pp);
	}
	if (! (isalnum ((unsigned char)*p) || *p == '_' || *p == '$')) {
		return NULL;
	}
	const char *start = p;
	while (isalnum ((unsigned char)*p) || *p == '_' || *p == '$') {
		p++;
	}
	*pp = p;
	return sbom_dup_range (start, (size_t) (p - start));
}

static void sbom_skip_quoted(const char **pp) {
	const char *p = *pp;
	if (*p != '"') {
		return;
	}
	for (p++; *p && *p != '"'; p++) {
		if (*p == '\\' && p[1]) {
			p++;
		}
	}
	if (*p == '"') {
		p++;
	}
	*pp = p;
}

static void sbom_skip_value(const char **pp) {
	const char *p = *pp;
	int depth = 0;
	while (*p) {
		if (*p == '"') {
			sbom_skip_quoted (&p);
			continue;
		}
		if (*p == '{' || *p == '[') {
			depth++;
			p++;
			continue;
		}
		if (*p == '}' || *p == ']') {
			if (depth == 0) {
				break;
			}
			depth--;
			p++;
			continue;
		}
		if (*p == ',' && depth == 0) {
			break;
		}
		p++;
	}
	*pp = p;
}

/* Extract name/version metadata and dependency-map entries from one literal. */
static size_t sbom_harvest(const char *formatted, SbomCompList *out) {
	size_t before = out->count;
	while (formatted && isspace ((unsigned char)*formatted)) {
		formatted++;
	}
	if (!formatted || *formatted != '{' || !strchr (formatted, ':')) {
		return 0;
	}
	const char *p = formatted + 1;
	char *name = NULL;
	char *version = NULL;
	bool manifest = false;
	for (;;) {
		sbom_skip_ws (&p);
		if (*p == '}') {
			break;
		}
		char *key = sbom_parse_key (&p);
		if (!key) {
			break;
		}
		sbom_skip_ws (&p);
		if (*p != ':') {
			free (key);
			break;
		}
		p++;
		sbom_skip_ws (&p);
		char *value = NULL;
		if (*p == '"') {
			value = sbom_parse_quoted (&p);
		} else {
			sbom_skip_value (&p);
		}
		if (sbom_is_manifest_key (key)) {
			manifest = true;
		}
		if (value) {
			if (!strcmp (key, "name")) {
				free (name);
				name = strdup (value);
			} else if (!strcmp (key, "version")) {
				free (version);
				version = strdup (value);
			} else if (sbom_is_dep_name (key) && sbom_is_version_spec (value)) {
				(void)sbom_push (out, key, value);
			}
		}
		free (value);
		free (key);
		sbom_skip_ws (&p);
		if (*p == ',') {
			p++;
			continue;
		}
		if (*p == '}') {
			break;
		}
	}
	if (manifest && sbom_is_npm_name (name) && sbom_is_version_spec (version)) {
		(void)sbom_push (out, name, version);
	}
	free (name);
	free (version);
	return out->count - before;
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
		r_cons_println (core->cons, "(no SBOM candidates)");
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
	bool reset_lit_cache = hbc_literals_count (hbc) == 0;
	r = reset_lit_cache? hbc_literals_scan_code_kind (hbc, HBC_LIT_OBJECT, false, &nscanned): SUCCESS_RESULT ();
	if (r.code != RESULT_SUCCESS) {
		if (reset_lit_cache) {
			hbc_literals_reset (hbc);
		}
		R_LOG_ERROR ("literal scan failed: %s", safe_errmsg (r.error_message));
		return;
	}

	const HBCLiteralEntry *arr = NULL;
	u32 n = 0;
	if (hbc_literals_list (hbc, &arr, &n).code != RESULT_SUCCESS || !arr) {
		if (reset_lit_cache) {
			hbc_literals_reset (hbc);
		}
		R_LOG_ERROR ("literal list unavailable");
		return;
	}

	SbomCompList comps = { 0 };
	u32 matched = 0;
	for (u32 i = 0; i < n; i++) {
		const HBCLiteralEntry *e = &arr[i];
		if (e->kind != HBC_LIT_OBJECT || !sbom_object_may_match (hbc, e)) {
			continue;
		}
		char *owned = NULL;
		const char *formatted = e->formatted;
		if (!formatted) {
			Result fr = hbc_literals_format_raw (hbc, HBC_LIT_OBJECT, e->num_items, e->primary_id, e->secondary_id, &owned);
			if (fr.code != RESULT_SUCCESS || !owned) {
				free (owned);
				continue;
			}
			formatted = owned;
		}
		if (fmt == SBOM_FMT_RAW) {
			SbomCompList tmp = { 0 };
			if (sbom_harvest (formatted, &tmp) > 0) {
				matched++;
				r_cons_printf (core->cons, "# paddr=0x%08x xrefs=%u\n%s\n", e->paddr, e->xref_count, formatted);
			}
			sbom_free (&tmp);
		} else {
			matched += sbom_harvest (formatted, &comps) > 0;
		}
		free (owned);
	}

	if (fmt == SBOM_FMT_RAW) {
		if (matched == 0) {
			r_cons_println (core->cons, "(no SBOM candidates)");
		}
		if (reset_lit_cache) {
			hbc_literals_reset (hbc);
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
	if (reset_lit_cache) {
		hbc_literals_reset (hbc);
	}
}
