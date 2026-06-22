/* radare2 - BSD - Copyright 2025-2026 - pancake */

/* CycloneDX SBOM generation for Hermes bytecode.
 *
 * Strategy:
 *   - Use string-table package path/name evidence when present.
 *   - Otherwise scan SLP literals and keep adjacent package/version array
 *     entries, package.json-style metadata objects ({name,version}), and
 *     dependency maps ({package: version}).
 *   - The literal formatter prints valid JS identifiers as bare keys
 *({foo: "1.2.3"}), which is not strict JSON. We rewrite bare keys
 *     into quoted ones, then parse with r_json so we don't hand-roll a
 *     key/value parser.
 *   - Emit each recovered package name and version as a CycloneDX component.
 *
 * Output formats:
 *   r2hermes-S    plaintext (one "name version" per line)
 *   r2hermes-Sj   CycloneDX JSON (built via PJ)
 */

#include <hbc/hbc.h>
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
	if (!name) {
		return false;
	}
	for (size_t i = 0; i < list->count; i++) {
		SbomComp *it = &list->items[i];
		if (strcmp (it->name, name)) {
			continue;
		}
		if (!version) {
			return true;
		}
		if (!it->version) {
			it->version = strdup (version);
			return it->version != NULL;
		}
		if (!strcmp (it->version, version)) {
			return true;
		}
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
	list->items[list->count].version = version? strdup (version): NULL;
	if (!list->items[list->count].name || (version && !list->items[list->count].version)) {
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
			r_strbuf_append_n (sb, start, (int) (p - start));
			continue;
		}
		unsigned char c = (unsigned char)*p;
		if (isalpha (c) || c == '_' || c == '$') {
			const char *start = p;
			while (*p && (isalnum ((unsigned char)*p) || *p == '_' || *p == '$')) {
				p++;
			}
			int len = (int) (p - start);
			const char *q = p;
			while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') {
				q++;
			}
			bool is_key = (*q == ':');
			bool is_literal = (len == 4 && !memcmp (start, "true", 4)) || (len == 5 && !memcmp (start, "false", 5)) || (len == 4 && !memcmp (start, "null", 4));
			if (is_key && !is_literal) {
				r_strbuf_append (sb, "\"");
				r_strbuf_append_n (sb, start, len);
				r_strbuf_append (sb, "\"");
			} else {
				r_strbuf_append_n (sb, start, len);
			}
			continue;
		}
		if (isdigit (c)) {
			const char *start = p;
			while (*p && (isdigit ((unsigned char)*p) || *p == '.')) {
				p++;
			}
			const char *q = p;
			while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') {
				q++;
			}
			if (*q == ':') {
				r_strbuf_append (sb, "\"");
				r_strbuf_append_n (sb, start, (int) (p - start));
				r_strbuf_append (sb, "\"");
			} else {
				r_strbuf_append_n (sb, start, (int) (p - start));
			}
			continue;
		}
		char one[2] = { *p, 0 };
		r_strbuf_append (sb, one);
		p++;
	}
	return r_strbuf_drain (sb);
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

static bool sbom_is_manifest_key(const char *key) {
	return !strcmp (key, "description") || !strcmp (key, "license") || !strcmp (key, "main") ||
		!strcmp (key, "module") || !strcmp (key, "repository") || !strcmp (key, "dependencies") ||
		!strcmp (key, "devDependencies") || !strcmp (key, "peerDependencies");
}

static bool sbom_is_dep_name(const char *s) {
	return sbom_is_npm_name (s) && !sbom_is_manifest_key (s);
}

static bool sbom_pkg_name_char(unsigned char c) {
	return c && (islower (c) || isdigit (c) || strchr ("-_.~", c));
}

static char *sbom_parse_pkg_at(const char *s) {
	if (R_STR_ISEMPTY (s)) {
		return NULL;
	}
	const char *p = s;
	if (*p == '@') {
		p++;
		if (!islower ((unsigned char)*p) && !isdigit ((unsigned char)*p)) {
			return NULL;
		}
		while (sbom_pkg_name_char ((unsigned char)*p)) {
			p++;
		}
		if (*p != '/' || (!islower ((unsigned char)p[1]) && !isdigit ((unsigned char)p[1]))) {
			return NULL;
		}
		p++;
		while (sbom_pkg_name_char ((unsigned char)*p)) {
			p++;
		}
	} else {
		if (!islower ((unsigned char)*p) && !isdigit ((unsigned char)*p)) {
			return NULL;
		}
		while (sbom_pkg_name_char ((unsigned char)*p)) {
			p++;
		}
	}
	if (p == s) {
		return NULL;
	}
	char *name = r_str_ndup (s, (int) (p - s));
	if (!name) {
		return NULL;
	}
	if (!sbom_is_npm_name (name)) {
		free (name);
		return NULL;
	}
	return name;
}

static char *sbom_pkg_from_ref(const char *s) {
	if (R_STR_ISEMPTY (s)) {
		return NULL;
	}
	if (sbom_is_dep_name (s)) {
		return strdup (s);
	}
	const char *slash = strchr (s, '/');
	if (!slash || *s == '@') {
		return NULL;
	}
	char *name = r_str_ndup (s, (int)(slash - s));
	if (!name) {
		return NULL;
	}
	if (!sbom_is_dep_name (name)) {
		free (name);
		return NULL;
	}
	return name;
}

static size_t sbom_harvest_quoted_package_refs(const char *s, SbomCompList *out) {
	size_t before = out->count;
	if (!strstr (s, "package") || !strchr (s, '"')) {
		return 0;
	}
	const char *p = s;
	while ((p = strchr (p, '"'))) {
		p++;
		const char *end = strchr (p, '"');
		if (!end) {
			break;
		}
		const char *after = end + 1;
		while (isspace ((unsigned char)*after)) {
			after++;
		}
		if (r_str_startswith (after, "package")) {
			char *ref = r_str_ndup (p, (int)(end - p));
			if (ref) {
				char *pkg = sbom_pkg_from_ref (ref);
				if (pkg) {
					(void)sbom_push (out, pkg, NULL);
					free (pkg);
				}
				free (ref);
			}
		}
		p = end + 1;
	}
	return out->count - before;
}

static size_t sbom_harvest_package_path_refs(const char *s, SbomCompList *out) {
	size_t before = out->count;
	if (R_STR_ISEMPTY (s)) {
		return 0;
	}
	const char *needle = "node_modules/";
	const size_t needle_len = strlen (needle);
	for (const char *p = strstr (s, needle); p; p = strstr (p, needle)) {
		p += needle_len;
		char *pkg = sbom_parse_pkg_at (p);
		if (pkg) {
			(void)sbom_push (out, pkg, NULL);
			free (pkg);
		}
	}
	if (*s == '@') {
		char *pkg = sbom_parse_pkg_at (s);
		if (pkg) {
			if (!strcmp (pkg, s)) {
				(void)sbom_push (out, pkg, NULL);
			}
			free (pkg);
		}
	}
	return out->count - before;
}

static size_t sbom_harvest_strings(HBC *hbc, SbomCompList *out) {
	if (!hbc) {
		return 0;
	}
	size_t path_evidence = 0;
	u32 n = hbc_string_count (hbc);
	for (u32 i = 0; i < n; i++) {
		const char *s = NULL;
		if (hbc_get_string (hbc, i, &s).code == RESULT_SUCCESS && s) {
			path_evidence += sbom_harvest_package_path_refs (s, out);
			(void)sbom_harvest_quoted_package_refs (s, out);
		}
	}
	return path_evidence;
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

static bool sbom_is_array_version_spec(const char *version) {
	if (R_STR_ISEMPTY (version)) {
		return false;
	}
	const char *p = version;
	while (isspace ((unsigned char)*p)) {
		p++;
	}
	if (*p == 'v') {
		p++;
	}
	int segments = 0;
	bool dot = false;
	for (;;) {
		if (!isdigit ((unsigned char)*p)) {
			return false;
		}
		do {
			p++;
		} while (isdigit ((unsigned char)*p));
		segments++;
		if (*p != '.') {
			break;
		}
		dot = true;
		p++;
	}
	if (!dot || segments < 2) {
		return false;
	}
	if (*p == '-' || *p == '+') {
		p++;
		if (!isalnum ((unsigned char)*p)) {
			return false;
		}
		while (*p && (isalnum ((unsigned char)*p) || strchr ("-.+", *p))) {
			p++;
		}
	}
	while (isspace ((unsigned char)*p)) {
		p++;
	}
	return *p == 0;
}

static bool sbom_is_strong_npm_name(const char *name) {
	return sbom_is_dep_name (name) && (*name == '@' || strchr (name, '/') || strchr (name, '-'));
}

static bool sbom_is_module_evidence(const HBCModule *module) {
	if (!module || !module->kind || !module->name) {
		return false;
	}
	if (!strcmp (module->kind, "package")) {
		return sbom_is_dep_name (module->name);
	}
	return !strcmp (module->kind, "native") && sbom_is_strong_npm_name (module->name);
}

static size_t sbom_harvest_modules(HBC *hbc, SbomCompList *out) {
	size_t before = out->count;
	HBCModules modules = { 0 };
	if (hbc_list_modules (hbc, &modules).code != RESULT_SUCCESS) {
		return 0;
	}
	for (u32 i = 0; i < modules.count; i++) {
		const HBCModule *m = &modules.modules[i];
		if (sbom_is_module_evidence (m)) {
			(void)sbom_push (out, m->name, m->version);
		}
	}
	hbc_free_modules (&modules);
	return out->count - before;
}

static char *sbom_read_json_string(const char **cursor) {
	const char *p = *cursor;
	if (*p != '"') {
		return NULL;
	}
	p++;
	const char *start = p;
	RStrBuf *sb = NULL;
	while (*p && *p != '"') {
		if (*p != '\\') {
			p++;
			continue;
		}
		if (!sb) {
			sb = r_strbuf_new ("");
			if (!sb) {
				return NULL;
			}
		}
		r_strbuf_append_n (sb, start, (int)(p - start));
		p++;
		if (!*p) {
			r_strbuf_free (sb);
			return NULL;
		}
		switch (*p) {
		case '"':
		case '\\':
		case '/':
			r_strbuf_append_n (sb, p, 1);
			break;
		case 'b':
			r_strbuf_append_n (sb, "\b", 1);
			break;
		case 'f':
			r_strbuf_append_n (sb, "\f", 1);
			break;
		case 'n':
			r_strbuf_append_n (sb, "\n", 1);
			break;
		case 'r':
			r_strbuf_append_n (sb, "\r", 1);
			break;
		case 't':
			r_strbuf_append_n (sb, "\t", 1);
			break;
		default:
			r_strbuf_append_n (sb, p, 1);
			break;
		}
		p++;
		start = p;
	}
	if (*p != '"') {
		if (sb) {
			r_strbuf_free (sb);
		}
		return NULL;
	}
	char *out = sb? r_strbuf_drain (sb): r_str_ndup (start, (int)(p - start));
	*cursor = p + 1;
	return out;
}

typedef struct {
	char *text;
	bool is_name;
	bool is_version;
} SbomArrayToken;

static void sbom_array_token_fini(SbomArrayToken *tok) {
	free (tok->text);
	tok->text = NULL;
	tok->is_name = false;
	tok->is_version = false;
}

static void sbom_array_pair_push(SbomCompList *out, const SbomArrayToken *a, const SbomArrayToken *b) {
	if (a->is_name && b->is_version && sbom_is_strong_npm_name (a->text)) {
		(void)sbom_push (out, a->text, b->text);
	} else if (a->is_version && b->is_name) {
		(void)sbom_push (out, b->text, a->text);
	}
}

static size_t sbom_harvest_array(const char *formatted, SbomCompList *out) {
	size_t before = out->count;
	if (R_STR_ISEMPTY (formatted) || *formatted != '[') {
		return 0;
	}
	SbomArrayToken prev = { 0 };
	const char *p = formatted;
	while (*p) {
		if (*p != '"') {
			p++;
			continue;
		}
		char *text = sbom_read_json_string (&p);
		if (!text) {
			break;
		}
		bool is_version = sbom_is_array_version_spec (text);
		SbomArrayToken cur = {
			.text = text,
			.is_name = !is_version && sbom_is_dep_name (text),
			.is_version = is_version,
		};
		sbom_array_pair_push (out, &prev, &cur);
		sbom_array_token_fini (&prev);
		prev = cur;
	}
	sbom_array_token_fini (&prev);
	return out->count - before;
}

/* Extract name/version metadata and dependency-map entries from one literal. */
static size_t sbom_harvest_object(const char *formatted, SbomCompList *out) {
	size_t before = out->count;
	char *jsonstr = jsobj_to_json (formatted);
	if (!jsonstr) {
		return 0;
	}
	RJson *js = r_json_parsedup (jsonstr);
	free (jsonstr);
	if (!js) {
		return 0;
	}
	if (js->type == R_JSON_OBJECT) {
		const char *name = NULL;
		const char *version = NULL;
		bool manifest = false;
		for (RJson *kid = js->children.first; kid; kid = kid->next) {
			if (!kid->key) {
				continue;
			}
			if (sbom_is_manifest_key (kid->key)) {
				manifest = true;
			}
			if (kid->type != R_JSON_STRING || !kid->str_value) {
				continue;
			}
			if (!strcmp (kid->key, "name")) {
				name = kid->str_value;
			} else if (!strcmp (kid->key, "version")) {
				version = kid->str_value;
			} else if (sbom_is_dep_name (kid->key) && sbom_is_version_spec (kid->str_value)) {
				(void)sbom_push (out, kid->key, kid->str_value);
			}
		}
		if (manifest && sbom_is_npm_name (name) && (!version || sbom_is_version_spec (version))) {
			(void)sbom_push (out, name, version);
		}
	}
	r_json_free (js);
	return out->count - before;
}

static size_t sbom_harvest_literal(const HBCLiteralEntry *e, SbomCompList *out) {
	if (!e || !e->formatted) {
		return 0;
	}
	if (e->kind == HBC_LIT_ARRAY) {
		return sbom_harvest_array (e->formatted, out);
	}
	if (e->kind == HBC_LIT_OBJECT) {
		return sbom_harvest_object (e->formatted, out);
	}
	return 0;
}

static int sbom_comp_cmp(const void *a, const void *b) {
	const SbomComp *ca = a;
	const SbomComp *cb = b;
	int r = strcmp (ca->name, cb->name);
	const char *va = ca->version? ca->version: "";
	const char *vb = cb->version? cb->version: "";
	return r? r: strcmp (va, vb);
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
		if (list->items[i].version) {
			r_cons_printf (core->cons, "%s %s\n", list->items[i].name, list->items[i].version);
		} else {
			r_cons_println (core->cons, list->items[i].name);
		}
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
		if (c->version) {
			pj_ks (pj, "version", c->version);
		}
		char *purl = c->version? r_str_newf ("pkg:npm/%s@%s", c->name, c->version): r_str_newf ("pkg:npm/%s", c->name);
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
	" r2hermes-S       Emit SBOM as plaintext (name + version, or name only when version is unknown)\n"
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

	SbomCompList comps = { 0 };
	if (fmt != SBOM_FMT_RAW) {
		size_t path_evidence = sbom_harvest_strings (hbc, &comps);
		(void)sbom_harvest_modules (hbc, &comps);
		if (path_evidence > 0) {
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
			return;
		}
	}

	u32 nscanned = 0;
	r = hbc_literals_scan_code (hbc, &nscanned);
	if (r.code != RESULT_SUCCESS) {
		R_LOG_ERROR ("literal scan failed: %s", safe_errmsg (r.error_message));
		sbom_free (&comps);
		return;
	}

	const HBCLiteralEntry *arr = NULL;
	u32 n = 0;
	if (hbc_literals_list (hbc, &arr, &n).code != RESULT_SUCCESS || !arr) {
		R_LOG_ERROR ("literal list unavailable");
		sbom_free (&comps);
		return;
	}

	u32 matched = 0;
	for (u32 i = 0; i < n; i++) {
		const HBCLiteralEntry *e = &arr[i];
		if (!e->formatted) {
			continue;
		}
		if (fmt == SBOM_FMT_RAW) {
			SbomCompList tmp = { 0 };
			if (sbom_harvest_literal (e, &tmp) > 0) {
				matched++;
				r_cons_printf (core->cons, "# paddr=0x%08x xrefs=%u\n%s\n", e->paddr, e->xref_count, e->formatted);
			}
			sbom_free (&tmp);
		} else {
			matched += sbom_harvest_literal (e, &comps) > 0;
		}
	}

	if (fmt == SBOM_FMT_RAW) {
		if (matched == 0) {
			r_cons_println (core->cons, "(no SBOM candidates)");
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
