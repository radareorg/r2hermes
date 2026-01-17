#include <hbc/decompilation/literals.h>
#include <ctype.h>
#include <math.h>

bool _hbc_is_js_identifier(const char *s) {
	if (!s || !*s) {
		return false;
	}
	unsigned char c = (unsigned char)*s;
	if (! (isalpha (c) || c == '_' || c == '$')) {
		return false;
	}
	for (s++; *s; s++) {
		unsigned char d = (unsigned char)*s;
		if (! (isalnum (d) || d == '_' || d == '$')) {
			return false;
		}
	}
	return true;
}

static Result append_quoted(StringBuffer *out, const char *s) {
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, "\""));
	for (const char *p = s; p && *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (c == '"' || c == '\\') {
			RETURN_IF_ERROR (_hbc_string_buffer_append_char (out, '\\'));
			RETURN_IF_ERROR (_hbc_string_buffer_append_char (out, (char)c));
		} else if (c < 0x20) {
			char tmp[8];
			snprintf (tmp, sizeof (tmp), "\\x%02x", c);
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, tmp));
		} else {
			RETURN_IF_ERROR (_hbc_string_buffer_append_char (out, (char)c));
		}
	}
	return _hbc_string_buffer_append (out, "\"");
}

Result _hbc_format_property_from_string_id(HBCReader *r, u32 string_id, StringBuffer *out) {
	const char *s = NULL;
	if (r && r->strings && string_id < r->header.stringCount) {
		s = r->strings[string_id];
	}
	if (_hbc_is_js_identifier (s)) {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, "."));
		return _hbc_string_buffer_append (out, s);
	}
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, "["));
	if (s) {
		RETURN_IF_ERROR (append_quoted (out, s));
	} else {
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, "\"\""));
	}
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, "]"));
	return SUCCESS_RESULT ();
}

/*(legacy helper removed: previous buffer interpretation used u32 lists) */

/* Serialized Literal Parser (SLP) */
typedef enum {
	SLP_NullTag = 0,
	SLP_TrueTag = 1,
	SLP_FalseTag = 2,
	SLP_NumberTag = 3,
	SLP_LongStringTag = 4,
	SLP_ShortStringTag = 5,
	SLP_ByteStringTag = 6,
	SLP_IntegerTag = 7
} SLPTagType;

typedef struct {
	SLPTagType tag;
	union {
		double num;
		u32 str_id;
		u32 intv;
	} v;
} SLPValue;

static bool slp_read_u8(const u8 *base, size_t size, size_t *pos, u8 *out) {
	if (*pos + 1 > size) {
		return false;
	}
	*out = base[*pos];
	(*pos)++;
	return true;
}
static bool slp_read_u16(const u8 *base, size_t size, size_t *pos, u16 *out) {
	if (*pos + 2 > size) {
		return false;
	}
	*out = (u16) (base[*pos] | (base[*pos + 1] << 8));
	(*pos) += 2;
	return true;
}
static bool slp_read_u32(const u8 *base, size_t size, size_t *pos, u32 *out) {
	if (*pos + 4 > size) {
		return false;
	}
	*out = (u32) (base[*pos] | (base[*pos + 1] << 8) | (base[*pos + 2] << 16) | (base[*pos + 3] << 24));
	(*pos) += 4;
	return true;
}
static bool slp_read_double(const u8 *base, size_t size, size_t *pos, double *out) {
	if (*pos + 8 > size) {
		return false;
	}
	union {
		u64 u;
		double d;
	} u;
	u.u = ((u64)base[*pos + 7] << 56) | ((u64)base[*pos + 6] << 48) | ((u64)base[*pos + 5] << 40) | ((u64)base[*pos + 4] << 32) | ((u64)base[*pos + 3] << 24) | ((u64)base[*pos + 2] << 16) | ((u64)base[*pos + 1] << 8) | (u64)base[*pos];
	*out = u.d;
	(*pos) += 8;
	return true;
}

/* Parse exactly num_items values from a SerializedLiteral stream at offset.
 * If a run-length group exceeds remaining items, we still consume the full group's bytes
 * but only store the first remaining values. Returns false on bounds/format errors. */
static bool slp_parse_values(const u8 *base, size_t size, u32 offset, u32 num_items, SLPValue *out_vals) {
	if (!base) {
		return false;
	}
	size_t pos = (size_t)offset;
	u32 written = 0;
	while (written < num_items) {
		u8 taglen;
		if (!slp_read_u8 (base, size, &pos, &taglen)) {
			return false;
		}
		SLPTagType tag = (SLPTagType) ((taglen >> 4) & 0x7);
		u32 length = (u32) (taglen & 0x0F);
		if ((taglen >> 7) & 0x1) {
			/* extended length: low nibble << 8 | next byte */
			u8 extra;
			if (!slp_read_u8 (base, size, &pos, &extra)) {
				return false;
			}
			length = ((u32) (taglen & 0x0F) << 8) | (u32)extra;
		}
		/* For each value in the run */
		for (u32 i = 0; i < length; i++) {
			SLPValue tmp;
			tmp.tag = tag;
			switch (tag) {
			case SLP_NullTag: break;
			case SLP_TrueTag: break;
			case SLP_FalseTag: break;
			case SLP_NumberTag:
				if (!slp_read_double (base, size, &pos, &tmp.v.num)) {
					return false;
				}
				break;
			case SLP_LongStringTag:
				if (!slp_read_u32 (base, size, &pos, &tmp.v.str_id)) {
					return false;
				}
				break;
			case SLP_ShortStringTag:
				{
					u16 sid;
					if (!slp_read_u16 (base, size, &pos, &sid)) {
						return false;
					}
					tmp.v.str_id = sid;
					break;
				}
			case SLP_ByteStringTag:
				{
					u8 sid;
					if (!slp_read_u8 (base, size, &pos, &sid)) {
						return false;
					}
					tmp.v.str_id = sid;
					break;
				}
			case SLP_IntegerTag:
				if (!slp_read_u32 (base, size, &pos, &tmp.v.intv)) {
					return false;
				}
				break;
			default: return false;
			}
			if (written < num_items) {
				out_vals[written++] = tmp;
			} else {
				/* Discard extra parsed values beyond requested count (shouldn't happen) */
			}
		}
	}
	return true;
}

static Result slp_append_value_js(HBCReader *r, const SLPValue *v, bool for_key, StringBuffer *out) {
	switch (v->tag) {
	case SLP_NullTag: return _hbc_string_buffer_append (out, "null");
	case SLP_TrueTag: return _hbc_string_buffer_append (out, "true");
	case SLP_FalseTag: return _hbc_string_buffer_append (out, "false");
	case SLP_IntegerTag:
		{
			char nb[32];
			snprintf (nb, sizeof (nb), "%u", (unsigned)v->v.intv);
			return _hbc_string_buffer_append (out, nb);
		}
	case SLP_NumberTag:
		{
			char db[64];
			/* Use %.17g to preserve precision while avoiding trailing noise */
			snprintf (db, sizeof (db), "%.17g", v->v.num);
			return _hbc_string_buffer_append (out, db);
		}
	case SLP_LongStringTag:
	case SLP_ShortStringTag:
	case SLP_ByteStringTag:
		{
		const char *s = (r && r->strings && v->v.str_id < r->header.stringCount)? r->strings[v->v.str_id]: NULL;
		if (for_key && s && _hbc_is_js_identifier (s)) {
				return _hbc_string_buffer_append (out, s);
			}
			if (s) {
				return append_quoted (out, s);
			}
			return _hbc_string_buffer_append (out, "\"\"");
		}
	default:
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Unknown SLP tag");
	}
}

Result _hbc_format_object_literal(HBCReader *r, u32 key_count, u32 value_count, u32 keys_id, u32 values_id, StringBuffer *out, LiteralsPrettyPolicy policy, bool suppress_comments) {
	/* Apply policy */
	bool pretty = (policy == LITERALS_PRETTY_ALWAYS) || (policy == LITERALS_PRETTY_AUTO && (key_count > 0));
	bool multiline = pretty && (key_count > 0);
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, multiline? "{\n": "{"));
	if (!r || key_count == 0 || value_count == 0 || !r->object_keys || !r->object_values) {
		/* Fallback placeholder */
		if (suppress_comments) {
			return _hbc_string_buffer_append (out, "}");
		}
		char tmp[96];
		snprintf (tmp, sizeof (tmp), " /*k:%u id:%u vals:%u*/ }", key_count, keys_id, values_id);
		return _hbc_string_buffer_append (out, tmp);
	}
	u32 n = key_count < value_count? key_count: value_count;
	SLPValue *key_vals = (SLPValue *)calloc (n, sizeof (SLPValue));
	if (!key_vals) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom key slp");
	}
	SLPValue *val_vals = (SLPValue *)calloc (n, sizeof (SLPValue));
	if (!val_vals) {
		free (key_vals);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom val slp");
	}

	bool ok1 = slp_parse_values (r->object_keys, r->header.objKeyBufferSize, keys_id, n, key_vals);
	bool ok2 = slp_parse_values (r->object_values, r->header.objValueBufferSize, values_id, n, val_vals);
	if (!ok1 || !ok2) {
		free (key_vals);
		free (val_vals);
		if (suppress_comments) {
			return _hbc_string_buffer_append (out, "}");
		}
		char tmp[96];
		snprintf (tmp, sizeof (tmp), " /*k:%u id:%u vals:%u*/ }", key_count, keys_id, values_id);
		return _hbc_string_buffer_append (out, tmp);
	}

	for (u32 i = 0; i < n; i++) {
		if (multiline) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, "  "));
		}
		if (!multiline && i) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, ", "));
		}
		/* Key: allow identifiers and numeric keys unquoted; otherwise quote. */
		RETURN_IF_ERROR (slp_append_value_js (r, &key_vals[i], true /*for_key*/, out));
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, ": "));
		/* Value: always a valid JS literal */
		RETURN_IF_ERROR (slp_append_value_js (r, &val_vals[i], false, out));
		if (multiline) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, i + 1 < n? ",\n": "\n"));
		}
	}

	free (key_vals);
	free (val_vals);
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, multiline? "}": "}"));
	return SUCCESS_RESULT ();
}

Result _hbc_format_array_literal(HBCReader *r, u32 value_count, u32 array_id, StringBuffer *out, LiteralsPrettyPolicy policy, bool suppress_comments) {
	/* Apply policy */
	bool pretty = (policy == LITERALS_PRETTY_ALWAYS) || (policy == LITERALS_PRETTY_AUTO && (value_count > 0));
	bool multiline = pretty && (value_count > 0);
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, multiline? "[\n": "["));
	if (!r || !r->arrays || value_count == 0) {
		if (suppress_comments) {
			return _hbc_string_buffer_append (out, "]");
		}
		char tmp[64];
		snprintf (tmp, sizeof (tmp), " /*n:%u id:%u*/ ]", value_count, array_id);
		return _hbc_string_buffer_append (out, tmp);
	}
	SLPValue *vals = (SLPValue *)calloc (value_count, sizeof (SLPValue));
	if (!vals) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "oom arr slp");
	}
	bool ok = slp_parse_values (r->arrays, r->header.arrayBufferSize, array_id, value_count, vals);
	if (!ok) {
		free (vals);
		if (suppress_comments) {
			return _hbc_string_buffer_append (out, "]");
		}
		char tmp[64];
		snprintf (tmp, sizeof (tmp), " /*n:%u id:%u*/ ]", value_count, array_id);
		return _hbc_string_buffer_append (out, tmp);
	}
	for (u32 i = 0; i < value_count; i++) {
		if (multiline) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, "  "));
		}
		if (!multiline && i) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, ", "));
		}
		RETURN_IF_ERROR (slp_append_value_js (r, &vals[i], false, out));
		if (multiline) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, i + 1 < value_count? ",\n": "\n"));
		}
	}
	free (vals);
	RETURN_IF_ERROR (_hbc_string_buffer_append (out, "]"));
	return SUCCESS_RESULT ();
}

Result _hbc_format_variadic_call(const ParsedInstruction *insn, StringBuffer *out) {
	/* Known operands: arg1=callee, arg2=this, arg3=argc or imm32 argc. */
	u32 argc = insn->arg3;
	if (argc > 0) {
		/* Heuristic: arguments follow 'this' in successive registers */
		u32 base = insn->arg2;
		for (u32 i = 1; i <= argc; i++) {
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, ", "));
			char nb[16];
			snprintf (nb, sizeof (nb), "r%u", base + i);
			RETURN_IF_ERROR (_hbc_string_buffer_append (out, nb));
		}
		/* Also annotate argc */
		char cm[32];
		snprintf (cm, sizeof (cm), " /*argc:%u*/", argc);
		RETURN_IF_ERROR (_hbc_string_buffer_append (out, cm));
	} else {
		/* No args beyond 'this' */
	}
	return SUCCESS_RESULT ();
}
