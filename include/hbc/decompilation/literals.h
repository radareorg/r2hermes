#ifndef HERMES_DEC_LITERALS_H
#define HERMES_DEC_LITERALS_H

#include <hbc/common.h>
#include <hbc/parser.h>
#include <hbc/bytecode.h>

/* Utilities to format JS-like literals and calls from Hermes buffers/instructions. */

/* Pretty-print policy for literals. */
typedef enum {
	LITERALS_PRETTY_AUTO = 0, /* Heuristic based on element count */
	LITERALS_PRETTY_ALWAYS = 1, /* Force multi-line */
	LITERALS_PRETTY_NEVER = 2 /* Force single-line */
} LiteralsPrettyPolicy;

/* True if the given string is a valid JS identifier (simple heuristic: [A-Za-z_$][A-Za-z0-9_$]*) */
bool is_js_identifier(const char *s);

/* Append a JS object literal reconstructed from object key/value buffers.
 * Decodes the Hermes SerializedLiteral buffers into real JS literals.
 * Falls back to a compact placeholder comment on failure. */
Result format_object_literal(HBCReader *r, u32 key_count, u32 value_count, u32 keys_id, u32 values_id, StringBuffer *out, LiteralsPrettyPolicy policy, bool suppress_comments);

/* Append a JS array literal reconstructed from array buffer.
 * Decodes the Hermes SerializedLiteral buffers into real JS literals.
 * Falls back to a compact placeholder comment on failure. */
Result format_array_literal(HBCReader *r, u32 value_count, u32 array_id, StringBuffer *out, LiteralsPrettyPolicy policy, bool suppress_comments);

/* Format property access: emits ".name" for identifier-like names, or ["name"] otherwise. */
Result format_property_from_string_id(HBCReader *r, u32 string_id, StringBuffer *out);

/* Format a variadic call/construct when only (callee, this, argc) are provided.
 * Attempts best-effort representation and falls back to including argc as a comment. */
Result format_variadic_call(const ParsedInstruction *insn, StringBuffer *out);

#endif /* HERMES_DEC_LITERALS_H */
