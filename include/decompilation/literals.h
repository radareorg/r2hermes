#ifndef HERMES_DEC_LITERALS_H
#define HERMES_DEC_LITERALS_H

#include "../common.h"
#include "../parsers/hbc_file_parser.h"
#include "../parsers/hbc_bytecode_parser.h"

/* Utilities to format JS-like literals and calls from Hermes buffers/instructions. */

/* Pretty-print policy for literals. */
typedef enum {
    LITERALS_PRETTY_AUTO = 0,   /* Heuristic based on element count */
    LITERALS_PRETTY_ALWAYS = 1, /* Force multi-line */
    LITERALS_PRETTY_NEVER = 2   /* Force single-line */
} LiteralsPrettyPolicy;

/* Configure pretty-print policy (global within process). */
void set_literals_pretty_policy(LiteralsPrettyPolicy p);
LiteralsPrettyPolicy get_literals_pretty_policy(void);

/* Global toggle to suppress comments in decompiled output. */
void set_decompile_suppress_comments(bool on);
bool get_decompile_suppress_comments(void);

/* True if the given string is a valid JS identifier (simple heuristic: [A-Za-z_$][A-Za-z0-9_$]*) */
bool is_js_identifier(const char* s);

/* Append a JS object literal reconstructed from object key/value buffers.
 * Decodes the Hermes SerializedLiteral buffers into real JS literals.
 * Falls back to a compact placeholder comment on failure. */
Result format_object_literal(HBCReader* r, u32 key_count, u32 value_count, u32 keys_id, u32 values_id, StringBuffer* out, bool pretty);

/* Append a JS array literal reconstructed from array buffer.
 * Decodes the Hermes SerializedLiteral buffers into real JS literals.
 * Falls back to a compact placeholder comment on failure. */
Result format_array_literal(HBCReader* r, u32 value_count, u32 array_id, StringBuffer* out, bool pretty);

/* Format property access: emits ".name" for identifier-like names, or ["name"] otherwise. */
Result format_property_from_string_id(HBCReader* r, u32 string_id, StringBuffer* out);

/* Format a variadic call/construct when only (callee, this, argc) are provided.
 * Attempts best-effort representation and falls back to including argc as a comment. */
Result format_variadic_call(const ParsedInstruction* insn, StringBuffer* out);

#endif /* HERMES_DEC_LITERALS_H */
