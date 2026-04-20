#ifndef LIBHBC_LITERALS_PUBLIC_H
#define LIBHBC_LITERALS_PUBLIC_H

#include <hbc/common.h>
#include <hbc/hbc.h>

/* ============================================================================
 * Literals API (public)
 *
 * Covers the buffer-backed literals produced by:
 *   OP_NewArrayWithBuffer / OP_NewArrayWithBufferLong
 *   OP_NewObjectWithBuffer / OP_NewObjectWithBufferLong
 *
 * Responsibilities:
 *   - Format a literal from opcode immediates into a JS-like string.
 *   - Maintain a lazy cache of distinct literals so the disassembler and
 *     decompiler can look up previously-formatted literals in O(1) and avoid
 *     re-walking the SLP buffer on every call.
 *   - Track the set of instruction addresses that reference each literal.
 *   - Enumerate literals from the pool side (scan SLP stream) and from the
 *     code side (walk function bodies).
 *   - Allow resetting the cache to recover from a bad scan.
 *
 * Caching policy: entries are keyed by (kind, num_items, primary_id,
 * secondary_id); formatting happens at registration time and is memoized.
 * The cache can be cleared at any time.
 * ============================================================================ */

typedef enum {
	HBC_LIT_ARRAY = 0,
	HBC_LIT_OBJECT = 1
} HBCLiteralKind;

/* One entry in the literal cache. The strings / xref array are owned by the
 * HBC and freed on hbc_close() or hbc_literals_reset(). */
typedef struct {
	HBCLiteralKind kind;
	u32 num_items;
	u32 primary_id; /* array_id (array) or keys/shape id (object) */
	u32 secondary_id; /* values_id for objects, 0 for arrays */
	u32 paddr; /* absolute file offset of the literal data in the SLP pool (0 if unknown) */
	char *formatted; /* cached JS literal text; NULL if not yet formatted */
	u32 *xref_addrs; /* instruction addresses that construct this literal */
	u32 xref_count;
} HBCLiteralEntry;

/* Format a literal directly from raw parameters. Does not touch the cache.
 * Returned string is heap-allocated; caller frees with free(). */
Result hbc_literals_format_raw(HBC *hbc, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, char **out);

/* Convenience wrapper taking opcode + raw arg3/arg4/arg5 as decoded by
 * hbc_dec(). Knows the per-opcode mapping; useful as the "give me the string
 * for these parameters" helper. */
Result hbc_literals_format_for_opcode(HBC *hbc, u8 opcode, u32 arg3, u32 arg4,
	u32 arg5, char **out);

/* Look up (or create) a cache entry for a literal and return the formatted
 * text. The returned pointer is owned by the cache — do not free it. */
Result hbc_literals_get(HBC *hbc, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, const char **out_formatted);

/* Register that `from_addr` references the literal described by the key.
 * Creates the cache entry (and formats) on first reference. */
Result hbc_literals_register(HBC *hbc, HBCLiteralKind kind, u32 num_items,
	u32 primary_id, u32 secondary_id, u32 from_addr);

/* Full-binary scan: walk every function body; record every
 * New{Array,Object}WithBuffer[Long] call site into the cache (with xrefs).
 * Returns the number of distinct literals found in *out_count. */
Result hbc_literals_scan_code(HBC *hbc, u32 *out_count);

/* Pool-side scan: enumerate group boundaries in the SLP pool for the given
 * kind. For arrays and object-values it walks the byte stream linearly.
 * For object-keys on v97+ it enumerates the shape table instead.
 * Does not populate the cache — this is an inspection helper. Caller frees
 * *out via free(). */
typedef struct {
	u32 paddr; /* absolute file offset */
	u32 pool_offset; /* byte offset within the pool */
	u32 num_items; /* number of values in this group (or shape prop_count) */
	u8 tag; /* SLP tag 0..7 (for arrays/values); 0xff if not applicable */
} HBCPoolGroup;

Result hbc_literals_scan_pool(HBC *hbc, HBCLiteralKind kind,
	HBCPoolGroup **out, u32 *out_count);

/* Enumerate the current cache contents. The returned array is owned by the
 * HBC and valid until the next cache mutation. */
Result hbc_literals_list(HBC *hbc, const HBCLiteralEntry **out,
	u32 *out_count);

/* Drop every cached entry and every xref. Fast. Does not affect the SLP
 * pools themselves. */
void hbc_literals_reset(HBC *hbc);

/* Number of cached entries. 0 before any register / scan call. */
u32 hbc_literals_count(HBC *hbc);

/* Absolute file offset of the named pool, or 0 if the pool is empty/absent. */
u32 hbc_get_pool_paddr(HBC *hbc, HBCLiteralKind kind);
u32 hbc_get_pool_size(HBC *hbc, HBCLiteralKind kind);

/* Value pool paddr/size for objects (arrays & object-keys reuse the kind-based
 * accessors; object values is a distinct pool). */
u32 hbc_get_object_values_paddr(HBC *hbc);
u32 hbc_get_object_values_size(HBC *hbc);

/* Global toggle: whether hbc_dec() should inline the formatted literal as a
 * trailing " ; <text>" comment on the disasm line. Default: off. */
void hbc_set_inline_literals(bool on);
bool hbc_get_inline_literals(void);

#endif /* LIBHBC_LITERALS_PUBLIC_H */
