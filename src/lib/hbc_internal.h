/* radare2 - BSD - Copyright 2025-2026 - pancake */

#ifndef HBC_INTERNAL_H
#define HBC_INTERNAL_H

#include <hbc/hbc.h>
#include <hbc/parser.h>
#include <hbc/literals.h>
#include <string.h>

/* Grow a dynamic array (doubling) so it has room for one more element.
 * arrp points at the array pointer (e.g. &vec->data); *cap is the capacity in
 * elements; initial is the capacity to allocate when growing from empty. The
 * stored pointer is read/written via memcpy so no aliasing cast is needed. */
static inline Result grow_array(void *arrp, u32 *cap, u32 count, size_t elem_size, u32 initial) {
	if (count < *cap) {
		return SUCCESS_RESULT ();
	}
	u32 new_cap = *cap? *cap * 2: initial;
	void *cur;
	memcpy (&cur, arrp, sizeof (cur));
	void *grown = realloc (cur, (size_t)new_cap * elem_size);
	if (!grown) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "out of memory");
	}
	memcpy (arrp, &grown, sizeof (grown));
	*cap = new_cap;
	return SUCCESS_RESULT ();
}

typedef struct {
	HBCLiteralEntry *entries;
	u32 count;
	u32 cap;
} HBCLiteralCache;

struct HBC {
	HBCReader reader;
	HBCHeader header;
	u32 version;
	u32 string_count;
	const char **strings;
	u32 function_count;
	HBCLiteralCache lit_cache;
};

#endif /* HBC_INTERNAL_H */
