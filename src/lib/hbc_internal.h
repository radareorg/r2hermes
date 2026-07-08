/* radare2 - BSD - Copyright 2025-2026 - pancake */

#ifndef HBC_INTERNAL_H
#define HBC_INTERNAL_H

#include <hbc/hbc.h>
#include <hbc/parser.h>
#include <hbc/literals.h>
#include <hbc/vec.h>
#include <stdlib.h>
#include <string.h>

static inline void hbc_literal_entry_fini(HBCLiteralEntry *entry) {
	if (!entry) {
		return;
	}
	free (entry->formatted);
	free (entry->xref_addrs);
}

R_VEC_TYPE_WITH_FINI(RVecHBCLiteralEntry, HBCLiteralEntry, hbc_literal_entry_fini)

typedef struct {
	RVecHBCLiteralEntry entries;
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
