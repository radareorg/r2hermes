#ifndef HBC_INTERNAL_H
#define HBC_INTERNAL_H

#include <hbc/hbc.h>
#include <hbc/parser.h>
#include <hbc/literals.h>

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
