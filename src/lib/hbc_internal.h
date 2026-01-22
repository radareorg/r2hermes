#ifndef HBC_INTERNAL_H
#define HBC_INTERNAL_H

#include <hbc/hbc.h>
#include <hbc/parser.h>

struct HBC {
	HBCReader reader;
	HBCHeader header;
	u32 version;
	u32 string_count;
	const char **strings;
	u32 function_count;
};

#endif /* HBC_INTERNAL_H */
