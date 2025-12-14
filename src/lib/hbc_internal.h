#ifndef SRC_LIB_HBC_INTERNAL_H
#define SRC_LIB_HBC_INTERNAL_H

#include <hbc/hbc.h>
#include <hbc/parser.h>

/* Internal full definition of HBCState (kept in a private header).
 * The public header exposes HBCState as an opaque typedef. */
struct HBCState {
	HBCReader reader; // Internal parser state
	HBCHeader header; // File header
	u32 version; // Bytecode version (from header)
	u32 string_count; // Number of strings in constant pool
	const char **strings; // Array of string pointers (constant string pool)
	u32 function_count; // Number of functions
	// Add more fields as needed: function info, bytecode, bigints, regex, etc.
};

#endif /* SRC_LIB_HBC_INTERNAL_H */
