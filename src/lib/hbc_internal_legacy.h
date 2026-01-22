#ifndef HBC_INTERNAL_LEGACY_H
#define HBC_INTERNAL_LEGACY_H

#include <hbc/hbc.h>

/* ============================================================================
 * INTERNAL LEGACY API - HBC (For Data Provider Implementations Only)
 *
 * These functions are internal only. They exist to support the data provider
 * implementations that use HBC internally. Do NOT use these in new code.
 * ============================================================================ */

typedef struct HBC HBC;

/* Opaque state handle (internal use only) */
Result hbc_open(const char *path, HBC **out);
Result hbc_open_from_memory(const u8 *data, size_t size, HBC **out);
void hbc_close(HBC *hbc);

u32 hbc_function_count(HBC *hbc);
u32 hbc_string_count(HBC *hbc);

Result hbc_get_header(HBC *hbc, HBCHeader *out);
Result hbc_get_function_info(HBC *hbc, u32 function_id, HBCFunc *out);
Result hbc_get_string(HBC *hbc, u32 index, const char **out_str);
Result hbc_get_string_meta(HBC *hbc, u32 index, HBCStringMeta *out);
Result hbc_get_string_tables(HBC *hbc, HBCStrs *out);
Result hbc_get_function_source(HBC *hbc, u32 function_id, const char **out_str);
Result hbc_get_function_bytecode(HBC *hbc, u32 function_id, const u8 **out_ptr, u32 *out_size);

#endif /* HBC_INTERNAL_LEGACY_H */
