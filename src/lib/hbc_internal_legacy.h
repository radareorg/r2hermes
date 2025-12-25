#ifndef HBC_INTERNAL_LEGACY_H
#define HBC_INTERNAL_LEGACY_H

#include <hbc/hbc.h>

/* ============================================================================
 * INTERNAL LEGACY API - HBCState (For Data Provider Implementations Only)
 *
 * These functions are internal only. They exist to support the data provider
 * implementations that use HBCState internally. Do NOT use these in new code.
 * ============================================================================ */

typedef struct HBCState HBCState;

/* Opaque state handle (internal use only) */
Result hbc_open(const char *path, HBCState **out);
Result hbc_open_from_memory(const u8 *data, size_t size, HBCState **out);
void hbc_close(HBCState *hd);

u32 hbc_function_count(HBCState *hd);
u32 hbc_string_count(HBCState *hd);

Result hbc_get_header(HBCState *hd, HBCHeader *out);
Result hbc_get_function_info(HBCState *hd, u32 function_id, HBCFunc *out);
Result hbc_get_string(HBCState *hd, u32 index, const char **out_str);
Result hbc_get_string_meta(HBCState *hd, u32 index, HBCStringMeta *out);
Result hbc_get_string_tables(HBCState *hd, HBCStrs *out);
Result hbc_get_function_source(HBCState *hd, u32 function_id, const char **out_str);
Result hbc_get_function_bytecode(HBCState *hd, u32 function_id, const u8 **out_ptr, u32 *out_size);

#endif /* HBC_INTERNAL_LEGACY_H */
