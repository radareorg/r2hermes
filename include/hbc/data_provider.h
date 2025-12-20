#ifndef HBC_DATA_PROVIDER_H
#define HBC_DATA_PROVIDER_H

#include <hbc/common.h>

/* Opaque data provider handle */
typedef struct HBCDataProvider HBCDataProvider;

/* Forward declarations for types defined in hbc.h (avoid circular include) */
struct HBCHeader;
struct HBCHeader;
struct HBCFunctionInfo;
struct HBCStringMeta;
struct HBCStringTables;

/* ============================================================================
   Factory Functions - Create a provider from different sources
   ============================================================================ */

/**
 * Create a data provider from a file on disk.
 * Internally opens the file and parses HBC structures.
 * Returns NULL on failure.
 */
HBCDataProvider *hbc_data_provider_from_file(const char *path);

/**
 * Create a data provider from a memory buffer.
 * Data must remain valid for the lifetime of the provider.
 * Returns NULL on failure.
 */
HBCDataProvider *hbc_data_provider_from_buffer(const u8 *data, size_t size);

/* Forward declarations for optional r2 integration */
struct RBinFile;  /* r2 binary file handle */

/**
 * Create a data provider from an r2 RBinFile.
 * Reads data via r2's RBuffer API (no separate file opens).
 * Returns NULL if bf is NULL or invalid.
 * AVAILABILITY: Only compiled if R2_INTEGRATION is enabled.
 */
HBCDataProvider *hbc_data_provider_from_rbinfile(struct RBinFile *bf);

/* ============================================================================
   Query Methods - Access parsed binary data
   ============================================================================ */

/**
 * Get the HBC file header.
 * Returns RESULT_SUCCESS if header was read successfully.
 */
Result hbc_data_provider_get_header(
    HBCDataProvider *provider,
    struct HBCHeader *out);

/* Use public typedefs for referenced types to avoid incompatible-pointer warnings */

/**
 * Get the total number of functions in the binary.
 * Returns RESULT_SUCCESS on success, RESULT_ERROR_INVALID_ARGUMENT if provider is NULL.
 */
Result hbc_data_provider_get_function_count(
    HBCDataProvider *provider,
    u32 *out_count);

/**
 * Get metadata for a specific function.
 * out->name is valid while provider is alive; caller must not free.
 */
Result hbc_data_provider_get_function_info(
    HBCDataProvider *provider,
    u32 function_id,
    struct HBCFunctionInfo *out);

/**
 * Get the total number of strings in the binary.
 */
Result hbc_data_provider_get_string_count(
    HBCDataProvider *provider,
    u32 *out_count);

/**
 * Get a string by index (const reference, valid while provider is alive).
 * out_str should not be freed by caller.
 */
Result hbc_data_provider_get_string(
    HBCDataProvider *provider,
    u32 string_id,
    const char **out_str);

/**
 * Get metadata for a string (offset, length, kind).
 */
Result hbc_data_provider_get_string_meta(
    HBCDataProvider *provider,
    u32 string_id,
    struct HBCStringMeta *out);

/**
 * Get the raw bytecode bytes for a function.
 * out_ptr and out_size should not be freed; valid while provider is alive.
 */
Result hbc_data_provider_get_bytecode(
    HBCDataProvider *provider,
    u32 function_id,
    const u8 **out_ptr,
    u32 *out_size);

/**
 * Get pre-parsed string table data (small_string_table, overflow_string_table, etc).
 * Used for efficient string ID resolution during instruction decoding.
 */
Result hbc_data_provider_get_string_tables(
    HBCDataProvider *provider,
    struct HBCStringTables *out);

/**
 * Get source/module name associated with a function (optional, may be NULL).
 * Used for contextual naming in decompilation output.
 */
Result hbc_data_provider_get_function_source(
    HBCDataProvider *provider,
    u32 function_id,
    const char **out_src);

/**
 * Low-level: Read raw bytes from the binary at a specific offset.
 * Used internally for parsing variable-length structures.
 * out_ptr is valid until next provider call; do not hold references.
 */
Result hbc_data_provider_read_raw(
    HBCDataProvider *provider,
    u64 offset,
    u32 size,
    const u8 **out_ptr);

/* ============================================================================
   Lifecycle
   ============================================================================ */

/**
 * Free a data provider and all associated resources.
 * After this call, all pointers returned by provider queries are invalid.
 */
void hbc_data_provider_free(HBCDataProvider *provider);

#endif /* HBC_DATA_PROVIDER_H */
