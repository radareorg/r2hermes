#include <hbc/hbc.h>
#include <hbc/data_provider.h>
#include <stdlib.h>
#include <string.h>

/**
 * BufferDataProvider wraps a memory buffer containing HBC binary data.
 * Used for testing and embedded systems without file I/O.
 */
struct BufferDataProvider {
    HBCState *hbc;
};

HBCDataProvider *hbc_data_provider_from_buffer(const u8 *data, size_t size) {
    if (!data || size == 0) {
        return NULL;
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)malloc(sizeof(*bp));
    if (!bp) {
        return NULL;
    }

    /* Use existing hbc_open_from_memory API */
    Result res = hbc_open_from_memory(data, size, &bp->hbc);
    if (res.code != RESULT_SUCCESS) {
        free(bp);
        return NULL;
    }

    return (HBCDataProvider *)bp;
}

Result hbc_data_provider_get_header(
    HBCDataProvider *provider,
    struct HBCHeader *out) {
    
    if (!provider || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    return hbc_get_header(bp->hbc, out);
}

Result hbc_data_provider_get_function_count(
    HBCDataProvider *provider,
    u32 *out_count) {
    
    if (!provider || !out_count) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    *out_count = hbc_function_count(bp->hbc);
    return SUCCESS_RESULT();
}

Result hbc_data_provider_get_function_info(
    HBCDataProvider *provider,
    u32 function_id,
    HBCFunctionInfo *out) {
    
    if (!provider || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    return hbc_get_function_info(bp->hbc, function_id, out);
}

Result hbc_data_provider_get_string_count(
    HBCDataProvider *provider,
    u32 *out_count) {
    
    if (!provider || !out_count) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    *out_count = hbc_string_count(bp->hbc);
    return SUCCESS_RESULT();
}

Result hbc_data_provider_get_string(
    HBCDataProvider *provider,
    u32 string_id,
    const char **out_str) {
    
    if (!provider || !out_str) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    return hbc_get_string(bp->hbc, string_id, out_str);
}

Result hbc_data_provider_get_string_meta(
    HBCDataProvider *provider,
    u32 string_id,
    HBCStringMeta *out) {
    
    if (!provider || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    return hbc_get_string_meta(bp->hbc, string_id, out);
}

Result hbc_data_provider_get_bytecode(
    HBCDataProvider *provider,
    u32 function_id,
    const u8 **out_ptr,
    u32 *out_size) {
    
    if (!provider || !out_ptr || !out_size) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    return hbc_get_function_bytecode(bp->hbc, function_id, out_ptr, out_size);
}

Result hbc_data_provider_get_string_tables(
    HBCDataProvider *provider,
    HBCStringTables *out) {
    
    if (!provider || !out) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    return hbc_get_string_tables(bp->hbc, out);
}

Result hbc_data_provider_get_function_source(
    HBCDataProvider *provider,
    u32 function_id,
    const char **out_src) {
    
    if (!provider || !out_src) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    return hbc_get_function_source(bp->hbc, function_id, out_src);
}

Result hbc_data_provider_read_raw(
    HBCDataProvider *provider,
    u64 offset,
    u32 size,
    const u8 **out_ptr) {
    
    /* Buffer provider doesn't need raw read since HBCState handles it */
    (void)provider;
    (void)offset;
    (void)size;
    (void)out_ptr;
    
    return ERROR_RESULT(RESULT_ERROR_NOT_IMPLEMENTED, 
        "Raw read not available for buffer provider");
}

void hbc_data_provider_free(HBCDataProvider *provider) {
    if (!provider) {
        return;
    }

    struct BufferDataProvider *bp = (struct BufferDataProvider *)provider;
    if (bp->hbc) {
        hbc_close(bp->hbc);
        bp->hbc = NULL;
    }
    free(bp);
}
