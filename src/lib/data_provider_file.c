#include <hbc/hbc.h>
#include <hbc/data_provider.h>
#include <stdlib.h>
#include <string.h>

/**
 * FileDataProvider wraps HBCState and HBCReader (current implementation).
 * This maintains backward compatibility while enabling other providers.
 */
struct FileDataProvider {
	HBCState *hbc;
};

HBCDataProvider *hbc_data_provider_from_file(const char *path) {
	if (!path) {
		return NULL;
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)malloc (sizeof (*fp));
	if (!fp) {
		return NULL;
	}

	Result res = hbc_open (path, &fp->hbc);
	if (res.code != RESULT_SUCCESS) {
		free (fp);
		return NULL;
	}

	return (HBCDataProvider *)fp;
}

Result hbc_data_provider_get_header(
	HBCDataProvider *provider,
	struct HBCHeader *out) {

	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	return hbc_get_header (fp->hbc, out);
}

Result hbc_data_provider_get_function_count(
	HBCDataProvider *provider,
	u32 *out_count) {

	if (!provider || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	*out_count = hbc_function_count (fp->hbc);
	return SUCCESS_RESULT ();
}

Result hbc_data_provider_get_function_info(
	HBCDataProvider *provider,
	u32 function_id,
	HBCFunctionInfo *out) {

	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	return hbc_get_function_info (fp->hbc, function_id, out);
}

Result hbc_data_provider_get_string_count(
	HBCDataProvider *provider,
	u32 *out_count) {

	if (!provider || !out_count) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	*out_count = hbc_string_count (fp->hbc);
	return SUCCESS_RESULT ();
}

Result hbc_data_provider_get_string(
	HBCDataProvider *provider,
	u32 string_id,
	const char **out_str) {

	if (!provider || !out_str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	return hbc_get_string (fp->hbc, string_id, out_str);
}

Result hbc_data_provider_get_string_meta(
	HBCDataProvider *provider,
	u32 string_id,
	HBCStringMeta *out) {

	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	return hbc_get_string_meta (fp->hbc, string_id, out);
}

Result hbc_data_provider_get_bytecode(
	HBCDataProvider *provider,
	u32 function_id,
	const u8 **out_ptr,
	u32 *out_size) {

	if (!provider || !out_ptr || !out_size) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	return hbc_get_function_bytecode (fp->hbc, function_id, out_ptr, out_size);
}

Result hbc_data_provider_get_string_tables(
	HBCDataProvider *provider,
	HBCStringTables *out) {

	if (!provider || !out) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	return hbc_get_string_tables (fp->hbc, out);
}

Result hbc_data_provider_get_function_source(
	HBCDataProvider *provider,
	u32 function_id,
	const char **out_src) {

	if (!provider || !out_src) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "NULL pointer");
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	return hbc_get_function_source (fp->hbc, function_id, out_src);
}

Result hbc_data_provider_read_raw(
	HBCDataProvider *provider,
	u64 offset,
	u32 size,
	const u8 **out_ptr) {

	/* File provider doesn't need this since HBCState handles it internally */
	(void)provider;
	(void)offset;
	(void)size;
	(void)out_ptr;

	return ERROR_RESULT (RESULT_ERROR_NOT_IMPLEMENTED,
		"Raw read not available for file provider");
}

void hbc_data_provider_free(HBCDataProvider *provider) {
	if (!provider) {
		return;
	}

	struct FileDataProvider *fp = (struct FileDataProvider *)provider;
	if (fp->hbc) {
		hbc_close (fp->hbc);
		fp->hbc = NULL;
	}
	free (fp);
}
