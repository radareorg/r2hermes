/* radare2 - LGPL - Copyright 2025-2026 - pancake */

#ifndef R2HERMES_UTILS_INC_C
#define R2HERMES_UTILS_INC_C

#include <r_util.h>

static inline bool r_buf_read_alloc(RBuffer *buf, ut8 **data, ut64 *out_size) {
	ut64 size = r_buf_size (buf);
	if (size == 0 || size > SIZE_MAX) {
		return false;
	}

	ut8 *ptr = malloc (size);
	if (!ptr) {
		return false;
	}

	if ((ut64)r_buf_read_at (buf, 0, ptr, size) != size) {
		free (ptr);
		return false;
	}

	*data = ptr;
	if (out_size) {
		*out_size = size;
	}
	return true;
}

static inline Result hbc_open_from_buffer(RBuffer *buf, HBC **out_hbc, ut8 **out_data) {
	if (!buf || !out_hbc) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}

	ut64 size = r_buf_size (buf);
	if (size == 0 || size > SIZE_MAX) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid buffer size");
	}

	ut8 *data = NULL;
	if (!r_buf_read_alloc (buf, &data, NULL)) {
		return ERROR_RESULT (RESULT_ERROR_READ, "Failed to read buffer");
	}

	Result res = hbc_open_from_memory (data, size, out_hbc);
	if (res.code != RESULT_SUCCESS) {
		free (data);
		return res;
	}

	if (out_data) {
		*out_data = data;
	} else {
		free (data);
	}
	return SUCCESS_RESULT ();
}

static inline void hbc_safe_close(HBC **hbc) {
	if (hbc && *hbc) {
		hbc_close (*hbc);
		*hbc = NULL;
	}
}

static inline void hbc_free_data_and_close(HBC **hbc, ut8 **data) {
	if (data && *data) {
		R_FREE (*data);
	}
	hbc_safe_close (hbc);
}

#endif
