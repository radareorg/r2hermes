/* radare2 - LGPL - Copyright 2025-2026 - pancake */

#ifndef R2HERMES_UTILS_INC_C
#define R2HERMES_UTILS_INC_C

#include <r_util.h>

static inline Result hbc_open_from_buffer(RBuffer *buf, HBC **out_hbc) {
	if (!buf || !out_hbc) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	ut64 size = r_buf_size (buf);
	if (size == 0 || size > SIZE_MAX) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid buffer size");
	}
	ut8 *data = malloc (size);
	if (!data) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate buffer");
	}
	if ((ut64)r_buf_read_at (buf, 0, data, size) != size) {
		free (data);
		return ERROR_RESULT (RESULT_ERROR_READ, "Failed to read buffer");
	}
	Result res = hbc_open_from_memory (data, size, out_hbc);
	free (data);
	return res;
}

static inline void hbc_safe_close(HBC **hbc) {
	if (hbc && *hbc) {
		hbc_close (*hbc);
		*hbc = NULL;
	}
}

#endif
