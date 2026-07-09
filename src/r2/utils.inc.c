/* radare2 - BSD - Copyright 2025-2026 - pancake */

#ifndef R2HERMES_UTILS_INC_C
#define R2HERMES_UTILS_INC_C

#include <r_util.h>

static inline Result hbc_open_from_buffer(RBuffer *buf, HBC **out_hbc) {
	if (!buf || !out_hbc) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments");
	}
	return hbc_open_from_rbuffer (buf, out_hbc);
}

static inline void hbc_safe_close(HBC **hbc) {
	if (hbc && *hbc) {
		hbc_close (*hbc);
		*hbc = NULL;
	}
}

#endif
