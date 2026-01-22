/* radare2 - LGPL - Copyright 2025-2026 - pancake */

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
