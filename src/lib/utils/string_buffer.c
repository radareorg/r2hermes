/* radare2 - BSD - Copyright 2025-2026 - pancake */

#include <hbc/common.h>

/* Grow the buffer (doubling) so it can hold at least required_capacity bytes. */
static Result sb_ensure(StringBuffer *buffer, size_t required_capacity) {
	if (required_capacity <= buffer->capacity) {
		return SUCCESS_RESULT ();
	}
	size_t new_capacity = buffer->capacity? buffer->capacity: 64;
	while (new_capacity < required_capacity) {
		size_t doubled = new_capacity * 2;
		if (doubled <= new_capacity) { /* overflow: just take what's needed */
			new_capacity = required_capacity;
			break;
		}
		new_capacity = doubled;
	}
	char *new_data = (char *)realloc (buffer->data, new_capacity);
	if (!new_data) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to resize string buffer");
	}
	buffer->data = new_data;
	buffer->capacity = new_capacity;
	return SUCCESS_RESULT ();
}

Result _hbc_sb_init(StringBuffer *buffer, size_t initial_capacity) {
	if (!buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer is NULL");
	}

	if (initial_capacity == 0) {
		initial_capacity = 64; /* Default initial capacity */
	}

	buffer->data = (char *)malloc (initial_capacity);
	if (!buffer->data) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate string buffer");
	}

	buffer->data[0] = '\0';
	buffer->length = 0;
	buffer->capacity = initial_capacity;

	return SUCCESS_RESULT ();
}

Result _hbc_sb_append(StringBuffer *buffer, const char *str) {
	if (!buffer || !str) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer or string is NULL");
	}

	size_t str_len = strlen (str);
	if (str_len == 0) {
		return SUCCESS_RESULT ();
	}

	/* Ensure enough capacity */
	RETURN_IF_ERROR (sb_ensure (buffer, buffer->length + str_len + 1));

	/* Append the string */
	memcpy (buffer->data + buffer->length, str, str_len);
	buffer->length += str_len;
	buffer->data[buffer->length] = '\0';

	return SUCCESS_RESULT ();
}

Result _hbc_sb_appendf(StringBuffer *buffer, const char *fmt, ...) {
	if (!buffer || !fmt) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer or format is NULL");
	}

	char stack[128];
	va_list ap, ap2;
	va_start (ap, fmt);
	va_copy (ap2, ap);
	int len = vsnprintf (stack, sizeof (stack), fmt, ap);
	va_end (ap);
	if (len < 0) {
		va_end (ap2);
		return ERROR_RESULT (RESULT_ERROR_INVALID_FORMAT, "Failed to format string buffer append");
	}
	if ((size_t)len < sizeof (stack)) {
		va_end (ap2);
		return _hbc_sb_append (buffer, stack);
	}

	char *heap = (char *)malloc ((size_t)len + 1);
	if (!heap) {
		va_end (ap2);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate formatted string");
	}
	vsnprintf (heap, (size_t)len + 1, fmt, ap2);
	va_end (ap2);
	Result result = _hbc_sb_append (buffer, heap);
	free (heap);
	return result;
}

Result _hbc_sb_append_char(StringBuffer *buffer, char c) {
	if (!buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer is NULL");
	}

	/* Ensure enough capacity (+1 for the char, +1 for null terminator) */
	RETURN_IF_ERROR (sb_ensure (buffer, buffer->length + 2));

	/* Append the character */
	buffer->data[buffer->length] = c;
	buffer->length++;
	buffer->data[buffer->length] = '\0';

	return SUCCESS_RESULT ();
}

Result _hbc_sb_append_int(StringBuffer *buffer, int value) {
	if (!buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Buffer is NULL");
	}

	return _hbc_sb_appendf (buffer, "%d", value);
}

void _hbc_sb_free(StringBuffer *buffer) {
	if (buffer && buffer->data) {
		free (buffer->data);
		buffer->data = NULL;
		buffer->length = 0;
		buffer->capacity = 0;
	}
}

/* Convert CamelCase to snake_case for instruction names */
void hbc_camel_to_snake(const char *camel, char *snake, size_t snake_size) {
	if (!camel || !snake || snake_size == 0) {
		return;
	}

	size_t j = 0;
	for (size_t i = 0; camel[i] && j < snake_size - 1; i++) {
		char c = camel[i];

		/* Insert underscore before uppercase letter (except at start) */
		if (i > 0 && c >= 'A' && c <= 'Z') {
			/* Don't insert underscore if previous char was also uppercase
			 * and next char is lowercase (e.g., "ID" in "GetByID") */
			if (! (camel[i - 1] >= 'A' && camel[i - 1] <= 'Z' &&
				camel[i + 1] >= 'a' && camel[i + 1] <= 'z')) {
				if (j < snake_size - 1) {
					snake[j++] = '_';
				}
			}
		}

		/* Convert to lowercase */
		if (j < snake_size - 1) {
			snake[j++] = (c >= 'A' && c <= 'Z')? (c + 32): c;
		}
	}
	snake[j] = '\0';
}

/* Convert snake_case to CamelCase */
void hbc_snake_to_camel(const char *snake, char *camel, size_t camel_size) {
	if (!snake || !camel || camel_size < 2) {
		if (camel && camel_size > 0) {
			camel[0] = '\0';
		}
		return;
	}
	size_t j = 0;
	bool cap_next = true;
	for (size_t i = 0; snake[i] && j + 1 < camel_size; i++) {
		if (snake[i] == '_') {
			cap_next = true;
		} else {
			char c = snake[i];
			if (cap_next && c >= 'a' && c <= 'z') {
				c = c - 32; /* to uppercase */
			}
			camel[j++] = c;
			cap_next = false;
		}
	}
	camel[j] = '\0';
}
