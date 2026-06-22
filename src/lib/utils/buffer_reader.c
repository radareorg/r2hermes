/* radare2 - BSD - Copyright 2025-2026 - pancake */

#include <hbc/common.h>

Result _hbc_buffer_reader_init_from_file(BufferReader *reader, const char *filename) {
	if (!reader || !filename) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Reader or filename is NULL");
	}

	FILE *file = fopen (filename, "rb");
	if (!file) {
		return ERROR_RESULT (RESULT_ERROR_FILE_NOT_FOUND, "Failed to open file");
	}

	/* Get file size */
	fseek (file, 0, SEEK_END);
	long file_size = ftell (file);
	fseek (file, 0, SEEK_SET);

	if (file_size <= 0) {
		fclose (file);
		return ERROR_RESULT (RESULT_ERROR_INVALID_FORMAT, "Empty or invalid file");
	}

	/* Allocate buffer */
	reader->data = (u8 *)malloc (file_size);
	if (!reader->data) {
		fclose (file);
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate buffer for file");
	}

	/* Read file contents */
	size_t bytes_read = fread (reader->data, 1, file_size, file);
	fclose (file);

	if (bytes_read != (size_t)file_size) {
		free (reader->data);
		reader->data = NULL;
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Failed to read entire file");
	}

	reader->size = file_size;
	reader->position = 0;

	return SUCCESS_RESULT ();
}

Result _hbc_buffer_reader_init_from_memory(BufferReader *reader, const u8 *data, size_t size) {
	if (!reader || !data || size == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for _hbc_buffer_reader_init_from_memory");
	}

	/* Copy the data to ensure ownership */
	reader->data = (u8 *)malloc (size);
	if (!reader->data) {
		return ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate buffer");
	}

	memcpy (reader->data, data, size);
	reader->size = size;
	reader->position = 0;

	return SUCCESS_RESULT ();
}

/* Shared validity + bounds check for a read of `need` bytes at the cursor. */
static Result buffer_reader_check(const BufferReader *reader, size_t need) {
	if (!reader || !reader->data) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid buffer reader");
	}
	if (reader->position > reader->size || need > reader->size - reader->position) {
		hbc_debug_printf ("Warning: Buffer overflow prevented reading %zu bytes at position %zu of %zu\n",
			need,
			reader->position,
			reader->size);
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Buffer overflow");
	}
	return SUCCESS_RESULT ();
}

/* Read `n` (1..8) little-endian bytes at the cursor, advancing the position.
 * *out is zeroed on any failure. */
static Result buffer_reader_read_le(BufferReader *reader, size_t n, u64 *out) {
	*out = 0;
	RETURN_IF_ERROR (buffer_reader_check (reader, n));
	u64 v = 0;
	for (size_t i = 0; i < n; i++) {
		v |= (u64)reader->data[reader->position + i] << (8 * i);
	}
	reader->position += n;
	*out = v;
	return SUCCESS_RESULT ();
}

/* Define the fixed-width little-endian readers; all share buffer_reader_read_le. */
#define HBC_DEFINE_READ(bits) \
	Result _hbc_buffer_reader_read_u ## bits (BufferReader *reader, u ## bits *out_value) { \
		if (!out_value) { \
			return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "read out_value is NULL"); \
		} \
		u64 v; \
		Result r = buffer_reader_read_le (reader, sizeof (u ## bits), &v); \
		*out_value = (u ## bits)v; \
		return r; \
	}
HBC_DEFINE_READ(8)
HBC_DEFINE_READ(16)
HBC_DEFINE_READ(32)
HBC_DEFINE_READ(64)
#undef HBC_DEFINE_READ

Result _hbc_buffer_reader_read_bytes(BufferReader *reader, u8 *out_buffer, size_t length) {
	if (!out_buffer) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for _hbc_buffer_reader_read_bytes");
	}
	RETURN_IF_ERROR (buffer_reader_check (reader, length));
	memcpy (out_buffer, reader->data + reader->position, length);
	reader->position += length;
	return SUCCESS_RESULT ();
}

Result _hbc_buffer_reader_seek(BufferReader *reader, size_t position) {
	if (!reader) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Safety check - is the reader data valid? */
	if (!reader->data) {
		return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "BufferReader has no data");
	}

	/* Validate position */
	if (position > reader->size) {
		hbc_debug_printf ("Warning: Attempted to seek beyond buffer bounds (pos: %zu, size: %zu)\n",
			position,
			reader->size);
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Seek position beyond buffer size");
	}

	reader->position = position;
	return SUCCESS_RESULT ();
}

Result _hbc_buffer_reader_align(BufferReader *reader, size_t alignment) {
	if (!reader) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	if (alignment == 0) {
		return ERROR_RESULT (RESULT_ERROR_INVALID_ARGUMENT, "Alignment must be non-zero");
	}

	size_t remainder = reader->position % alignment;
	if (remainder != 0) {
		size_t padding = alignment - remainder;
		if (reader->position > reader->size || padding > reader->size - reader->position) {
			return ERROR_RESULT (RESULT_ERROR_PARSING_FAILED, "Buffer overflow in align");
		}
		reader->position += padding;
	}

	return SUCCESS_RESULT ();
}

void _hbc_buffer_reader_free(BufferReader *reader) {
	if (reader && reader->data) {
		free (reader->data);
		reader->data = NULL;
		reader->size = 0;
		reader->position = 0;
	}
}
