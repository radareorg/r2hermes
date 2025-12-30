#ifndef LIBHBC_COMMON_H
#define LIBHBC_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include "version.h"

#ifndef R2_VERSION
#define R_RETURN_VAL_IF_FAIL(x, y) if (! (x)) return y
#define R_LOG_WARN(x, ...) // (x)
#define R_LOG_DEBUG(x, ...) // (x)
#endif

/* Debug logging support - disable by default for clean output */
#ifndef HBC_DEBUG_LOGGING
#define HBC_DEBUG_LOGGING 0
#endif

/* Inline debug logging macro - compiles to nothing when disabled */
static inline void hbc_debug_printf(const char *fmt, ...) {
#if HBC_DEBUG_LOGGING
	va_list ap;
	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
#else
	(void)fmt; /* Suppress unused parameter warning */
#endif
}

/* Type definitions for consistent sizes */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

/* String buffer for dynamic strings */
typedef struct {
	char *data;
	size_t length;
	size_t capacity;
} StringBuffer;

/* Result code for error handling */
typedef enum {
	RESULT_SUCCESS,
	RESULT_ERROR_FILE_NOT_FOUND,
	RESULT_ERROR_INVALID_FORMAT,
	RESULT_ERROR_UNSUPPORTED_VERSION,
	RESULT_ERROR_MEMORY_ALLOCATION,
	RESULT_ERROR_PARSING_FAILED,
	RESULT_ERROR_INVALID_ARGUMENT,
	RESULT_ERROR_NOT_IMPLEMENTED,
	RESULT_ERROR_INVALID_DATA,
	RESULT_ERROR_NOT_FOUND,
	RESULT_ERROR_READ
} ResultCode;

/* Result structure for error reporting */
typedef struct {
	ResultCode code;
	const char *error_message;
} Result;

/* Buffer reader for file operations */
typedef struct {
	uint8_t *data;
	size_t size;
	size_t position;
} BufferReader;

/* Forward declarations */
struct HBCReader;
typedef struct HBCReader HBCReader;

/* StringBuffer functions */
Result _hbc_string_buffer_init(StringBuffer *buffer, size_t initial_capacity);
Result _hbc_string_buffer_append(StringBuffer *buffer, const char *str);
Result _hbc_string_buffer_append_char(StringBuffer *buffer, char c);
Result _hbc_string_buffer_append_int(StringBuffer *buffer, int value);
void _hbc_string_buffer_free(StringBuffer *buffer);

/* BufferReader functions */
Result _hbc_buffer_reader_init_from_file(BufferReader *reader, const char *filename);
Result _hbc_buffer_reader_init_from_memory(BufferReader *reader, const u8 *data, size_t size);
Result _hbc_buffer_reader_read_u8(BufferReader *reader, u8 *out_value);
Result _hbc_buffer_reader_read_u16(BufferReader *reader, u16 *out_value);
Result _hbc_buffer_reader_read_u32(BufferReader *reader, u32 *out_value);
Result _hbc_buffer_reader_read_u64(BufferReader *reader, u64 *out_value);
Result _hbc_buffer_reader_read_bytes(BufferReader *reader, u8 *out_buffer, size_t length);
Result _hbc_buffer_reader_seek(BufferReader *reader, size_t position);
Result _hbc_buffer_reader_align(BufferReader *reader, size_t alignment);
void _hbc_buffer_reader_free(BufferReader *reader);

/* String case conversion utilities */
void hbc_camel_to_snake(const char *camel, char *snake, size_t snake_size);
void hbc_snake_to_camel(const char *snake, char *camel, size_t camel_size);

/* Utility macros for error handling */
#define RETURN_IF_ERROR(expr) \
	do { \
		Result result = (expr); \
		if (result.code != RESULT_SUCCESS) { \
			return result; \
		} \
	} while (0)

#define SUCCESS_RESULT() ((Result){ RESULT_SUCCESS, "" })

#define ERROR_RESULT(code, message) ((Result){ code, message })

#endif /* LIBHBC_COMMON_H */
