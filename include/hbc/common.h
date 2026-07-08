/* radare2 - BSD - Copyright 2025-2026 - pancake */

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
#include <r_util/r_strbuf.h>

#if defined(_WIN32) && defined(HBC_BUILD_SHARED)
#define HBC_API __declspec (dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define HBC_API __attribute__((visibility ("default")))
#else
#define HBC_API
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

#define SUCCESS_RESULT() ((Result){ RESULT_SUCCESS, "" })

#define ERROR_RESULT(code, message) ((Result){ code, message })

static inline Result hbc_result_from_result(Result result) {
	return result;
}

static inline Result hbc_result_from_bool(bool ok) {
	return ok? SUCCESS_RESULT (): ERROR_RESULT (RESULT_ERROR_MEMORY_ALLOCATION, "String buffer operation failed");
}

#define HBC_TO_RESULT(expr) _Generic ((expr), Result: hbc_result_from_result, bool: hbc_result_from_bool) (expr)

/* Utility macros for error handling */
#define RETURN_IF_ERROR(expr) \
	do { \
		Result result = HBC_TO_RESULT (expr); \
		if (result.code != RESULT_SUCCESS) { \
			return result; \
		} \
	} while (0)

#endif /* LIBHBC_COMMON_H */
