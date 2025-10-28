#ifndef HERMES_DEC_COMMON_H
#define HERMES_DEC_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Type definitions for consistent sizes */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define R_RETURN_VAL_IF_FAIL(x, y) \
	if (! (x)) \
	return y
#define R_LOG_WARN(x, ...) // (x)
#define R_LOG_DEBUG(x, ...) // (x)

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
	RESULT_ERROR_NOT_IMPLEMENTED
} ResultCode;

/* Result structure for error reporting */
typedef struct {
	ResultCode code;
	char error_message[256];
} Result;

/* Buffer reader for file operations */
typedef struct {
	u8 *data;
	size_t size;
	size_t position;
} BufferReader;

/* Forward declarations */
struct HBCReader;
typedef struct HBCReader HBCReader;

/* StringBuffer functions */
Result string_buffer_init(StringBuffer *buffer, size_t initial_capacity);
Result string_buffer_append(StringBuffer *buffer, const char *str);
Result string_buffer_append_char(StringBuffer *buffer, char c);
Result string_buffer_append_int(StringBuffer *buffer, int value);
void string_buffer_free(StringBuffer *buffer);

/* BufferReader functions */
Result buffer_reader_init_from_file(BufferReader *reader, const char *filename);
Result buffer_reader_init_from_memory(BufferReader *reader, const u8 *data, size_t size);
Result buffer_reader_read_u8(BufferReader *reader, u8 *out_value);
Result buffer_reader_read_u16(BufferReader *reader, u16 *out_value);
Result buffer_reader_read_u32(BufferReader *reader, u32 *out_value);
Result buffer_reader_read_u64(BufferReader *reader, u64 *out_value);
Result buffer_reader_read_bytes(BufferReader *reader, u8 *out_buffer, size_t length);
Result buffer_reader_seek(BufferReader *reader, size_t position);
Result buffer_reader_align(BufferReader *reader, size_t alignment);
void buffer_reader_free(BufferReader *reader);

/* Utility macros for error handling */
#define RETURN_IF_ERROR(expr) \
	do { \
		Result result = (expr); \
		if (result.code != RESULT_SUCCESS) \
			return result; \
	} while (0)

#define SUCCESS_RESULT() ((Result){ RESULT_SUCCESS, "" })

#define ERROR_RESULT(code, message) ((Result){ (code), (message) })

#endif /* HERMES_DEC_COMMON_H */
