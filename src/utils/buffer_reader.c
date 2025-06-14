#include "../../include/common.h"

Result buffer_reader_init_from_file(BufferReader* reader, const char* filename) {
    if (!reader || !filename) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader or filename is NULL");
    }
    
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return ERROR_RESULT(RESULT_ERROR_FILE_NOT_FOUND, "Failed to open file");
    }
    
    /* Get file size */
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(file);
        return ERROR_RESULT(RESULT_ERROR_INVALID_FORMAT, "Empty or invalid file");
    }
    
    /* Allocate buffer */
    reader->data = (u8*)malloc(file_size);
    if (!reader->data) {
        fclose(file);
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate buffer for file");
    }
    
    /* Read file contents */
    size_t bytes_read = fread(reader->data, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_size) {
        free(reader->data);
        reader->data = NULL;
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Failed to read entire file");
    }
    
    reader->size = file_size;
    reader->position = 0;
    
    return SUCCESS_RESULT();
}

Result buffer_reader_init_from_memory(BufferReader* reader, const u8* data, size_t size) {
    if (!reader || !data || size == 0) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for buffer_reader_init_from_memory");
    }
    
    /* Copy the data to ensure ownership */
    reader->data = (u8*)malloc(size);
    if (!reader->data) {
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate buffer");
    }
    
    memcpy(reader->data, data, size);
    reader->size = size;
    reader->position = 0;
    
    return SUCCESS_RESULT();
}

Result buffer_reader_read_u8(BufferReader* reader, u8* out_value) {
    if (!reader || !out_value) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for buffer_reader_read_u8");
    }
    
    /* Safety check - is the reader data valid? */
    if (!reader->data) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "BufferReader has no data");
    }
    
    /* Extra validation for position */
    if (reader->position >= reader->size) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer position at or beyond buffer size");
    }
    
    /* Now check if we can read a byte */
    if (reader->position + sizeof(u8) > reader->size) {
        /* Provide a default but warn */
        fprintf(stderr, "Warning: Buffer overflow prevented in read_u8 at position %zu of %zu bytes\n",
               reader->position, reader->size);
        *out_value = 0;
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer overflow in read_u8");
    }
    
    /* All good, proceed with read */
    *out_value = reader->data[reader->position];
    reader->position += sizeof(u8);
    
    return SUCCESS_RESULT();
}

Result buffer_reader_read_u16(BufferReader* reader, u16* out_value) {
    if (!reader || !out_value) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for buffer_reader_read_u16");
    }
    
    /* Safety check - is the reader data valid? */
    if (!reader->data) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "BufferReader has no data");
    }
    
    /* Extra validation for position */
    if (reader->position >= reader->size) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer position at or beyond buffer size");
    }
    
    /* Now check if we can read 2 bytes */
    if (reader->position + sizeof(u16) > reader->size) {
        /* Provide a default but warn */
        fprintf(stderr, "Warning: Buffer overflow prevented in read_u16 at position %zu of %zu bytes\n",
               reader->position, reader->size);
        *out_value = 0;
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer overflow in read_u16");
    }
    
    /* Read in little-endian format */
    *out_value = (u16)reader->data[reader->position] |
                ((u16)reader->data[reader->position + 1] << 8);
    reader->position += sizeof(u16);
    
    return SUCCESS_RESULT();
}

Result buffer_reader_read_u32(BufferReader* reader, u32* out_value) {
    if (!reader || !out_value) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for buffer_reader_read_u32");
    }
    
    /* Safety check - is the reader data valid? */
    if (!reader->data) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "BufferReader has no data");
    }
    
    /* Extra validation for position */
    if (reader->position >= reader->size) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer position at or beyond buffer size");
    }
    
    /* Now check if we can read 4 bytes */
    if (reader->position + sizeof(u32) > reader->size) {
        /* Provide a default but warn */
        fprintf(stderr, "Warning: Buffer overflow prevented in read_u32 at position %zu of %zu bytes\n",
               reader->position, reader->size);
        *out_value = 0;
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer overflow in read_u32");
    }
    
    /* Read in little-endian format */
    *out_value = (u32)reader->data[reader->position] |
                ((u32)reader->data[reader->position + 1] << 8) |
                ((u32)reader->data[reader->position + 2] << 16) |
                ((u32)reader->data[reader->position + 3] << 24);
    reader->position += sizeof(u32);
    
    return SUCCESS_RESULT();
}

Result buffer_reader_read_u64(BufferReader* reader, u64* out_value) {
    if (!reader || !out_value) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for buffer_reader_read_u64");
    }
    
    if (reader->position + sizeof(u64) > reader->size) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer overflow in read_u64");
    }
    
    /* Read in little-endian format */
    *out_value = (u64)reader->data[reader->position] |
                ((u64)reader->data[reader->position + 1] << 8) |
                ((u64)reader->data[reader->position + 2] << 16) |
                ((u64)reader->data[reader->position + 3] << 24) |
                ((u64)reader->data[reader->position + 4] << 32) |
                ((u64)reader->data[reader->position + 5] << 40) |
                ((u64)reader->data[reader->position + 6] << 48) |
                ((u64)reader->data[reader->position + 7] << 56);
    reader->position += sizeof(u64);
    
    return SUCCESS_RESULT();
}

Result buffer_reader_read_bytes(BufferReader* reader, u8* out_buffer, size_t length) {
    if (!reader || !out_buffer) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for buffer_reader_read_bytes");
    }
    
    if (reader->position + length > reader->size) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer overflow in read_bytes");
    }
    
    memcpy(out_buffer, reader->data + reader->position, length);
    reader->position += length;
    
    return SUCCESS_RESULT();
}

Result buffer_reader_seek(BufferReader* reader, size_t position) {
    if (!reader) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
    }
    
    /* Safety check - is the reader data valid? */
    if (!reader->data) {
        return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "BufferReader has no data");
    }
    
    /* Validate position */
    if (position > reader->size) {
        fprintf(stderr, "Warning: Attempted to seek beyond buffer bounds (pos: %zu, size: %zu)\n", 
                position, reader->size);
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Seek position beyond buffer size");
    }
    
    reader->position = position;
    return SUCCESS_RESULT();
}

Result buffer_reader_align(BufferReader* reader, size_t alignment) {
    if (!reader) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
    }
    
    if (alignment == 0) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Alignment must be non-zero");
    }
    
    size_t remainder = reader->position % alignment;
    if (remainder != 0) {
        size_t padding = alignment - remainder;
        if (reader->position + padding > reader->size) {
            return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer overflow in align");
        }
        reader->position += padding;
    }
    
    return SUCCESS_RESULT();
}

void buffer_reader_free(BufferReader* reader) {
    if (reader && reader->data) {
        free(reader->data);
        reader->data = NULL;
        reader->size = 0;
        reader->position = 0;
    }
}

