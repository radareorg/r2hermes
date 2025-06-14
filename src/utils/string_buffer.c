#include "../../include/common.h"

Result string_buffer_init(StringBuffer* buffer, size_t initial_capacity) {
    if (!buffer) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer is NULL");
    }
    
    if (initial_capacity == 0) {
        initial_capacity = 64; /* Default initial capacity */
    }
    
    buffer->data = (char*)malloc(initial_capacity);
    if (!buffer->data) {
        return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate string buffer");
    }
    
    buffer->data[0] = '\0';
    buffer->length = 0;
    buffer->capacity = initial_capacity;
    
    return SUCCESS_RESULT();
}

Result string_buffer_append(StringBuffer* buffer, const char* str) {
    if (!buffer || !str) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer or string is NULL");
    }
    
    size_t str_len = strlen(str);
    if (str_len == 0) {
        return SUCCESS_RESULT();
    }
    
    /* Ensure enough capacity */
    size_t required_capacity = buffer->length + str_len + 1;
    if (required_capacity > buffer->capacity) {
        size_t new_capacity = buffer->capacity * 2;
        while (new_capacity < required_capacity) {
            new_capacity *= 2;
        }
        
        char* new_data = (char*)realloc(buffer->data, new_capacity);
        if (!new_data) {
            return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to resize string buffer");
        }
        
        buffer->data = new_data;
        buffer->capacity = new_capacity;
    }
    
    /* Append the string */
    memcpy(buffer->data + buffer->length, str, str_len);
    buffer->length += str_len;
    buffer->data[buffer->length] = '\0';
    
    return SUCCESS_RESULT();
}

Result string_buffer_append_char(StringBuffer* buffer, char c) {
    if (!buffer) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer is NULL");
    }
    
    /* Ensure enough capacity */
    size_t required_capacity = buffer->length + 2; /* +1 for the char, +1 for null terminator */
    if (required_capacity > buffer->capacity) {
        size_t new_capacity = buffer->capacity * 2;
        
        char* new_data = (char*)realloc(buffer->data, new_capacity);
        if (!new_data) {
            return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to resize string buffer");
        }
        
        buffer->data = new_data;
        buffer->capacity = new_capacity;
    }
    
    /* Append the character */
    buffer->data[buffer->length] = c;
    buffer->length++;
    buffer->data[buffer->length] = '\0';
    
    return SUCCESS_RESULT();
}

Result string_buffer_append_int(StringBuffer* buffer, int value) {
    if (!buffer) {
        return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Buffer is NULL");
    }
    
    char temp[32]; /* Enough for any integer */
    snprintf(temp, sizeof(temp), "%d", value);
    
    return string_buffer_append(buffer, temp);
}

void string_buffer_free(StringBuffer* buffer) {
    if (buffer && buffer->data) {
        free(buffer->data);
        buffer->data = NULL;
        buffer->length = 0;
        buffer->capacity = 0;
    }
}

