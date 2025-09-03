#include "../../include/parsers/hbc_file_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Initialize HBC reader */
Result hbc_reader_init(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Zero out all fields */
	memset(reader, 0, sizeof(HBCReader));

	return SUCCESS_RESULT();
}

/* Clean up HBC reader */
Result hbc_reader_cleanup(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Clean up file buffer */
	buffer_reader_free(&reader->file_buffer);

	/* Clean up function data */
	if (reader->function_headers) {
		for (u32 i = 0; i < reader->header.functionCount; i++) {
			free(reader->function_headers[i].bytecode);
		}
		free(reader->function_headers);
	}

	if (reader->function_id_to_exc_handlers) {
		for (u32 i = 0; i < reader->header.functionCount; i++) {
			free(reader->function_id_to_exc_handlers[i].handlers);
		}
		free(reader->function_id_to_exc_handlers);
	}

	free(reader->function_id_to_debug_offsets);

	/* Clean up string data */
	free(reader->string_kinds);
	free(reader->identifier_hashes);
	free(reader->small_string_table);
	free(reader->overflow_string_table);

	if (reader->strings) {
		for (u32 i = 0; i < reader->header.stringCount; i++) {
			free(reader->strings[i]);
		}
		free(reader->strings);
	}

	/* Clean up array and object data */
	free(reader->arrays);
	free(reader->object_keys);
	free(reader->object_values);

	/* Clean up BigInt data */
	free(reader->bigint_values);

	/* Clean up RegExp data */
	free(reader->regexp_table);
	free(reader->regexp_storage);

	/* Clean up CJS module data */
	if (reader->header.version < 77) {
		free(reader->cjs_module_ids);
	} else {
		free(reader->cjs_modules);
	}

	/* Clean up function source data */
	free(reader->function_sources);

	/* Clean up debug info */
	free(reader->debug_string_table);
	free(reader->debug_string_storage);
	free(reader->debug_file_regions);
	free(reader->sources_data_storage);
	free(reader->scope_desc_data_storage);
	free(reader->textified_data_storage);
	free(reader->string_table_storage);

	/* Clean up bytecode module */
	/* Note: this will be implemented later when we define the bytecode modules */

	/* Reset all fields */
	memset(reader, 0, sizeof(HBCReader));

	return SUCCESS_RESULT();
}

/* Read file into buffer */
Result hbc_reader_read_file(HBCReader* reader, const char* filename) {
	if (!reader || !filename) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_reader_read_file");
	}
	
	Result result = buffer_reader_init_from_file(&reader->file_buffer, filename);
	if (result.code != RESULT_SUCCESS) {
		return result;
	}
	
	/* Quick validation that this looks like a Hermes bytecode file */
	if (reader->file_buffer.size < 40) { /* Minimum size for a valid header */
		return ERROR_RESULT(RESULT_ERROR_INVALID_FORMAT, "File too small to be a valid Hermes bytecode file");
	}
	
	/* Check for Hermes magic number */
	u64 magic;
	size_t saved_pos = reader->file_buffer.position;
	result = buffer_reader_read_u64(&reader->file_buffer, &magic);
	reader->file_buffer.position = saved_pos; /* Restore position */
	
	if (result.code != RESULT_SUCCESS) {
		return result;
	}
	
	if (magic != HEADER_MAGIC) {
		/* Check if this might be a bundle file that needs preprocessing */
		char signature[10] = {0};
		if (reader->file_buffer.size > 9) {
			memcpy(signature, reader->file_buffer.data, 9);
			signature[9] = '\0';
			
			if (strcmp(signature, "function(") == 0 || 
				(signature[0] == '{' && strchr(signature, ':') != NULL)) {
				return ERROR_RESULT(RESULT_ERROR_INVALID_FORMAT, 
					"This appears to be a JavaScript bundle file, not a compiled Hermes bytecode file. "
					"You may need to extract the bytecode from the bundle first.");
			}
		}
		
		fprintf(stderr, "Warning: File does not start with Hermes bytecode magic number (found 0x%016llx, expected 0x%016llx).\n",
			(unsigned long long)magic, (unsigned long long)HEADER_MAGIC);
		fprintf(stderr, "This file may not be a Hermes bytecode file or might be corrupted.\n");
	}
	
	return SUCCESS_RESULT();
}

/* Align the file buffer to a specific boundary */
static Result align_over_padding(BufferReader* reader, size_t padding_amount) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	if (padding_amount == 0) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Padding amount must be non-zero");
	}

	size_t current_pos = reader->position;
	size_t remainder = current_pos % padding_amount;

	if (remainder != 0) {
		size_t padding = padding_amount - remainder;
		if (current_pos + padding > reader->size) {
			return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Buffer overflow in align_over_padding");
		}
		reader->position += padding;
	}

	return SUCCESS_RESULT();
}

/* Read and validate the header */
Result hbc_reader_read_header(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Seek to the beginning of the file */
	RETURN_IF_ERROR(buffer_reader_seek(&reader->file_buffer, 0));

	/* Read the magic number */
	u64 magic;
	RETURN_IF_ERROR(buffer_reader_read_u64(&reader->file_buffer, &magic));

	if (magic != HEADER_MAGIC) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_FORMAT, "Invalid Hermes bytecode file (wrong magic number)");
	}

	reader->header.magic = magic;

	/* Read the version */
	u32 version;
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &version));
	reader->header.version = version;

	/* Check for supported version */
	if (version < 72) {
		return ERROR_RESULT(RESULT_ERROR_UNSUPPORTED_VERSION, 
				"Unsupported bytecode version (too old, minimum supported is 72)");
	}

	if (version > 96) {
		fprintf(stderr, "Warning: Version %u is newer than the latest supported version (96). Some features may not work correctly.\n", version);
	}

	/* Read the source hash */
	RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->header.sourceHash, SHA1_NUM_BYTES));

	/* Read the file length */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.fileLength));

	/* Sanity check on file length */
	if (reader->header.fileLength > reader->file_buffer.size) {
		fprintf(stderr, "Warning: Reported file length (%u) is larger than actual file size (%zu).\n",
			reader->header.fileLength, reader->file_buffer.size);
	}

	/* Read the global code index */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.globalCodeIndex));

	/* Read the function count */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.functionCount));
	
	/* Sanity check on function count */
	if (reader->header.functionCount > 1000000) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_FORMAT, 
			"Function count unreasonably large, likely not a valid Hermes bytecode file");
	}

	/* Read the string kind count */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.stringKindCount));

	/* Read the identifier count */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.identifierCount));

	/* Read the string count */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.stringCount));

	/* Read the overflow string count */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.overflowStringCount));

	/* Read the string storage size */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.stringStorageSize));

	/* Read BigInt fields if present (version >= 87) */
	if (version >= 87) {
		RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.bigIntCount));
		RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.bigIntStorageSize));
	} else {
		reader->header.bigIntCount = 0;
		reader->header.bigIntStorageSize = 0;
	}

	/* Read the RegExp count */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.regExpCount));

	/* Read the RegExp storage size */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.regExpStorageSize));

	/* Read the array buffer size */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.arrayBufferSize));

	/* Read the object key buffer size */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.objKeyBufferSize));

	/* Read the object value buffer size */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.objValueBufferSize));

	/* Read the segment ID (or CJS module offset for older versions) */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.segmentID));

	/* Read the CJS module count */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.cjsModuleCount));

	/* Read the function source count if present (version >= 84) */
	if (version >= 84) {
		RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.functionSourceCount));
	} else {
		reader->header.functionSourceCount = 0;
	}

	/* Read the debug info offset */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->header.debugInfoOffset));

	/* Read the option flags */
	u8 flags;
	RETURN_IF_ERROR(buffer_reader_read_u8(&reader->file_buffer, &flags));

	reader->header.staticBuiltins = (flags & 0x01) != 0;
	reader->header.cjsModulesStaticallyResolved = (flags & 0x02) != 0;
	reader->header.hasAsync = (flags & 0x04) != 0;

	/* Skip padding bytes */
	RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 32));

	return SUCCESS_RESULT();
}

/* Read function headers */
Result hbc_reader_read_functions(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Check if the function count is reasonable to prevent memory exhaustion */
	if (reader->header.functionCount > MAX_FUNCTIONS) {
		fprintf(stderr, "Warning: Large number of functions detected (%u). This may require significant memory.\n", 
				reader->header.functionCount);
	}

	/* Add detailed debugging about file position */
	fprintf(stderr, "Reading functions at position %zu of %zu bytes.\n", 
		reader->file_buffer.position, reader->file_buffer.size);

	/* Validate if we have enough data to read function headers */
	size_t min_bytes_needed = 16 * reader->header.functionCount; /* Each function header is at least 16 bytes */
	if (reader->file_buffer.position + min_bytes_needed > reader->file_buffer.size) {
		fprintf(stderr, "Warning: File might be truncated. Need ~%zu more bytes for function headers.\n", 
			min_bytes_needed);
		/* Continue anyway to handle whatever data is available */
	}
	
	/* Check for a special case - if we can't even read the first function header */
	if (reader->file_buffer.position + 16 > reader->file_buffer.size) {
		return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, 
			"File too small to contain even a single function header");
	}

	/* Align buffer */
	RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

	/* Calculate memory requirements */
	size_t function_headers_size = reader->header.functionCount * sizeof(FunctionHeader);
	size_t exc_handlers_size = reader->header.functionCount * sizeof(ExceptionHandlerList);
	size_t debug_offsets_size = reader->header.functionCount * sizeof(DebugOffsets);
	
	/* Warn if memory allocation might be very large */
	size_t total_memory = function_headers_size + exc_handlers_size + debug_offsets_size;
	if (total_memory > 1024 * 1024 * 1024) { /* > 1GB */
		fprintf(stderr, "Warning: Attempting to allocate %.2f GB for function data.\n", 
			(double)total_memory / (1024 * 1024 * 1024));
	}
	
	/* Allocate function headers */
	reader->function_headers = (FunctionHeader*)calloc(reader->header.functionCount, sizeof(FunctionHeader));
	if (!reader->function_headers) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function headers");
	}

	/* Allocate exception handler lists */
	reader->function_id_to_exc_handlers = (ExceptionHandlerList*)calloc(reader->header.functionCount, sizeof(ExceptionHandlerList));
	if (!reader->function_id_to_exc_handlers) {
		free(reader->function_headers);
		reader->function_headers = NULL;
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate exception handler lists");
	}

	/* Allocate debug offsets */
	reader->function_id_to_debug_offsets = (DebugOffsets*)calloc(reader->header.functionCount, sizeof(DebugOffsets));
	if (!reader->function_id_to_debug_offsets) {
		free(reader->function_headers);
		free(reader->function_id_to_exc_handlers);
		reader->function_headers = NULL;
		reader->function_id_to_exc_handlers = NULL;
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate debug offsets");
	}

	/* Read each function header */
	/* Track initial position */
	fprintf(stderr, "Function section start position: %zu\n", reader->file_buffer.position);
	
	/* Set a reasonable safety limit on function count for memory protection */
	u32 max_functions_to_read = reader->header.functionCount;
	const u32 ABSOLUTE_MAX_FUNCTIONS = 50000; /* Absolute safety limit */
	
	if (max_functions_to_read > ABSOLUTE_MAX_FUNCTIONS) {
		fprintf(stderr, "Warning: Function count extremely high (%u), limiting to %u for safety\n", 
			reader->header.functionCount, ABSOLUTE_MAX_FUNCTIONS);
		max_functions_to_read = ABSOLUTE_MAX_FUNCTIONS;
	}
	
	/* Detect file format issues early */
	if (reader->file_buffer.position + 16 > reader->file_buffer.size) {
		return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "Not enough data to read function headers");
	}
	
	/* Validate expected function section size - make sure there's enough data */
	const size_t BYTES_PER_FUNCTION_HEADER = 16;
	if (reader->file_buffer.position + (max_functions_to_read * BYTES_PER_FUNCTION_HEADER) > reader->file_buffer.size) {
		fprintf(stderr, "Warning: File appears too small for %u functions, may only read partial data\n", 
			max_functions_to_read);
	}
	
	for (u32 i = 0; i < max_functions_to_read; i++) {
		/* Ensure we have enough buffer for this function header */
		if (reader->file_buffer.position + 16 > reader->file_buffer.size) {
			fprintf(stderr, "Warning: Reached end of file after reading %u of %u functions\n", 
				i, reader->header.functionCount);
			
			/* Adjust the actual function count to what we were able to read */
			reader->header.functionCount = i;
			break;
		}
		
		/* Read small function header */
		SmallFunctionHeader small_header;
		u32 raw_data[4];  /* 4 words for the small function header */

		/* Read the raw data with explicit error handling */
		bool read_error = false;
        for (int j = 0; j < 4; j++) {
            Result res = buffer_reader_read_u32(&reader->file_buffer, &raw_data[j]);
            if (res.code != RESULT_SUCCESS) {
				fprintf(stderr, "Error reading function %u header word %d: %s\n", 
					i, j, res.error_message);
				read_error = true;
				break;
			}
		}
		
		/* Handle read errors */
		if (read_error) {
			fprintf(stderr, "Warning: Error while reading function headers, truncating to %u functions\n", i);
			reader->header.functionCount = i;
			break;
		}

		/* Extract fields from the bit patterns */
		small_header.offset = raw_data[0] & 0x1FFFFFF;  /* 25 bits */
		small_header.paramCount = (raw_data[0] >> 25) & 0x7F;  /* 7 bits */

		small_header.bytecodeSizeInBytes = raw_data[1] & 0x7FFF;  /* 15 bits */
		small_header.functionName = (raw_data[1] >> 15) & 0x1FFFF;  /* 17 bits */

		small_header.infoOffset = raw_data[2] & 0x1FFFFFF;  /* 25 bits */
		small_header.frameSize = (raw_data[2] >> 25) & 0x7F;  /* 7 bits */

		small_header.environmentSize = (u8)(raw_data[3] & 0xFF);
		small_header.highestReadCacheIndex = (u8)((raw_data[3] >> 8) & 0xFF);
		small_header.highestWriteCacheIndex = (u8)((raw_data[3] >> 16) & 0xFF);

		small_header.prohibitInvoke = (raw_data[3] >> 24) & 0x3;
		small_header.strictMode = (raw_data[3] >> 26) & 0x1;
		small_header.hasExceptionHandler = (raw_data[3] >> 27) & 0x1;
		small_header.hasDebugInfo = (raw_data[3] >> 28) & 0x1;
		small_header.overflowed = (raw_data[3] >> 29) & 0x1;
		small_header.unused = (raw_data[3] >> 30) & 0x3;

		/* Store the function header */
		FunctionHeader* header = &reader->function_headers[i];
		header->offset = small_header.offset;
		header->paramCount = small_header.paramCount;
		header->bytecodeSizeInBytes = small_header.bytecodeSizeInBytes;
		header->functionName = small_header.functionName;
		header->infoOffset = small_header.infoOffset;
		header->frameSize = small_header.frameSize;
		header->environmentSize = small_header.environmentSize;
		header->highestReadCacheIndex = small_header.highestReadCacheIndex;
		header->highestWriteCacheIndex = small_header.highestWriteCacheIndex;
		header->prohibitInvoke = small_header.prohibitInvoke;
		header->strictMode = small_header.strictMode;
		header->hasExceptionHandler = small_header.hasExceptionHandler;
		header->hasDebugInfo = small_header.hasDebugInfo;
		header->overflowed = small_header.overflowed;
		header->unused = small_header.unused;

		/* Save current position */
		size_t current_pos = reader->file_buffer.position;

		/* Handle overflowed header */
		if (small_header.overflowed) {
			/* Calculate the absolute offset of the large header */
			u32 large_header_offset = (small_header.infoOffset << 16) | small_header.offset;

			/* Seek to the large header */
			RETURN_IF_ERROR(buffer_reader_seek(&reader->file_buffer, large_header_offset));

			/* Read large function header */
			LargeFunctionHeader large_header;

			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &large_header.offset));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &large_header.paramCount));

			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &large_header.bytecodeSizeInBytes));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &large_header.functionName));

			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &large_header.infoOffset));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &large_header.frameSize));

			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &large_header.environmentSize));
			RETURN_IF_ERROR(buffer_reader_read_u8(&reader->file_buffer, &large_header.highestReadCacheIndex));
			RETURN_IF_ERROR(buffer_reader_read_u8(&reader->file_buffer, &large_header.highestWriteCacheIndex));

			/* Read flags byte */
			u8 flags;
			RETURN_IF_ERROR(buffer_reader_read_u8(&reader->file_buffer, &flags));

			large_header.prohibitInvoke = flags & 0x3;
			large_header.strictMode = (flags >> 2) & 0x1;
			large_header.hasExceptionHandler = (flags >> 3) & 0x1;
			large_header.hasDebugInfo = (flags >> 4) & 0x1;
			large_header.overflowed = (flags >> 5) & 0x1;
			large_header.unused = (flags >> 6) & 0x3;

			/* Copy to the combined header */
			header->offset = large_header.offset;
			header->paramCount = large_header.paramCount;
			header->bytecodeSizeInBytes = large_header.bytecodeSizeInBytes;
			header->functionName = large_header.functionName;
			header->infoOffset = large_header.infoOffset;
			header->frameSize = large_header.frameSize;
			header->environmentSize = (u8)large_header.environmentSize; /* Cast from u32 to u8 */
			header->highestReadCacheIndex = large_header.highestReadCacheIndex;
			header->highestWriteCacheIndex = large_header.highestWriteCacheIndex;
			header->prohibitInvoke = large_header.prohibitInvoke;
			header->strictMode = large_header.strictMode;
			header->hasExceptionHandler = large_header.hasExceptionHandler;
			header->hasDebugInfo = large_header.hasDebugInfo;
			header->overflowed = large_header.overflowed;
			header->unused = large_header.unused;
		}

		/* Read the function bytecode */
		u8* bytecode = (u8*)malloc(header->bytecodeSizeInBytes);
		if (!bytecode) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate bytecode buffer");
		}

		/* Save the current position */
		// size_t saved_pos = reader->file_buffer.position;

		/* Seek to the function bytecode */
		RETURN_IF_ERROR(buffer_reader_seek(&reader->file_buffer, header->offset));

		/* Read the bytecode */
		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, bytecode, header->bytecodeSizeInBytes));

		/* Store the bytecode pointer */
		header->bytecode = bytecode;

		/* Read exception handlers if present */
		if (header->hasExceptionHandler) {
			/* Seek to the exception handler info */
			RETURN_IF_ERROR(buffer_reader_seek(&reader->file_buffer, header->infoOffset));

			/* Align buffer */
			RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

			/* Read the number of exception handlers */
			u32 exc_handler_count;
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &exc_handler_count));

			/* Allocate exception handlers */
			ExceptionHandlerInfo* handlers = (ExceptionHandlerInfo*)malloc(exc_handler_count * sizeof(ExceptionHandlerInfo));
			if (!handlers) {
				return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate exception handlers");
			}

			/* Read each exception handler */
			for (u32 j = 0; j < exc_handler_count; j++) {
				RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &handlers[j].start));
				RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &handlers[j].end));
				RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &handlers[j].target));
			}

			/* Store the exception handlers */
			reader->function_id_to_exc_handlers[i].handlers = handlers;
			reader->function_id_to_exc_handlers[i].count = exc_handler_count;
		}

		/* Read debug information if present */
		if (header->hasDebugInfo) {
			/* Align buffer */
			RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

			/* Read debug offsets */
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->function_id_to_debug_offsets[i].source_locations));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->function_id_to_debug_offsets[i].scope_desc_data));

			/* Read textified callees if present (version >= 91) */
			if (reader->header.version >= 91) {
				RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->function_id_to_debug_offsets[i].textified_callees));
			}
		}

		/* Restore position for next function header */
		RETURN_IF_ERROR(buffer_reader_seek(&reader->file_buffer, current_pos));
	}

	return SUCCESS_RESULT();
}

/* Read string kinds */
Result hbc_reader_read_string_kinds(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Align buffer */
	RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

	/* Allocate string kinds */
	reader->string_kinds = (StringKind*)malloc(reader->header.stringCount * sizeof(StringKind));
	if (!reader->string_kinds) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate string kinds");
	}

	/* Initialize all string kinds to STRING_KIND_STRING */
	for (u32 i = 0; i < reader->header.stringCount; i++) {
		reader->string_kinds[i] = STRING_KIND_STRING;
	}

	/* Read string kind entries (run-length encoded) */
	u32 string_index = 0;
	for (u32 i = 0; i < reader->header.stringKindCount; i++) {
		u32 entry;
		RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &entry));

		u32 count, kind;

		/* Parse the entry based on version */
		if (reader->header.version >= 71) {
			count = entry & 0x7FFFFFFF;  /* 31 bits */
			kind = (entry >> 31) & 0x1;  /* 1 bit */
		} else {
			count = entry & 0x3FFFFFFF;  /* 30 bits */
			kind = (entry >> 30) & 0x3;  /* 2 bits */
		}

		/* Apply the string kind to the range */
		for (u32 j = 0; j < count && string_index < reader->header.stringCount; j++, string_index++) {
			reader->string_kinds[string_index] = (StringKind)kind;
		}
	}

	return SUCCESS_RESULT();
}

/* Read identifier hashes */
Result hbc_reader_read_identifier_hashes(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}
	
	fprintf(stderr, "Reading identifier hashes at position %zu\n", reader->file_buffer.position);
	
	/* Sanity check on identifier count */
	if (reader->header.identifierCount > 1000000) { /* 1M limit */
		fprintf(stderr, "Warning: Very large identifier count (%u), may be corrupted\n", 
			reader->header.identifierCount);
		/* We'll still attempt to read, but we'll be cautious */
	}
	
	/* Check if we have enough data in the buffer */
	size_t bytes_needed = reader->header.identifierCount * sizeof(u32);
	if (reader->file_buffer.position + bytes_needed > reader->file_buffer.size) {
		fprintf(stderr, "Warning: File too small for %u identifiers, truncating\n", 
			reader->header.identifierCount);
		/* Adjust the identifier count to what we can safely read */
		u32 max_identifiers = (reader->file_buffer.size - reader->file_buffer.position) / sizeof(u32);
		reader->header.identifierCount = max_identifiers;
	}
	
	/* If we have no identifiers to read, return success */
	if (reader->header.identifierCount == 0) {
		fprintf(stderr, "No identifier hashes to read\n");
		reader->identifier_hashes = NULL;
		return SUCCESS_RESULT();
	}

	/* Align buffer */
	Result result = align_over_padding(&reader->file_buffer, 4);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error aligning buffer for identifier hashes: %s\n", result.error_message);
		return result;
	}

	/* Allocate identifier hashes */
	reader->identifier_hashes = (u32*)malloc(reader->header.identifierCount * sizeof(u32));
	if (!reader->identifier_hashes) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate identifier hashes");
	}

	/* Read each identifier hash with explicit error handling */
	u32 successful_reads = 0;
	for (u32 i = 0; i < reader->header.identifierCount; i++) {
		/* Check if we have enough buffer */
		if (reader->file_buffer.position + sizeof(u32) > reader->file_buffer.size) {
			fprintf(stderr, "Reached end of file after reading %u of %u identifier hashes\n", 
				i, reader->header.identifierCount);
			/* Adjust count to what we read */
			reader->header.identifierCount = i;
			break;
		}
		
		Result read_result = buffer_reader_read_u32(&reader->file_buffer, &reader->identifier_hashes[i]);
		if (read_result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error reading identifier hash %u: %s\n", i, read_result.error_message);
			reader->header.identifierCount = i;
			break;
		}
		
		successful_reads++;
	}
	
	fprintf(stderr, "Successfully read %u identifier hashes\n", successful_reads);
	return SUCCESS_RESULT();
}

/* Read string tables and string data */
Result hbc_reader_read_string_tables(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}
	
	fprintf(stderr, "Reading string tables at position %zu\n", reader->file_buffer.position);

	/* Check if the string count is reasonable */
	if (reader->header.stringCount > MAX_STRINGS) {
		fprintf(stderr, "Warning: Large number of strings detected (%u). This may require significant memory.\n", 
				reader->header.stringCount);
	}
	
	/* Check if we have enough data in the buffer */
	size_t min_bytes_needed = reader->header.stringCount * sizeof(StringTableEntry);
	if (reader->file_buffer.position + min_bytes_needed > reader->file_buffer.size) {
		fprintf(stderr, "Warning: File too small for %u strings, truncating\n", 
			reader->header.stringCount);
		/* Adjust the string count to what we can safely read */
		u32 max_strings = (reader->file_buffer.size - reader->file_buffer.position) / sizeof(StringTableEntry);
		max_strings = (max_strings < MAX_STRINGS) ? max_strings : MAX_STRINGS;
		reader->header.stringCount = max_strings;
	}
	
	/* Handle case with no strings */
	if (reader->header.stringCount == 0) {
		fprintf(stderr, "No strings to read\n");
		reader->strings = NULL;
		reader->small_string_table = NULL;
		return SUCCESS_RESULT();
	}

	/* Align buffer for small string table */
	Result result = align_over_padding(&reader->file_buffer, 4);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error aligning buffer for string tables: %s\n", result.error_message);
		return result;
	}

	/* Allocate small string table */
	reader->small_string_table = (StringTableEntry*)calloc(reader->header.stringCount, sizeof(StringTableEntry));
	if (!reader->small_string_table) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate small string table");
	}

	/* Read each small string table entry */
	for (u32 i = 0; i < reader->header.stringCount; i++) {
		u32 entry;
		RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &entry));

		/* Parse the entry based on version */
		if (reader->header.version >= 56) {
			reader->small_string_table[i].isUTF16 = entry & 0x1;
			reader->small_string_table[i].offset = (entry >> 1) & 0x7FFFFF;  /* 23 bits */
			reader->small_string_table[i].length = (entry >> 24) & 0xFF;  /* 8 bits */
		} else {
			reader->small_string_table[i].isUTF16 = entry & 0x1;
			reader->small_string_table[i].isIdentifier = (entry >> 1) & 0x1;
			reader->small_string_table[i].offset = (entry >> 2) & 0x3FFFFF;  /* 22 bits */
			reader->small_string_table[i].length = (entry >> 24) & 0xFF;  /* 8 bits */
		}
	}

	/* Align buffer for overflow string table */
	RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

	/* Allocate overflow string table if needed */
	if (reader->header.overflowStringCount > 0) {
		reader->overflow_string_table = (OffsetLengthPair*)malloc(
				reader->header.overflowStringCount * sizeof(OffsetLengthPair));
		if (!reader->overflow_string_table) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate overflow string table");
		}

		uint32_t i;
		/* Read each overflow string table entry */
		for (i = 0; i < reader->header.overflowStringCount; i++) {
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->overflow_string_table[i].offset));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->overflow_string_table[i].length));
		}
	}

	/* Align buffer for string storage */
	RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

	/* Read the string storage */
	u8* string_storage = (u8*)malloc(reader->header.stringStorageSize);
	if (!string_storage) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate string storage");
	}

	RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, string_storage, reader->header.stringStorageSize));

	/* Allocate string array */
	reader->strings = (char**)calloc(reader->header.stringCount, sizeof(char*));
	if (!reader->strings) {
		free(string_storage);
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate string array");
	}

	/* Decode each string */
	for (u32 i = 0; i < reader->header.stringCount; i++) {
		u32 offset, length;
		bool is_utf16;

		/* Get string info */
		if (reader->small_string_table[i].length == 0xFF) {
			/* This is an overflow string */
			u32 overflow_index = reader->small_string_table[i].offset;
			offset = reader->overflow_string_table[overflow_index].offset;
			length = reader->overflow_string_table[overflow_index].length;
			is_utf16 = reader->small_string_table[i].isUTF16;
		} else {
			/* This is a small string */
			offset = reader->small_string_table[i].offset;
			length = reader->small_string_table[i].length;
			is_utf16 = reader->small_string_table[i].isUTF16;
		}

		/* Check bounds */
		if (offset + (is_utf16 ? length*2 : length) > reader->header.stringStorageSize) {
			free(string_storage);
			return ERROR_RESULT(RESULT_ERROR_PARSING_FAILED, "String offset/length out of bounds");
		}

		/* Allocate string buffer */
		char* str = (char*)malloc(length + 1);
		if (!str) {
			free(string_storage);
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate string");
		}

		/* Copy string data */
		if (is_utf16) {
			/* UTF-16 string */
			/* Note: This is a simplified version that doesn't handle surrogate pairs */
			for (u32 j = 0; j < length; j++) {
				u16 c = (string_storage[offset + j*2] | (string_storage[offset + j*2 + 1] << 8));
				if (c < 128) {
					str[j] = (char)c;
				} else {
					str[j] = '?';  /* Replace non-ASCII with ? */
				}
			}
			str[length] = '\0';
		} else {
			/* ASCII string */
			memcpy(str, string_storage + offset, length);
			str[length] = '\0';
		}

		/* Store the string */
		reader->strings[i] = str;
	}

	/* Free the temporary string storage */
	free(string_storage);

	return SUCCESS_RESULT();
}

/* Read arrays data */
Result hbc_reader_read_arrays(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}
	
	fprintf(stderr, "Reading arrays at position %zu\n", reader->file_buffer.position);

	/* Sanity check on array buffer size */
	if (reader->header.arrayBufferSize > 100 * 1024 * 1024) { /* 100MB limit */
		fprintf(stderr, "Warning: Very large array buffer size (%u bytes), might be corrupted\n", 
			reader->header.arrayBufferSize);
		reader->header.arrayBufferSize = 0; /* Skip reading for safety */
		return SUCCESS_RESULT();
	}

	/* Align buffer for array buffer */
	Result result = align_over_padding(&reader->file_buffer, 4);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error aligning buffer for arrays: %s\n", result.error_message);
		reader->header.arrayBufferSize = 0;
		return SUCCESS_RESULT(); /* Continue with other sections */
	}

	/* Check if we have enough data for arrays */
	if (reader->file_buffer.position + reader->header.arrayBufferSize > reader->file_buffer.size) {
		fprintf(stderr, "Warning: Not enough data for array buffer (need %u bytes, have %zu)\n",
			reader->header.arrayBufferSize, reader->file_buffer.size - reader->file_buffer.position);
		reader->header.arrayBufferSize = reader->file_buffer.size - reader->file_buffer.position;
		
		/* If there's nothing to read, return */
		if (reader->header.arrayBufferSize <= 0) {
			reader->header.arrayBufferSize = 0;
			reader->arrays = NULL;
			return SUCCESS_RESULT();
		}
	}

	/* Read array buffer */
	if (reader->header.arrayBufferSize > 0) {
		reader->arrays = (u8*)malloc(reader->header.arrayBufferSize);
		if (!reader->arrays) {
			fprintf(stderr, "Failed to allocate %u bytes for array buffer\n", reader->header.arrayBufferSize);
			reader->header.arrayBufferSize = 0;
			return SUCCESS_RESULT(); /* Continue with other sections */
		}

		result = buffer_reader_read_bytes(&reader->file_buffer, reader->arrays, reader->header.arrayBufferSize);
		if (result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error reading array buffer: %s\n", result.error_message);
			free(reader->arrays);
			reader->arrays = NULL;
			reader->header.arrayBufferSize = 0;
			return SUCCESS_RESULT(); /* Continue with other sections */
		}
		
		fprintf(stderr, "Successfully read %u bytes of array data\n", reader->header.arrayBufferSize);
	}

	/* Handle object key buffer with safety checks */
	if (reader->header.objKeyBufferSize > 0) {
		/* Align buffer for object key buffer */
		Result key_align_result = align_over_padding(&reader->file_buffer, 4);
		if (key_align_result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error aligning buffer for object keys: %s\n", key_align_result.error_message);
			reader->header.objKeyBufferSize = 0;
		} else if (reader->file_buffer.position + reader->header.objKeyBufferSize > reader->file_buffer.size) {
			fprintf(stderr, "Warning: Not enough data for object key buffer (need %u bytes)\n",
				reader->header.objKeyBufferSize);
			reader->header.objKeyBufferSize = 0;
		} else {
			/* Safe to read object keys */
			reader->object_keys = (u8*)malloc(reader->header.objKeyBufferSize);
			if (!reader->object_keys) {
				fprintf(stderr, "Failed to allocate %u bytes for object key buffer\n", reader->header.objKeyBufferSize);
				reader->header.objKeyBufferSize = 0;
			} else {
				Result read_result = buffer_reader_read_bytes(
					&reader->file_buffer, reader->object_keys, reader->header.objKeyBufferSize);
				if (read_result.code != RESULT_SUCCESS) {
					fprintf(stderr, "Error reading object key buffer: %s\n", read_result.error_message);
					free(reader->object_keys);
					reader->object_keys = NULL;
					reader->header.objKeyBufferSize = 0;
				} else {
					fprintf(stderr, "Successfully read %u bytes of object keys\n", reader->header.objKeyBufferSize);
				}
			}
		}
	}

	/* Handle object value buffer with safety checks */
	if (reader->header.objValueBufferSize > 0) {
		/* Align buffer for object value buffer */
		Result val_align_result = align_over_padding(&reader->file_buffer, 4);
		if (val_align_result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error aligning buffer for object values: %s\n", val_align_result.error_message);
			reader->header.objValueBufferSize = 0;
		} else if (reader->file_buffer.position + reader->header.objValueBufferSize > reader->file_buffer.size) {
			fprintf(stderr, "Warning: Not enough data for object value buffer (need %u bytes)\n",
				reader->header.objValueBufferSize);
			reader->header.objValueBufferSize = 0;
		} else {
			/* Safe to read object values */
			reader->object_values = (u8*)malloc(reader->header.objValueBufferSize);
			if (!reader->object_values) {
				fprintf(stderr, "Failed to allocate %u bytes for object value buffer\n", reader->header.objValueBufferSize);
				reader->header.objValueBufferSize = 0;
			} else {
				Result read_result = buffer_reader_read_bytes(
					&reader->file_buffer, reader->object_values, reader->header.objValueBufferSize);
				if (read_result.code != RESULT_SUCCESS) {
					fprintf(stderr, "Error reading object value buffer: %s\n", read_result.error_message);
					free(reader->object_values);
					reader->object_values = NULL;
					reader->header.objValueBufferSize = 0;
				} else {
					fprintf(stderr, "Successfully read %u bytes of object values\n", reader->header.objValueBufferSize);
				}
			}
		}
	}

	return SUCCESS_RESULT();
}

/* Read big integers */
Result hbc_reader_read_bigints(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}
	
	fprintf(stderr, "Reading BigInts at position %zu\n", reader->file_buffer.position);

	/* Skip if not present in this version */
	if (reader->header.version < 87) {
		fprintf(stderr, "BigInt not supported in this bytecode version\n");
		return SUCCESS_RESULT();
	}
	
	/* Validate BigInt count */
	if (reader->header.bigIntCount > 100000) { /* Arbitrary reasonable limit */
		fprintf(stderr, "Warning: Very large BigInt count (%u), might be invalid\n", 
			reader->header.bigIntCount);
		reader->header.bigIntCount = 0;
		reader->header.bigIntStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Try to align buffer with safety check */
	Result align_result = align_over_padding(&reader->file_buffer, 4);
	if (align_result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Warning: Failed to align buffer for BigInts: %s\n", align_result.error_message);
		reader->header.bigIntCount = 0;
		reader->header.bigIntStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Check if there's anything to read */
	if (reader->header.bigIntCount == 0 || reader->header.bigIntStorageSize == 0) {
		fprintf(stderr, "No BigInts to read\n");
		reader->bigint_values = NULL;
		reader->bigint_count = 0;
		return SUCCESS_RESULT();
	}
	
	/* Check if there's enough data for the BigInt table */
	size_t bigint_table_size = reader->header.bigIntCount * sizeof(OffsetLengthPair);
	if (reader->file_buffer.position + bigint_table_size > reader->file_buffer.size) {
		fprintf(stderr, "Warning: Not enough data for BigInt table (need %zu bytes)\n", bigint_table_size);
		reader->header.bigIntCount = 0;
		reader->header.bigIntStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Allocate BigInt table */
	OffsetLengthPair* bigint_table = NULL;
	if (reader->header.bigIntCount > 0) {
		bigint_table = (OffsetLengthPair*)malloc(bigint_table_size);
		if (!bigint_table) {
			fprintf(stderr, "Failed to allocate %zu bytes for BigInt table\n", bigint_table_size);
			reader->header.bigIntCount = 0;
			reader->header.bigIntStorageSize = 0;
			return SUCCESS_RESULT();
		}

		/* Read BigInt table entries with safety checks */
		bool read_error = false;
		for (u32 i = 0; i < reader->header.bigIntCount; i++) {
			/* Ensure there's enough buffer for two u32s */
			if (reader->file_buffer.position + 8 > reader->file_buffer.size) {
				fprintf(stderr, "Reached end of buffer while reading BigInt table entry %u\n", i);
				reader->header.bigIntCount = i; /* Truncate to what we've read */
				read_error = true;
				break;
			}
			
			Result result1 = buffer_reader_read_u32(&reader->file_buffer, &bigint_table[i].offset);
			Result result2 = buffer_reader_read_u32(&reader->file_buffer, &bigint_table[i].length);
			
			if (result1.code != RESULT_SUCCESS || result2.code != RESULT_SUCCESS) {
				fprintf(stderr, "Error reading BigInt table entry %u\n", i);
				reader->header.bigIntCount = i; /* Truncate to what we've read */
				read_error = true;
				break;
			}
		}
		
		if (read_error) {
			free(bigint_table);
			return SUCCESS_RESULT();
		}
	}

	/* Align buffer for BigInt storage */
	Result storage_align_result = align_over_padding(&reader->file_buffer, 4);
	if (storage_align_result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Warning: Failed to align buffer for BigInt storage: %s\n", storage_align_result.error_message);
		free(bigint_table);
		reader->header.bigIntCount = 0;
		reader->header.bigIntStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Check if there's enough data for BigInt storage */
	if (reader->file_buffer.position + reader->header.bigIntStorageSize > reader->file_buffer.size) {
		fprintf(stderr, "Warning: Not enough data for BigInt storage (need %u bytes)\n", reader->header.bigIntStorageSize);
		free(bigint_table);
		reader->header.bigIntCount = 0;
		reader->header.bigIntStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Read BigInt storage */
	u8* bigint_storage = NULL;
	if (reader->header.bigIntStorageSize > 0) {
		bigint_storage = (u8*)malloc(reader->header.bigIntStorageSize);
		if (!bigint_storage) {
			fprintf(stderr, "Failed to allocate %u bytes for BigInt storage\n", reader->header.bigIntStorageSize);
			free(bigint_table);
			reader->header.bigIntCount = 0;
			reader->header.bigIntStorageSize = 0;
			return SUCCESS_RESULT();
		}

		Result read_result = buffer_reader_read_bytes(&reader->file_buffer, 
			bigint_storage, reader->header.bigIntStorageSize);
		if (read_result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error reading BigInt storage: %s\n", read_result.error_message);
			free(bigint_table);
			free(bigint_storage);
			reader->header.bigIntCount = 0;
			reader->header.bigIntStorageSize = 0;
			return SUCCESS_RESULT();
		}
		
		fprintf(stderr, "Successfully read %u bytes of BigInt storage\n", reader->header.bigIntStorageSize);
	}

	/* Allocate BigInt values */
	reader->bigint_values = (i64*)calloc(reader->header.bigIntCount, sizeof(i64));
	if (!reader->bigint_values) {
		fprintf(stderr, "Failed to allocate BigInt values array\n");
		free(bigint_table);
		free(bigint_storage);
		reader->header.bigIntCount = 0;
		reader->header.bigIntStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Parse BigInt values with safety checks */
	for (u32 i = 0; i < reader->header.bigIntCount; i++) {
		u32 offset = bigint_table[i].offset;
		u32 length = bigint_table[i].length;

		/* Check bounds */
		if (offset + length > reader->header.bigIntStorageSize) {
			fprintf(stderr, "Warning: BigInt %u has invalid offset/length (%u+%u exceeds %u)\n",
				i, offset, length, reader->header.bigIntStorageSize);
			/* Use zero for this value */
			reader->bigint_values[i] = 0;
			continue;
		}

		/* Make sure the length is reasonable */
		if (length > sizeof(i64)) {
			fprintf(stderr, "Warning: BigInt %u has excessive length (%u), truncating\n", i, length);
			length = sizeof(i64);
		}

		/* Read the BigInt */
		i64 value = 0;
		for (u32 j = 0; j < length; j++) {
			value |= ((i64)bigint_storage[offset + j]) << (j * 8);
		}

		reader->bigint_values[i] = value;
	}

	reader->bigint_count = reader->header.bigIntCount;
	fprintf(stderr, "Successfully processed %zu BigInt values\n", reader->bigint_count);

	/* Free temporary storage */
	free(bigint_table);
	free(bigint_storage);

	return SUCCESS_RESULT();
}

/* Read regular expressions */
Result hbc_reader_read_regexp(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}
	
	fprintf(stderr, "Reading RegExp data at position %zu\n", reader->file_buffer.position);
	
	/* Validate regexp count and storage size */
	if (reader->header.regExpCount > 100000) { /* Arbitrary limit */
		fprintf(stderr, "Warning: Very large RegExp count (%u), may be corrupted\n", 
			reader->header.regExpCount);
		reader->header.regExpCount = 0;
		reader->header.regExpStorageSize = 0;
		return SUCCESS_RESULT();
	}
	
	if (reader->header.regExpStorageSize > 100 * 1024 * 1024) { /* 100MB limit */
		fprintf(stderr, "Warning: Very large RegExp storage size (%u bytes), may be corrupted\n", 
			reader->header.regExpStorageSize);
		reader->header.regExpCount = 0;
		reader->header.regExpStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Align buffer with error handling */
	Result align_result = align_over_padding(&reader->file_buffer, 4);
	if (align_result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Warning: Failed to align buffer for RegExp table: %s\n", align_result.error_message);
		reader->header.regExpCount = 0;
		reader->header.regExpStorageSize = 0;
		return SUCCESS_RESULT();
	}
	
	/* Check if anything to read */
	if (reader->header.regExpCount == 0 || reader->header.regExpStorageSize == 0) {
		fprintf(stderr, "No RegExp data to read\n");
		reader->regexp_table = NULL;
		reader->regexp_storage = NULL;
		reader->regexp_storage_size = 0;
		return SUCCESS_RESULT();
	}

	/* Check if we have enough data for the table */
	size_t table_size = reader->header.regExpCount * sizeof(OffsetLengthPair);
	if (reader->file_buffer.position + table_size > reader->file_buffer.size) {
		fprintf(stderr, "Warning: Not enough data for RegExp table (need %zu bytes)\n", table_size);
		reader->header.regExpCount = 0;
		reader->header.regExpStorageSize = 0;
		return SUCCESS_RESULT();
	}

	/* Allocate regexp table */
	if (reader->header.regExpCount > 0) {
		reader->regexp_table = (OffsetLengthPair*)malloc(table_size);
		if (!reader->regexp_table) {
			fprintf(stderr, "Failed to allocate %zu bytes for RegExp table\n", table_size);
			reader->header.regExpCount = 0;
			reader->header.regExpStorageSize = 0;
			return SUCCESS_RESULT();
		}

		/* Read regexp table entries with safety checks */
		bool read_error = false;
		for (u32 i = 0; i < reader->header.regExpCount; i++) {
			/* Make sure there's enough data */
			if (reader->file_buffer.position + 8 > reader->file_buffer.size) {
				fprintf(stderr, "Reached end of file while reading RegExp table entry %u\n", i);
				reader->header.regExpCount = i;
				read_error = true;
				break;
			}
			
			Result res1 = buffer_reader_read_u32(&reader->file_buffer, &reader->regexp_table[i].offset);
			Result res2 = buffer_reader_read_u32(&reader->file_buffer, &reader->regexp_table[i].length);
			
			if (res1.code != RESULT_SUCCESS || res2.code != RESULT_SUCCESS) {
				fprintf(stderr, "Error reading RegExp table entry %u\n", i);
				reader->header.regExpCount = i;
				read_error = true;
				break;
			}
		}
		
		if (read_error) {
			return SUCCESS_RESULT();
		}
	}

	/* Align buffer for regexp storage with safety check */
	Result storage_align_result = align_over_padding(&reader->file_buffer, 4);
	if (storage_align_result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Warning: Failed to align buffer for RegExp storage: %s\n", 
			storage_align_result.error_message);
		reader->header.regExpStorageSize = 0;
		return SUCCESS_RESULT();
	}
	
	/* Check if enough data for storage */
	if (reader->file_buffer.position + reader->header.regExpStorageSize > reader->file_buffer.size) {
		fprintf(stderr, "Warning: Not enough data for RegExp storage (need %u bytes)\n",
			reader->header.regExpStorageSize);
		reader->header.regExpStorageSize = reader->file_buffer.size - reader->file_buffer.position;
		
		if (reader->header.regExpStorageSize <= 0) {
			reader->header.regExpStorageSize = 0;
			return SUCCESS_RESULT();
		}
	}

	/* Read regexp storage */
	if (reader->header.regExpStorageSize > 0) {
		reader->regexp_storage = (u8*)malloc(reader->header.regExpStorageSize);
		if (!reader->regexp_storage) {
			fprintf(stderr, "Failed to allocate %u bytes for RegExp storage\n",
				reader->header.regExpStorageSize);
			reader->header.regExpStorageSize = 0;
			return SUCCESS_RESULT();
		}

		Result read_result = buffer_reader_read_bytes(&reader->file_buffer, 
			reader->regexp_storage, reader->header.regExpStorageSize);
			
		if (read_result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error reading RegExp storage: %s\n", read_result.error_message);
			free(reader->regexp_storage);
			reader->regexp_storage = NULL;
			reader->header.regExpStorageSize = 0;
			return SUCCESS_RESULT();
		}
		
		reader->regexp_storage_size = reader->header.regExpStorageSize;
		fprintf(stderr, "Successfully read %u bytes of RegExp storage\n", reader->header.regExpStorageSize);
	}

	return SUCCESS_RESULT();
}

/* Read CommonJS modules */
Result hbc_reader_read_cjs_modules(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Align buffer */
	RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

	if (reader->header.cjsModuleCount > 0) {
		if (reader->header.cjsModulesStaticallyResolved && reader->header.version < 77) {
			/* Old format: just module IDs */
			reader->cjs_module_ids = (u32*)malloc(reader->header.cjsModuleCount * sizeof(u32));
			if (!reader->cjs_module_ids) {
				return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate CJS module IDs");
			}

			for (u32 i = 0; i < reader->header.cjsModuleCount; i++) {
				RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->cjs_module_ids[i]));
			}
		} else {
			/* New format: symbol-offset pairs */
			reader->cjs_modules = (SymbolOffsetPair*)malloc(reader->header.cjsModuleCount * sizeof(SymbolOffsetPair));
			if (!reader->cjs_modules) {
				return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate CJS modules");
			}

			for (u32 i = 0; i < reader->header.cjsModuleCount; i++) {
				RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->cjs_modules[i].symbol_id));
				RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->cjs_modules[i].offset));
			}
		}
	}

	return SUCCESS_RESULT();
}

/* Read function sources */
Result hbc_reader_read_function_sources(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Skip if not present in this version */
	if (reader->header.version < 84) {
		return SUCCESS_RESULT();
	}

	/* Align buffer */
	RETURN_IF_ERROR(align_over_padding(&reader->file_buffer, 4));

	/* Allocate function sources */
	if (reader->header.functionSourceCount > 0) {
		reader->function_sources = (FunctionSourceEntry*)malloc(reader->header.functionSourceCount * sizeof(FunctionSourceEntry));
		if (!reader->function_sources) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function sources");
		}

		/* Read function source entries */
		for (u32 i = 0; i < reader->header.functionSourceCount; i++) {
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->function_sources[i].function_id));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->function_sources[i].string_id));
		}

		reader->function_source_count = reader->header.functionSourceCount;
	}

	return SUCCESS_RESULT();
}

/* Read debug information */
Result hbc_reader_read_debug_info(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}

	/* Seek to debug info offset */
	RETURN_IF_ERROR(buffer_reader_seek(&reader->file_buffer, reader->header.debugInfoOffset));

	/* Read debug info header */
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_info_header.filename_count));
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_info_header.filename_storage_size));
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_info_header.file_region_count));
	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_info_header.scope_desc_data_offset));

	if (reader->header.version >= 91) {
		RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_info_header.textified_data_offset));
		RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_info_header.string_table_offset));
	}

	RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_info_header.debug_data_size));

	/* Allocate debug string table */
	if (reader->debug_info_header.filename_count > 0) {
		reader->debug_string_table = (OffsetLengthPair*)malloc(
				reader->debug_info_header.filename_count * sizeof(OffsetLengthPair));
		if (!reader->debug_string_table) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate debug string table");
		}

		/* Read debug string table entries */
		for (u32 i = 0; i < reader->debug_info_header.filename_count; i++) {
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_string_table[i].offset));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_string_table[i].length));
		}
	}

	/* Read debug string storage */
	if (reader->debug_info_header.filename_storage_size > 0) {
		reader->debug_string_storage = (u8*)malloc(reader->debug_info_header.filename_storage_size);
		if (!reader->debug_string_storage) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate debug string storage");
		}

		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->debug_string_storage, 
					reader->debug_info_header.filename_storage_size));
		reader->debug_string_storage_size = reader->debug_info_header.filename_storage_size;
	}

	/* Read debug file regions */
	if (reader->debug_info_header.file_region_count > 0) {
		reader->debug_file_regions = (DebugFileRegion*)malloc(
				reader->debug_info_header.file_region_count * sizeof(DebugFileRegion));
		if (!reader->debug_file_regions) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate debug file regions");
		}

		/* Read debug file region entries */
		for (u32 i = 0; i < reader->debug_info_header.file_region_count; i++) {
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_file_regions[i].from_address));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_file_regions[i].filename_id));
			RETURN_IF_ERROR(buffer_reader_read_u32(&reader->file_buffer, &reader->debug_file_regions[i].source_mapping_id));
		}

		reader->debug_file_region_count = reader->debug_info_header.file_region_count;
	}

	/* Read sources data */
	if (reader->header.version < 91) {
		size_t sources_data_size = reader->debug_info_header.scope_desc_data_offset;
		reader->sources_data_storage = (u8*)malloc(sources_data_size);
		if (!reader->sources_data_storage) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate sources data storage");
		}

		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->sources_data_storage, sources_data_size));
		reader->sources_data_storage_size = sources_data_size;

		size_t scope_desc_data_size = reader->debug_info_header.debug_data_size - reader->debug_info_header.scope_desc_data_offset;
		reader->scope_desc_data_storage = (u8*)malloc(scope_desc_data_size);
		if (!reader->scope_desc_data_storage) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate scope desc data storage");
		}

		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->scope_desc_data_storage, scope_desc_data_size));
		reader->scope_desc_data_storage_size = scope_desc_data_size;
	} else {
		size_t sources_data_size = reader->debug_info_header.scope_desc_data_offset;
		reader->sources_data_storage = (u8*)malloc(sources_data_size);
		if (!reader->sources_data_storage) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate sources data storage");
		}

		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->sources_data_storage, sources_data_size));
		reader->sources_data_storage_size = sources_data_size;

		size_t scope_desc_data_size = reader->debug_info_header.textified_data_offset - reader->debug_info_header.scope_desc_data_offset;
		reader->scope_desc_data_storage = (u8*)malloc(scope_desc_data_size);
		if (!reader->scope_desc_data_storage) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate scope desc data storage");
		}

		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->scope_desc_data_storage, scope_desc_data_size));
		reader->scope_desc_data_storage_size = scope_desc_data_size;

		size_t textified_data_size = reader->debug_info_header.string_table_offset - reader->debug_info_header.textified_data_offset;
		reader->textified_data_storage = (u8*)malloc(textified_data_size);
		if (!reader->textified_data_storage) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate textified data storage");
		}

		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->textified_data_storage, textified_data_size));
		reader->textified_data_storage_size = textified_data_size;

		size_t string_table_size = reader->debug_info_header.debug_data_size - reader->debug_info_header.string_table_offset;
		reader->string_table_storage = (u8*)malloc(string_table_size);
		if (!reader->string_table_storage) {
			return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate string table storage");
		}

		RETURN_IF_ERROR(buffer_reader_read_bytes(&reader->file_buffer, reader->string_table_storage, string_table_size));
		reader->string_table_storage_size = string_table_size;
	}

	return SUCCESS_RESULT();
}

/* Robust implementation of function reading */
Result hbc_reader_read_functions_robust(HBCReader* reader) {
	if (!reader) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Reader is NULL");
	}
	
	/* Set reasonable limits */
	const u32 MAX_SAFE_FUNCTIONS = 50000;
	u32 max_functions_to_read = reader->header.functionCount;
	
	if (max_functions_to_read > MAX_SAFE_FUNCTIONS) {
		fprintf(stderr, "Warning: Very large function count (%u). Limiting to %u for safety.\n", 
			reader->header.functionCount, MAX_SAFE_FUNCTIONS);
		max_functions_to_read = MAX_SAFE_FUNCTIONS;
	}
	
	/* Log position info */
	fprintf(stderr, "Reading functions at position %zu of %zu bytes.\n", 
		reader->file_buffer.position, reader->file_buffer.size);
		
	/* Align buffer */
	Result result = align_over_padding(&reader->file_buffer, 4);
	if (result.code != RESULT_SUCCESS) {
		return result;
	}
	
	/* Calculate memory requirements */
	size_t function_headers_size = max_functions_to_read * sizeof(FunctionHeader);
	size_t exc_handlers_size = max_functions_to_read * sizeof(ExceptionHandlerList);
	size_t debug_offsets_size = max_functions_to_read * sizeof(DebugOffsets);
	
	/* Check for unreasonable memory requirements */
	size_t total_memory = function_headers_size + exc_handlers_size + debug_offsets_size;
	if (total_memory > 1024 * 1024 * 1024) { /* > 1GB */
		fprintf(stderr, "Warning: Memory allocation for %u functions will require %.2f GB\n", 
			max_functions_to_read, (double)total_memory / (1024 * 1024 * 1024));
	}
	
	/* Allocate memory for function data */
	reader->function_headers = (FunctionHeader*)calloc(max_functions_to_read, sizeof(FunctionHeader));
	if (!reader->function_headers) {
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate function headers");
	}
	
	reader->function_id_to_exc_handlers = (ExceptionHandlerList*)calloc(max_functions_to_read, sizeof(ExceptionHandlerList));
	if (!reader->function_id_to_exc_handlers) {
		free(reader->function_headers);
		reader->function_headers = NULL;
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate exception handler lists");
	}
	
	reader->function_id_to_debug_offsets = (DebugOffsets*)calloc(max_functions_to_read, sizeof(DebugOffsets));
	if (!reader->function_id_to_debug_offsets) {
		free(reader->function_headers);
		free(reader->function_id_to_exc_handlers);
		reader->function_headers = NULL;
		reader->function_id_to_exc_handlers = NULL;
		return ERROR_RESULT(RESULT_ERROR_MEMORY_ALLOCATION, "Failed to allocate debug offsets");
	}
	
	/* Track success count */
	u32 successful_functions = 0;
	
	/* Read each function header */
	for (u32 i = 0; i < max_functions_to_read; i++) {
		/* Safety check - ensure we have enough buffer for a function header (16 bytes) */
		if (reader->file_buffer.position + 16 > reader->file_buffer.size) {
			fprintf(stderr, "Reached end of file after reading %u of %u functions\n", 
				i, reader->header.functionCount);
			break;  /* End reading if we reach end of buffer */
		}
		
		/* Track position in case we need to restore it */
		size_t start_position = reader->file_buffer.position;
		
		/* Read function header raw data with explicit error handling */
		u32 raw_data[4];
		bool header_read_failed = false;
		
		for (int j = 0; j < 4; j++) {
			Result res = buffer_reader_read_u32(&reader->file_buffer, &raw_data[j]);
			if (res.code != RESULT_SUCCESS) {
				fprintf(stderr, "Error reading function %u header word %d: %s\n", 
					i, j, res.error_message);
				header_read_failed = true;
				break;
			}
		}
		
		if (header_read_failed) {
			/* Try to restore position and break */
			buffer_reader_seek(&reader->file_buffer, start_position);
			break;
		}
		
        /* Debug: dump first header raw data to validate bit layout */
        if (i == 0) {
            fprintf(stderr, "Func0 raw: %08x %08x %08x %08x\n", raw_data[0], raw_data[1], raw_data[2], raw_data[3]);
        }

        /* Process function header data */
        FunctionHeader* header = &reader->function_headers[i];

        /* Extract fields from raw data (small header) */
        u32 small_offset = raw_data[0] & 0x1FFFFFF;  /* 25 bits */
        u32 small_paramCount = (raw_data[0] >> 25) & 0x7F;  /* 7 bits */

        u32 small_bytecodeSizeInBytes = raw_data[1] & 0x7FFF;  /* 15 bits */
        u32 small_functionName = (raw_data[1] >> 15) & 0x1FFFF;  /* 17 bits */

        u32 small_infoOffset = raw_data[2] & 0x1FFFFFF;  /* 25 bits */
        u32 small_frameSize = (raw_data[2] >> 25) & 0x7F;  /* 7 bits */

        u8  small_environmentSize = (u8)(raw_data[3] & 0xFF);
        u8  small_highestReadCacheIndex = (u8)((raw_data[3] >> 8) & 0xFF);
        u8  small_highestWriteCacheIndex = (u8)((raw_data[3] >> 16) & 0xFF);

        u8  small_prohibitInvoke = (raw_data[3] >> 24) & 0x3;
        u8  small_strictMode = (raw_data[3] >> 26) & 0x1;
        u8  small_hasExceptionHandler = (raw_data[3] >> 27) & 0x1;
        u8  small_hasDebugInfo = (raw_data[3] >> 28) & 0x1;
        u8  small_overflowed = (raw_data[3] >> 29) & 0x1;
        u8  small_unused = (raw_data[3] >> 30) & 0x3;

        /* If the small header overflowed OR looks truncated (e.g. size==0), load the large header as Python does */
        if (small_overflowed || small_bytecodeSizeInBytes == 0) {
            /* Calculate absolute offset of the large header */
            u32 large_header_offset = (small_infoOffset << 16) | small_offset;

            /* Seek to large header */
            Result sr = buffer_reader_seek(&reader->file_buffer, large_header_offset);
            if (sr.code == RESULT_SUCCESS) {
                /* Read large function header fields explicitly */
                LargeFunctionHeader large_header;
                memset(&large_header, 0, sizeof(large_header));

                /* Read in the same order as in the non-robust path */
                if (buffer_reader_read_u32(&reader->file_buffer, &large_header.offset).code == RESULT_SUCCESS &&
                    buffer_reader_read_u32(&reader->file_buffer, &large_header.paramCount).code == RESULT_SUCCESS &&
                    buffer_reader_read_u32(&reader->file_buffer, &large_header.bytecodeSizeInBytes).code == RESULT_SUCCESS &&
                    buffer_reader_read_u32(&reader->file_buffer, &large_header.functionName).code == RESULT_SUCCESS &&
                    buffer_reader_read_u32(&reader->file_buffer, &large_header.infoOffset).code == RESULT_SUCCESS &&
                    buffer_reader_read_u32(&reader->file_buffer, &large_header.frameSize).code == RESULT_SUCCESS &&
                    buffer_reader_read_u32(&reader->file_buffer, &large_header.environmentSize).code == RESULT_SUCCESS) {
                    /* Read tail bytes */
                    buffer_reader_read_u8(&reader->file_buffer, &large_header.highestReadCacheIndex);
                    buffer_reader_read_u8(&reader->file_buffer, &large_header.highestWriteCacheIndex);
                    u8 flags = 0;
                    buffer_reader_read_u8(&reader->file_buffer, &flags);
                    large_header.prohibitInvoke = flags & 0x3;
                    large_header.strictMode = (flags >> 2) & 0x1;
                    large_header.hasExceptionHandler = (flags >> 3) & 0x1;
                    large_header.hasDebugInfo = (flags >> 4) & 0x1;
                    large_header.overflowed = (flags >> 5) & 0x1;
                    large_header.unused = (flags >> 6) & 0x3;

                    /* Copy into combined header */
                    header->offset = large_header.offset;
                    header->paramCount = large_header.paramCount;
                    header->bytecodeSizeInBytes = large_header.bytecodeSizeInBytes;
                    header->functionName = large_header.functionName;
                    header->infoOffset = large_header.infoOffset;
                    header->frameSize = large_header.frameSize;
                    header->environmentSize = (u8)large_header.environmentSize;
                    header->highestReadCacheIndex = large_header.highestReadCacheIndex;
                    header->highestWriteCacheIndex = large_header.highestWriteCacheIndex;
                    header->prohibitInvoke = large_header.prohibitInvoke;
                    header->strictMode = large_header.strictMode;
                    header->hasExceptionHandler = large_header.hasExceptionHandler;
                    header->hasDebugInfo = large_header.hasDebugInfo;
                    header->overflowed = large_header.overflowed;
                    header->unused = large_header.unused;

                    /* Restore to next small header position */
                    buffer_reader_seek(&reader->file_buffer, start_position + 16);
                } else {
                    /* Fallback to small header values on read error */
                    header->offset = small_offset;
                    header->paramCount = small_paramCount;
                    header->bytecodeSizeInBytes = small_bytecodeSizeInBytes;
                    header->functionName = small_functionName;
                    header->infoOffset = small_infoOffset;
                    header->frameSize = small_frameSize;
                    header->environmentSize = small_environmentSize;
                    header->highestReadCacheIndex = small_highestReadCacheIndex;
                    header->highestWriteCacheIndex = small_highestWriteCacheIndex;
                    header->prohibitInvoke = small_prohibitInvoke;
                    header->strictMode = small_strictMode;
                    header->hasExceptionHandler = small_hasExceptionHandler;
                    header->hasDebugInfo = small_hasDebugInfo;
                    header->overflowed = small_overflowed;
                    header->unused = small_unused;
                }
            } else {
                /* Fallback to small header values if we can't seek */
                header->offset = small_offset;
                header->paramCount = small_paramCount;
                header->bytecodeSizeInBytes = small_bytecodeSizeInBytes;
                header->functionName = small_functionName;
                header->infoOffset = small_infoOffset;
                header->frameSize = small_frameSize;
                header->environmentSize = small_environmentSize;
                header->highestReadCacheIndex = small_highestReadCacheIndex;
                header->highestWriteCacheIndex = small_highestWriteCacheIndex;
                header->prohibitInvoke = small_prohibitInvoke;
                header->strictMode = small_strictMode;
                header->hasExceptionHandler = small_hasExceptionHandler;
                header->hasDebugInfo = small_hasDebugInfo;
                header->overflowed = small_overflowed;
                header->unused = small_unused;
            }
        } else {
            /* No overflow: use small header values directly */
            header->offset = small_offset;
            header->paramCount = small_paramCount;
            header->bytecodeSizeInBytes = small_bytecodeSizeInBytes;
            header->functionName = small_functionName;
            header->infoOffset = small_infoOffset;
            header->frameSize = small_frameSize;
            header->environmentSize = small_environmentSize;
            header->highestReadCacheIndex = small_highestReadCacheIndex;
            header->highestWriteCacheIndex = small_highestWriteCacheIndex;
            header->prohibitInvoke = small_prohibitInvoke;
            header->strictMode = small_strictMode;
            header->hasExceptionHandler = small_hasExceptionHandler;
            header->hasDebugInfo = small_hasDebugInfo;
            header->overflowed = small_overflowed;
            header->unused = small_unused;
        }
		
		/* Validation - check for unreasonable values */
		if (header->bytecodeSizeInBytes > 10 * 1024 * 1024) {  /* > 10MB */
			fprintf(stderr, "Warning: Function %u has very large bytecode: %u bytes\n", 
				i, header->bytecodeSizeInBytes);
		}
		
		if (header->offset >= reader->file_buffer.size) {
			fprintf(stderr, "Error: Function %u offset (%u) exceeds file size\n", 
				i, header->offset);
			continue;  /* Skip this function */
		}
		
        /* For robustness, we don't load bytecode here */
        header->bytecode = NULL;

        successful_functions++;

        /* Ensure position is at next small header (16 bytes per entry) */
        Result seek_result = buffer_reader_seek(&reader->file_buffer, start_position + 16);
        if (seek_result.code != RESULT_SUCCESS) {
            fprintf(stderr, "Error seeking to next function header after %u: %s\n", 
                    i, seek_result.error_message);
            break;
        }
	}
	
	/* Adjust function count to what we actually read */
	reader->header.functionCount = successful_functions;
	fprintf(stderr, "Successfully read %u function headers\n", successful_functions);
	
	return SUCCESS_RESULT();
}

/* Read the entire file */
Result hbc_reader_read_whole_file(HBCReader* reader, const char* filename) {
	if (!reader || !filename) {
		return ERROR_RESULT(RESULT_ERROR_INVALID_ARGUMENT, "Invalid arguments for hbc_reader_read_whole_file");
	}

	/* Initialize reader */
	RETURN_IF_ERROR(hbc_reader_init(reader));

	/* Read file into buffer */
	Result result = hbc_reader_read_file(reader, filename);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading file: %s\n", result.error_message);
		return result;
	}

	/* Read header */
	result = hbc_reader_read_header(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading header: %s\n", result.error_message);
		return result;
	}
	
	fprintf(stderr, "Read header successfully. Version: %u, Function count: %u, String count: %u\n", 
		reader->header.version, reader->header.functionCount, reader->header.stringCount);

	/* Read functions using the robust implementation */
	result = hbc_reader_read_functions_robust(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading functions: %s\n", result.error_message);
		return result;
	}
	
	/* Continue with the rest of the file parsing */
	
	/* Read string kinds */
	result = hbc_reader_read_string_kinds(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading string kinds: %s\n", result.error_message);
		return result;
	}

	/* Read identifier hashes */
	result = hbc_reader_read_identifier_hashes(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading identifier hashes: %s\n", result.error_message);
		return result;
	}

	/* Read string tables */
	result = hbc_reader_read_string_tables(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading string tables: %s\n", result.error_message);
		return result;
	}
	
	fprintf(stderr, "Read strings successfully.\n");

	/* Read arrays */
	result = hbc_reader_read_arrays(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading arrays: %s\n", result.error_message);
		return result;
	}

	/* Read BigInts if present */
	if (reader->header.version >= 87) {
		result = hbc_reader_read_bigints(reader);
		if (result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error reading BigInts: %s\n", result.error_message);
			return result;
		}
	}

	/* Read RegExps */
	result = hbc_reader_read_regexp(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading RegExp: %s\n", result.error_message);
		return result;
	}

	/* Read CJS modules */
	result = hbc_reader_read_cjs_modules(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading CJS modules: %s\n", result.error_message);
		return result;
	}

	/* Read function sources if present */
	if (reader->header.version >= 84) {
		result = hbc_reader_read_function_sources(reader);
		if (result.code != RESULT_SUCCESS) {
			fprintf(stderr, "Error reading function sources: %s\n", result.error_message);
			return result;
		}
	}

	/* Read debug info */
	result = hbc_reader_read_debug_info(reader);
	if (result.code != RESULT_SUCCESS) {
		fprintf(stderr, "Error reading debug info: %s\n", result.error_message);
		return result;
	}
	
	fprintf(stderr, "Read %u functions successfully.\n", reader->header.functionCount);

	return SUCCESS_RESULT();
}

/* Convert StringKind to string */
const char* string_kind_to_string(StringKind kind) {
	switch (kind) {
	case STRING_KIND_STRING:
		return "String";
	case STRING_KIND_IDENTIFIER:
		return "Identifier";
	case STRING_KIND_PREDEFINED:
		return "Predefined";
	default:
		return "Unknown";
	}
}

/* Temporary implementation of get_bytecode_module until we implement the opcodes */
BytecodeModule* get_bytecode_module(u32 bytecode_version) {
	/* This is a placeholder that will be replaced with actual implementation */
	static BytecodeModule dummy_module = {0};
	dummy_module.version = bytecode_version;
	return &dummy_module;
}
