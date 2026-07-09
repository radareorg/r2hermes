/* radare2 - BSD - Copyright 2025-2026 - pancake */

#include "../src/lib/hbc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
	if (!(x)) { \
		fprintf (stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x); \
		return 1; \
	} \
} while (0)

static int test_small_debug_info(const char *root) {
	char path[512];
	snprintf (path, sizeof (path), "%s/test/bins/hbc/bespoke_eval.hbc", root);

	HBC *hbc = NULL;
	CHECK (hbc_open (path, &hbc).code == RESULT_SUCCESS);

	HBCDebugInfo di = { 0 };
	CHECK (hbc_get_debug_info (hbc, &di).code == RESULT_SUCCESS);
	CHECK (di.has_debug_info);
	CHECK (di.filename_count == 1);
	CHECK (di.filename_storage_size == 6);
	CHECK (di.file_region_count == 1);
	CHECK (di.functions_with_debug_info == 1);
	CHECK (di.source_locations_size == 13);
	CHECK (di.scope_desc_data_size == 3);
	CHECK (di.textified_data_size == 1);

	HBCSourceLineArray lines = { 0 };
	CHECK (hbc_get_source_lines (hbc, &lines).code == RESULT_SUCCESS);
	CHECK (hbc_has_source_lines (hbc));
	CHECK (lines.count == 2);
	CHECK (lines.lines[0].address == 0xb0);
	CHECK (lines.lines[0].function_address == 0);
	CHECK (lines.lines[0].line == 1);
	CHECK (lines.lines[0].column == 1);
	CHECK (!strcmp (lines.lines[0].filename, "yes.js"));
	CHECK (lines.lines[1].address == 0xb4);
	CHECK (lines.lines[1].function_address == 4);
	CHECK (lines.lines[1].line == 1);
	CHECK (lines.lines[1].column == 5);

	hbc_free_source_lines (&lines);
	hbc_close (hbc);
	return 0;
}

static int test_empty_debug_info(const char *root) {
	char path[512];
	snprintf (path, sizeof (path), "%s/test/bins/hbc/index.android.bundle", root);

	HBC *hbc = NULL;
	CHECK (hbc_open (path, &hbc).code == RESULT_SUCCESS);

	HBCDebugInfo di = { 0 };
	CHECK (hbc_get_debug_info (hbc, &di).code == RESULT_SUCCESS);
	CHECK (di.has_debug_info);
	CHECK (di.filename_count == 0);
	CHECK (di.file_region_count == 0);
	CHECK (di.functions_with_debug_info == 0);
	CHECK (di.source_locations_size == 0);
	CHECK (!hbc_has_source_lines (hbc));

	HBCSourceLineArray lines = { 0 };
	CHECK (hbc_get_source_lines (hbc, &lines).code == RESULT_SUCCESS);
	CHECK (lines.count == 0);

	hbc_free_source_lines (&lines);
	hbc_close (hbc);
	return 0;
}

static int test_function_bytecode_bounds(const char *root) {
	char path[512];
	snprintf (path, sizeof (path), "%s/test/bins/hbc/bespoke_eval.hbc", root);

	HBC *hbc = NULL;
	CHECK (hbc_open (path, &hbc).code == RESULT_SUCCESS);
	CHECK (hbc->reader.function_headers);
	CHECK (r_buf_size (hbc->reader.file_buffer) < UINT32_MAX);

	FunctionHeader *fh = &hbc->reader.function_headers[0];
	fh->offset = (u32)r_buf_size (hbc->reader.file_buffer) + 1;
	fh->bytecodeSizeInBytes = 1;

	const u8 *ptr = (const u8 *)1;
	u32 size = 1;
	CHECK (hbc_get_function_bytecode (hbc, 0, &ptr, &size).code == RESULT_ERROR_INVALID_DATA);
	CHECK (!ptr);
	CHECK (size == 0);

	hbc_close (hbc);
	return 0;
}

static int test_decode_rejects_bad_overflow_string_index(void) {
	StringTableEntry small[1] = { 0 };
	OffsetLengthPair overflow[1] = { 0 };
	small[0].length = 0xff;
	small[0].offset = 1;
	overflow[0].offset = 0x40;
	overflow[0].length = 8;

	HBCStrs tables = {
		.string_count = 1,
		.overflow_string_count = 1,
		.small_string_table = small,
		.overflow_string_table = overflow,
		.string_storage_offset = 0x1000
	};
	const u8 bytes[] = { 115, 0, 0, 0 };
	HBCDecodeCtx ctx = {
		.bytes = bytes,
		.len = sizeof (bytes),
		.bytecode_version = 96,
		.asm_syntax = true,
		.resolve_string_ids = true,
		.string_tables = &tables
	};
	HBCInsnInfo info = { 0 };
	CHECK (hbc_dec (&ctx, &info).code == RESULT_SUCCESS);
	CHECK (info.text);
	CHECK (strstr (info.text, "0x0"));
	CHECK (!strstr (info.text, "0x1040"));
	free (info.text);
	return 0;
}

int main(int argc, char **argv) {
	const char *root = argc > 1? argv[1]: ".";
	if (test_small_debug_info (root) || test_empty_debug_info (root) || test_function_bytecode_bounds (root) || test_decode_rejects_bad_overflow_string_index ()) {
		return 1;
	}
	return 0;
}
