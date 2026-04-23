#include <hbc/hbc.h>

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
	if (!(x)) { \
		fprintf (stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x); \
		return 1; \
	} \
} while (0)

static void path_join(char *dst, size_t dst_size, const char *root, const char *path) {
	snprintf (dst, dst_size, "%s/%s", root, path);
}

static int test_small_debug_info(const char *root) {
	char path[512];
	path_join (path, sizeof (path), root, "test/bins/hbc/bespoke_eval.hbc");

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
	path_join (path, sizeof (path), root, "test/bins/hbc/index.android.bundle");

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

int main(int argc, char **argv) {
	const char *root = argc > 1? argv[1]: ".";
	if (test_small_debug_info (root) || test_empty_debug_info (root)) {
		return 1;
	}
	return 0;
}
