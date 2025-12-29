#include <hbc/opcodes.h>

/* Include per-version instruction set implementations (static functions) */
#include "v51.inc.c"
#include "v58.inc.c"
#include "v59.inc.c"
#include "v61.inc.c"
#include "v62.inc.c"
#include "v68.inc.c"
#include "v69.inc.c"
#include "v70.inc.c"
#include "v72.inc.c"
#include "v73.inc.c"
#include "v76.inc.c"
#include "v80.inc.c"
#include "v81.inc.c"
#include "v82.inc.c"
#include "v83.inc.c"
#include "v84.inc.c"
#include "v85.inc.c"
#include "v86.inc.c"
#include "v87.inc.c"
#include "v89.inc.c"
#include "v90.inc.c"
#include "v92.inc.c"
#include "v93.inc.c"
#include "v94.inc.c"
#include "v95.inc.c"
#include "v96.inc.c"

#define ISA_COUNT(v) (sizeof (k_instructions_v ## v) / sizeof (k_instructions_v ## v[0]))
#define ISA_ENTRY(v, count_expr) static const HBCISA k_isa_v ## v = { .count = count_expr, .instructions = k_instructions_v ## v };

ISA_ENTRY(51, ISA_COUNT(51))
ISA_ENTRY(58, ISA_COUNT(58))
ISA_ENTRY(59, ISA_COUNT(59))
ISA_ENTRY(61, ISA_COUNT(61))
ISA_ENTRY(62, ISA_COUNT(62))
ISA_ENTRY(68, ISA_COUNT(68))
ISA_ENTRY(69, ISA_COUNT(69))
ISA_ENTRY(70, ISA_COUNT(70))
ISA_ENTRY(72, ISA_COUNT(72))
ISA_ENTRY(73, ISA_COUNT(73))
ISA_ENTRY(76, 256)
ISA_ENTRY(80, ISA_COUNT(80))
ISA_ENTRY(81, ISA_COUNT(81))
ISA_ENTRY(82, ISA_COUNT(82))
ISA_ENTRY(83, ISA_COUNT(83))
ISA_ENTRY(84, 256)
ISA_ENTRY(85, ISA_COUNT(85))
ISA_ENTRY(86, ISA_COUNT(86))
ISA_ENTRY(87, ISA_COUNT(87))
ISA_ENTRY(89, 256)
ISA_ENTRY(90, 256)
ISA_ENTRY(92, ISA_COUNT(92))
ISA_ENTRY(93, 256)
ISA_ENTRY(94, 256)
ISA_ENTRY(95, 256)
ISA_ENTRY(96, 208)

typedef struct {
	int version;
	const HBCISA *isa;
} IsaVersion;

static const IsaVersion k_isa_versions[] = {
	{ 51, &k_isa_v51 },
	{ 58, &k_isa_v58 },
	{ 59, &k_isa_v59 },
	{ 61, &k_isa_v61 },
	{ 62, &k_isa_v62 },
	{ 68, &k_isa_v68 },
	{ 69, &k_isa_v69 },
	{ 70, &k_isa_v70 },
	{ 72, &k_isa_v72 },
	{ 73, &k_isa_v73 },
	{ 76, &k_isa_v76 },
	{ 80, &k_isa_v80 },
	{ 81, &k_isa_v81 },
	{ 82, &k_isa_v82 },
	{ 83, &k_isa_v83 },
	{ 84, &k_isa_v84 },
	{ 85, &k_isa_v85 },
	{ 86, &k_isa_v86 },
	{ 87, &k_isa_v87 },
	{ 89, &k_isa_v89 },
	{ 90, &k_isa_v90 },
	{ 92, &k_isa_v92 },
	{ 93, &k_isa_v93 },
	{ 94, &k_isa_v94 },
	{ 95, &k_isa_v95 },
	{ 96, &k_isa_v96 },
};

/* Public API for getting instruction set by version */
HBCISA hbc_isa_getv(int version) {
	const IsaVersion *selected = &k_isa_versions[0];
	const size_t entry_count = sizeof (k_isa_versions) / sizeof (k_isa_versions[0]);

	for (size_t i = 0; i < entry_count; i++) {
		const IsaVersion *entry = &k_isa_versions[i];
		if (version < entry->version) {
			break;
		}
		selected = entry;
	}

	return *selected->isa;
}
