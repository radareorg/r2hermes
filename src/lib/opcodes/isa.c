#include <hbc/opcodes.h>

/* Include per-version instruction set implementations (static functions) */
#include "v76.inc.c"
#include "v84.inc.c"
#include "v89.inc.c"
#include "v90.inc.c"
#include "v93.inc.c"
#include "v94.inc.c"
#include "v95.inc.c"
#include "v96.inc.c"

static const HBCISA k_isa_v76 = { .count = 256, .instructions = k_instructions_v76 };
static const HBCISA k_isa_v84 = { .count = 256, .instructions = k_instructions_v84 };
static const HBCISA k_isa_v89 = { .count = 256, .instructions = k_instructions_v89 };
static const HBCISA k_isa_v90 = { .count = 256, .instructions = k_instructions_v90 };
static const HBCISA k_isa_v93 = { .count = 256, .instructions = k_instructions_v93 };
static const HBCISA k_isa_v94 = { .count = 256, .instructions = k_instructions_v94 };
static const HBCISA k_isa_v95 = { .count = 256, .instructions = k_instructions_v95 };
static const HBCISA k_isa_v96 = { .count = 256, .instructions = k_instructions_v96 };

/* Public API for getting instruction set by version */
HBCISA hbc_isa_getv(int version) {
	switch (version) {
	case 76: return k_isa_v76;
	case 84: return k_isa_v84;
	case 89: return k_isa_v89;
	case 90: return k_isa_v90;
	case 91: return k_isa_v90;
	case 92: return k_isa_v90;
	case 93: return k_isa_v93;
	case 94: return k_isa_v94;
	case 95: return k_isa_v95;
	case 96: return k_isa_v96;
	default:
		if (version >= 72 && version < 90) {
			return k_isa_v90;
		} else {
			return k_isa_v96;
		}
	}
}
