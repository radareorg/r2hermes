#include <hbc/opcodes/hermes_opcodes.h>
#include <stdlib.h>

/* Include per-version instruction set implementations (static functions) */
#include "v76.inc"
#include "v84.inc"
#include "v89.inc"
#include "v90.inc"
#include "v93.inc"
#include "v94.inc"
#include "v95.inc"
#include "v96.inc"

/* v91 and v92 are compatible with v90 -> forward to v90 implementation */
static HBCISA get_instruction_set_v91(void) {
	return get_instruction_set_v90 ();
}
static HBCISA get_instruction_set_v92(void) {
	return get_instruction_set_v90 ();
}

/* Public API for getting instruction set by version */
HBCISA hbc_isa_getv(int version) {
	switch (version) {
	case 90:
		return get_instruction_set_v90 ();
	case 89:
		return get_instruction_set_v89 ();
	case 84:
		return get_instruction_set_v84 ();
	case 91:
		return get_instruction_set_v91 ();
	case 92:
		return get_instruction_set_v92 ();
	case 93:
		return get_instruction_set_v93 ();
	case 94:
		return get_instruction_set_v94 ();
	case 95:
		return get_instruction_set_v95 ();
	case 96:
		return get_instruction_set_v96 ();
	case 76:
		return get_instruction_set_v76 ();
	default:
		if (version >= 72 && version < 90) {
			return get_instruction_set_v90 ();
		} else {
			return get_instruction_set_v96 ();
		}
	}
}
