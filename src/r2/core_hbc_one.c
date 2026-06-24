/* radare2 - BSD - Copyright 2025-2026 - pancake */

/* Core HBC plugin with plugin registration enabled for r2one */

#define HBC_CORE_REGISTER_PLUGINS 1
#define R2_PLUGIN_INCORE 1
#include "asm_hbc.c"
#include "bin_hbc.c"
#include "arch_hbc.c"
#undef HBC_VADDR_BASE
#include "core_hbc.c"

R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = (void *)&r_core_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
