/* r2hermes - BSD - Copyright 2025-2026 - pancake */

/* Core HBC plugin with plugin registration enabled for r2one */

#define HBC_CORE_REGISTER_PLUGINS 1
// radare2 defines R2_PLUGIN_INCORE when linking us statically (XPS)
#ifdef R2_PLUGIN_INCORE
#define HBC_STATIC_INCORE 1
#else
#define R2_PLUGIN_INCORE 1
#endif
#include "asm_hbc.c"
#include "bin_hbc.c"
#include "arch_hbc.c"
#undef HBC_VADDR_BASE
#include "core_hbc.c"

#ifndef HBC_STATIC_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = (void *)&r_core_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
