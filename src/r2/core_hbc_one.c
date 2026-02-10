/* radare2 - LGPL - Copyright 2025-2026 - pancache */

/* Core HBC plugin with plugin registration enabled for r2one */

#define HBC_CORE_REGISTER_PLUGINS 1
#define R2_PLUGIN_INCORE 1
#include "asm_hbc.c"
#include "bin_hbc.c"
#include "arch_hbc.c"
#include "core_hbc.c"
