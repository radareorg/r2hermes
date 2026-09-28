/* r2hermes - BSD - Copyright 2026 - pancake */

/* r2hermes-V: identify the Hermes / React Native build of the loaded binary.
 *
 * For HBC files the bytecode version comes from the header. For the native
 * engine (libhermes.so) it recovers:
 *   - the "for RN x.y.z" string Hermes reports as "OSS Release Version"
 *   - the constant returned by HermesRuntime::getBytecodeVersion ()
 *   - the toolchain recorded in .comment (via RBinInfo.compiler)
 */

#include <hbc/parser.h>

#define HERMES_RN_TAG "for RN "
#define HERMES_BCVER_SYM "_ZN8facebook6hermes13HermesRuntime18getBytecodeVersionEv"

static char *version_find_rn(RBinFile *bf) {
	ut64 size = 0;
	const ut8 *data = r_buf_data (bf->buf, &size);
	if (!data || size > ST32_MAX) {
		return NULL;
	}
	const int taglen = strlen (HERMES_RN_TAG);
	const ut8 *p = data;
	const ut8 *end = data + size;
	while ((p = r_mem_mem (p, (int) (end - p), (const ut8 *)HERMES_RN_TAG, taglen))) {
		const ut8 *v = p + taglen;
		const ut8 *q = v;
		while (q < end && (isdigit (*q) || *q == '.' || *q == '-' || isalpha (*q))) {
			q++;
		}
		// must be a standalone NUL-terminated string starting with a digit
		if (q > v && q < end && !*q && isdigit (*v) && (p == data || !p[-1])) {
			return r_str_ndup ((const char *)v, (int) (q - v));
		}
		p++;
	}
	return NULL;
}

static int version_find_bcver(RCore *core) {
	RVecRBinSymbol *syms = r_bin_get_symbols_vec (core->bin);
	if (!syms) {
		return -1;
	}
	ut64 addr = UT64_MAX;
	RBinSymbol *sym;
	R_VEC_FOREACH (syms, sym) {
		if (sym->name && sym->vaddr && r_str_startswith (r_str_get (sym->name->oname), HERMES_BCVER_SYM)) {
			addr = sym->vaddr;
			break;
		}
	}
	if (addr == UT64_MAX) {
		return -1;
	}
	ut8 buf[64];
	if (!r_io_read_at (core->io, addr, buf, sizeof (buf))) {
		return -1;
	}
	// the function just returns a constant; accept a short prologue before it
	int ver = -1;
	int off = 0;
	int i;
	for (i = 0; i < 8 && off < (int)sizeof (buf); i++) {
		RAnalOp op;
		r_anal_op_init (&op);
		int len = r_anal_op (core->anal, &op, addr + off, buf + off, sizeof (buf) - off, R_ARCH_OP_MASK_VAL);
		const ut32 type = op.type & R_ANAL_OP_TYPE_MASK;
		if (type == R_ANAL_OP_TYPE_MOV && op.val != UT64_MAX && op.val > 0 && op.val < 1000) {
			ver = (int)op.val;
		}
		r_anal_op_fini (&op);
		if (len < 1 || type == R_ANAL_OP_TYPE_RET) {
			break;
		}
		off += len;
	}
	return ver;
}

static void cmd_version(HbcContext *ctx, RCore *core, const char *arg) {
	const bool json = *arg == 'j';
	if (*arg && !json) {
		r_cons_print (core->cons,
			"Usage: r2hermes-V[j]\n"
			" r2hermes-V       Show Hermes bytecode and React Native versions\n"
			" r2hermes-Vj      Same as JSON\n");
		return;
	}
	RBinFile *bf = core->bin->cur;
	if (!bf || !bf->buf) {
		R_LOG_ERROR ("No binary loaded");
		return;
	}
	int bcver = -1;
	char *rn = NULL;
	const char *compiler = NULL;
	const char *kind = "native";
	HBCHeader header;
	ut8 magic[8];
	if (r_buf_read_at (bf->buf, 0, magic, sizeof (magic)) == sizeof (magic) && r_read_le64 (magic) == HEADER_MAGIC && hbc_load_current_binary (ctx, core).code == RESULT_SUCCESS && hbc_get_header (ctx->hbc, &header).code == RESULT_SUCCESS) {
		kind = "hbc";
		bcver = header.version;
	} else {
		rn = version_find_rn (bf);
		bcver = version_find_bcver (core);
		RBinInfo *info = r_bin_get_info (core->bin);
		compiler = info? info->compiler: NULL;
		if (!rn && bcver < 0) {
			R_LOG_WARN ("This does not look like a Hermes binary");
		}
	}
	RCons *cons = core->cons;
	if (json) {
		PJ *pj = r_core_pj_new (core);
		pj_o (pj);
		pj_ks (pj, "type", kind);
		if (bcver >= 0) {
			pj_kn (pj, "bytecode_version", bcver);
		}
		if (rn) {
			pj_ks (pj, "react_native", rn);
		}
		if (compiler) {
			pj_ks (pj, "compiler", compiler);
		}
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (cons, s);
		free (s);
	} else {
		r_cons_printf (cons, "type             %s\n", kind);
		if (bcver >= 0) {
			r_cons_printf (cons, "bytecode_version %d\n", bcver);
		}
		if (rn) {
			r_cons_printf (cons, "react_native     %s\n", rn);
		}
		if (compiler) {
			r_cons_printf (cons, "compiler         %s\n", compiler);
		}
	}
	free (rn);
}
