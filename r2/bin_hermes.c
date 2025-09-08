/* radare2 - LGPL - Copyright 2025 - hermes-dec */

#include <r_bin.h>
#include <r_lib.h>

// Include hermesdec headers
#include "../include/hermesdec/hermesdec.h"
#include "../include/common.h"

#define HEADER_MAGIC 0x1f1903c103bc1fc6ULL

static bool check(RBinFile *bf, RBuffer *b) {
    if (r_buf_size (b) >= 8) {
        ut64 magic;
        r_buf_read_at (b, 0, (ut8 *)&magic, sizeof (magic));
        return magic == HEADER_MAGIC;
    }
    return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
    return check (bf, buf);
}

static ut64 get_entrypoint(RBuffer *buf) {
    // For Hermes bytecode, the entrypoint is typically the global code index
    // We need to parse the header to find it
    if (r_buf_size (buf) >= 32) {
        ut32 global_code_index;
        r_buf_read_at (buf, 16, (ut8 *)&global_code_index, sizeof (global_code_index));
        return global_code_index;
    }
    return 0;
}

static RBinInfo *info(RBinFile *bf) {
    RBinInfo *ret = R_NEW0 (RBinInfo);
    if (!ret) {
        return NULL;
    }

    // Try to get header information
    if (r_buf_size (bf->buf) >= 32) {
        ut64 magic;
        ut32 version;
        r_buf_read_at (bf->buf, 0, (ut8 *)&magic, sizeof (magic));
        r_buf_read_at (bf->buf, 8, (ut8 *)&version, sizeof (version));

        if (magic == HEADER_MAGIC) {
            ret->file = strdup (bf->file);
            ret->type = r_str_newf ("Hermes bytecode v%d", version);
            ret->bclass = strdup ("Hermes bytecode");
            ret->rclass = strdup ("hermes");
            ret->arch = strdup ("hermes");
            ret->machine = r_str_newf ("Hermes VM v%d", version);
            ret->os = strdup ("any");
            ret->bits = 32; // Hermes bytecode is typically 32-bit
            ret->cpu = r_str_newf ("%d", version); // Pass version info
            return ret;
        }
    }

    // Fallback
    ret->file = strdup (bf->file);
    ret->type = strdup ("Hermes bytecode");
    ret->bclass = strdup ("Hermes bytecode");
    ret->rclass = strdup ("hermes");
    ret->arch = strdup ("hermes");
    ret->machine = strdup ("Hermes VM");
    ret->os = strdup ("any");
    ret->bits = 32;
    ret->cpu = strdup ("unknown");

    return ret;
}

static RList *sections(RBinFile *bf) {
    RList *sections = r_list_newf ((RListFree)free);
    if (!sections) {
        return NULL;
    }

    // For now, create a basic section for the entire file
    RBinSection *section = R_NEW0 (RBinSection);
    if (section) {
        section->name = strdup ("hermes_bytecode");
        section->size = r_buf_size (bf->buf);
        section->vsize = section->size;
        section->paddr = 0;
        section->vaddr = 0;
        section->perm = R_PERM_R;
        r_list_append (sections, section);
    }

    return sections;
}

static RList *entries(RBinFile *bf) {
    RList *entries = r_list_newf ((RListFree)free);
    if (!entries) {
        return NULL;
    }

    RBinAddr *addr = R_NEW0 (RBinAddr);
    if (!addr) {
        r_list_free (entries);
        return NULL;
    }

    ut64 entrypoint = get_entrypoint (bf->buf);
    addr->paddr = entrypoint;
    addr->vaddr = entrypoint;
    r_list_append (entries, addr);

    return entries;
}

static ut64 baddr(RBinFile *bf) {
    return 0;
}

static RList *symbols(RBinFile *bf) {
    RList *symbols = r_list_newf ((RListFree)free);
    if (!symbols) {
        return NULL;
    }

    // Try to parse the file and extract function symbols
    HermesDec *hd = NULL;
    if (r_buf_size (bf->buf) > 0) {
        // Create a temporary file or use memory buffer
        // For now, we'll create a simple symbol for the entry point
        RBinSymbol *symbol = R_NEW0 (RBinSymbol);
        if (symbol) {
            symbol->name = strdup ("entry");
            symbol->paddr = get_entrypoint (bf->buf);
            symbol->vaddr = symbol->paddr;
            symbol->size = 0; // Unknown size
            symbol->ordinal = 0;
            r_list_append (symbols, symbol);
        }
    }

    return symbols;
}

RBinPlugin r_bin_plugin_hermes = {
    .meta = {
        .name = "hermes",
        .author = "pancake",
        .desc = "Hermes bytecode format",
        .license = "MIT",
    },
    .info = &info,
    .load = &load,
    .check = &check,
    .entries = &entries,
    .sections = &sections,
    .baddr = &baddr,
    .symbols = &symbols,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_BIN,
    .data = &r_bin_plugin_hermes,
    .version = R2_VERSION
};
#endif
