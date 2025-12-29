#ifndef LIBHBC_TRANSLATOR_H
#define LIBHBC_TRANSLATOR_H

#include <hbc/common.h>
#include <hbc/bytecode.h>
#include "token.h"

/* Translate a single parsed instruction into a TokenString */
Result _hbc_translate_instruction_to_tokens(const ParsedInstruction *insn, TokenString *out);

#endif /* LIBHBC_TRANSLATOR_H */
