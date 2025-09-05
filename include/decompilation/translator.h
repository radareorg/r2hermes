#ifndef HERMES_DEC_TRANSLATOR_H
#define HERMES_DEC_TRANSLATOR_H

#include "../common.h"
#include "../parsers/hbc_bytecode_parser.h"
#include "token.h"

/* Translate a single parsed instruction into a TokenString */
Result translate_instruction_to_tokens(const ParsedInstruction* insn, TokenString* out);

#endif /* HERMES_DEC_TRANSLATOR_H */

