/* radare2 - LGPL - Copyright 2025 - libhbc */

#include <r_asm.h>
#include <r_util.h>
#include <r_lib.h>
#include <string.h>

#ifndef R2_VERSION
#define R2_VERSION "6.0.3"
#endif

/* Pseudo transformation rules for Hermes bytecode instructions */
static const char *pseudo_rules[] = {
	/* Mov/Load operations */
	"Mov/2/$1 = $2",
	"MovLong/2/$1 = $2",
	"Loadi8/2/$1 = (int8)$2",
	"Loadu8/2/$1 = (uint8)$2",
	"Loadi16/2/$1 = (int16)$2",
	"Loadu16/2/$1 = (uint16)$2",
	"Loadi32/2/$1 = (int32)$2",
	"Loadu32/2/$1 = (uint32)$2",
	"LoadConstUInt8/2/$1 = $2",
	"LoadConstInt/2/$1 = $2",
	"LoadConstDouble/2/$1 = $2",
	"LoadConstBigInt/2/$1 = $2",
	"LoadConstString/2/$1 = $2",
	"LoadConstEmpty/1/$1 = empty",
	"LoadConstUndefined/1/$1 = undefined",
	"LoadConstNull/1/$1 = null",
	"LoadConstTrue/1/$1 = true",
	"LoadConstFalse/1/$1 = false",
	"LoadConstZero/1/$1 = 0",

	/* Property access */
	"GetById/3/$1 = $2[$3]",
	"GetByIdLong/3/$1 = $2[$3]",
	"GetByIdShort/3/$1 = $2[$3]",
	"GetByVal/3/$1 = $2[$3]",
	"PutById/3/$1[$2] = $3",
	"PutByIdLong/3/$1[$2] = $3",
	"PutByVal/3/$1[$2] = $3",
	"TryGetById/3/$1 = try_get($2, $3)",
	"TryGetByIdLong/3/$1 = try_get($2, $3)",
	"TryPutById/3/try_put($1, $2, $3)",
	"TryPutByIdLong/3/try_put($1, $2, $3)",
	"DelById/2/delete $1[$2]",
	"DelByIdLong/2/delete $1[$2]",
	"DelByVal/2/delete $1[$2]",

	/* Arithmetic operations */
	"Add/3/$1 = $2 + $3",
	"AddN/3/$1 = $2 + $3",
	"Add32/3/$1 = (int32)($2 + $3)",
	"AddEmptyString/2/$1 = \"\" + $2",
	"Sub/3/$1 = $2 - $3",
	"SubN/3/$1 = $2 - $3",
	"Sub32/3/$1 = (int32)($2 - $3)",
	"Mul/3/$1 = $2 * $3",
	"MulN/3/$1 = $2 * $3",
	"Mul32/3/$1 = (int32)($2 * $3)",
	"Div/3/$1 = $2 / $3",
	"DivN/3/$1 = $2 / $3",
	"Divi32/3/$1 = (int32)($2 / $3)",
	"Divu32/3/$1 = (uint32)($2 / $3)",
	"Mod/3/$1 = $2 % $3",
	"Inc/2/$1 = $2 + 1",
	"Dec/2/$1 = $2 - 1",
	"Negate/2/$1 = -$2",

	/* Bitwise operations */
	"BitAnd/3/$1 = $2 & $3",
	"BitOr/3/$1 = $2 | $3",
	"BitXor/3/$1 = $2 ^ $3",
	"BitNot/2/$1 = ~$2",
	"LShift/3/$1 = $2 << $3",
	"RShift/3/$1 = $2 >> $3",
	"URshift/3/$1 = (unsigned)$2 >> $3",

	/* Logical operations */
	"Not/2/$1 = !$2",
	"Eq/3/$1 = $2 == $3",
	"StrictEq/3/$1 = $2 === $3",
	"Neq/3/$1 = $2 != $3",
	"StrictNeq/3/$1 = $2 !== $3",
	"Less/3/$1 = $2 < $3",
	"Greater/3/$1 = $2 > $3",
	"LessEq/3/$1 = $2 <= $3",
	"GreaterEq/3/$1 = $2 >= $3",

	/* Type operations */
	"TypeOf/2/$1 = typeof($2)",
	"IsIn/3/$1 = ($2 in $3)",
	"InstanceOf/3/$1 = ($2 instanceof $3)",
	"ToNumber/2/$1 = Number($2)",
	"ToNumeric/2/$1 = Numeric($2)",
	"ToInt32/2/$1 = (int32)$2",

	/* Object/Array creation */
	"NewObject/1/$1 = {}",
	"NewObjectWithParent/2/$1 = Object.create($2)",
	"NewArray/1/$1 = []",
	"NewArrayWithBuffer/2/$1 = Array.from($2)",
	"CreateClosure/2/$1 = closure($2)",
	"CreateClosureLongIndex/2/$1 = closure($2)",
	"CreateRegExp/2/$1 = /regex/$2",

	/* Control flow */
	"Jmp/1/goto $1",
	"JmpLong/1/goto $1",
	"JmpTrue/2/if ($1) goto $2",
	"JmpTrueLong/2/if ($1) goto $2",
	"JmpFalse/2/if (!$1) goto $2",
	"JmpFalseLong/2/if (!$1) goto $2",
	"JmpUndefined/2/if ($1 === undefined) goto $2",
	"JmpUndefinedLong/2/if ($1 === undefined) goto $2",
	"JLess/3/if ($1 < $2) goto $3",
	"JLessLong/3/if ($1 < $2) goto $3",
	"JLessEq/3/if ($1 <= $2) goto $3",
	"JLessEqLong/3/if ($1 <= $2) goto $3",
	"JGreater/3/if ($1 > $2) goto $3",
	"JGreaterLong/3/if ($1 > $2) goto $3",
	"JGreaterEq/3/if ($1 >= $2) goto $3",
	"JGreaterEqLong/3/if ($1 >= $2) goto $3",
	"JEqual/3/if ($1 == $2) goto $3",
	"JEqualLong/3/if ($1 == $2) goto $3",
	"JStrictEqual/3/if ($1 === $2) goto $3",
	"JStrictEqualLong/3/if ($1 === $2) goto $3",
	"JNotEqual/3/if ($1 != $2) goto $3",
	"JNotEqualLong/3/if ($1 != $2) goto $3",
	"JStrictNotEqual/3/if ($1 !== $2) goto $3",
	"JStrictNotEqualLong/3/if ($1 !== $2) goto $3",

	/* Function calls and returns */
	"Call/2/$1($2)",
	"CallBuiltin/2/$1($2)",
	"Ret/1/return $1",
	"RetUndefined/0/return",

	/* Exception handling */
	"Throw/1/throw $1",
	"ThrowIfEmpty/2/if (empty($1)) throw $2",
	"Catch/2/$1 = catch $2",

	/* Parameter handling */
	"LoadParam/2/$1 = param[$2]",
	"LoadParamLong/2/$1 = param[$2]",
	"ReifyArguments/1/arguments = reify($1)",
	"GetArgumentsLength/2/$1 = arguments.length",
	"GetArgumentsPropByVal/3/$1 = arguments[$2]",

	/* Environment operations */
	"GetEnvironment/1/$1 = environment",
	"LoadFromEnvironment/2/$1 = env[$2]",
	"LoadFromEnvironmentL/2/$1 = env[$2]",
	"StoreToEnvironment/2/env[$1] = $2",
	"StoreToEnvironmentL/2/env[$1] = $2",
	"CreateEnvironment/2/env = create_env($1, $2)",
	"CreateInnerEnvironment/2/env = create_inner_env($1, $2)",

	/* Generator operations */
	"StartGenerator/1/$1 = start_generator()",
	"ResumeGenerator/2/$1 = resume_generator($2)",
	"SaveGenerator/1/save_generator($1)",

	/* Miscellaneous */
	"Debugger/0/debugger",
	"ProfilePoint/1/profile($1)",
	"SelectObject/3/$1 = select($2, $3)",
	"Catch/2/$1 = catch_value($2)",
	"GetBuiltinClosure/2/$1 = builtin_closure($2)",
	"GetGlobalObject/1/$1 = global",
	"GetNewTarget/1/$1 = new.target",
	"GetThisNS/1/$1 = this",
	"CoerceThisNS/1/$1 = coerce_this()",

	/* Iterator operations */
	"IteratorBegin/2/$1 = iterator_begin($2)",
	"IteratorNext/3/$1 = iterator_next($2, $3)",
	"IteratorClose/2/iterator_close($1, $2)",
	"GetPNameList/2/$1 = property_names($2)",
	"GetNextPName/4/$1 = next_property_name($2, $3, $4)",

	/* Switch */
	"SwitchImm/3/switch($1) { cases in $2 }",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	(void)aps;
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_hbc = {
	.meta = {
		.name = "hbc.asm",
		.desc = "Hermes bytecode pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_hbc,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
