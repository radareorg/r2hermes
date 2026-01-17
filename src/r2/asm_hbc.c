/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_asm.h>

/* Pseudo transformation rules for Hermes bytecode instructions */
static const char *pseudo_rules[] = {
	/* Mov/Load operations */
	"mov/2/$1 = $2",
	"mov_long/2/$1 = $2",
	"loadi8/2/$1 = (int8)$2",
	"loadu8/2/$1 = (uint8)$2",
	"loadi16/2/$1 = (int16)$2",
	"loadu16/2/$1 = (uint16)$2",
	"loadi32/2/$1 = (int32)$2",
	"loadu32/2/$1 = (uint32)$2",
	"load_const_uint8/2/$1 = $2",
	"load_const_u_int8/2/$1 = $2",
	"load_const_int/2/$1 = $2",
	"load_const_double/2/$1 = $2",
	"load_const_bigint/2/$1 = $2",
	"load_const_string/2/$1 = $2",
	"load_const_string_long_index/2/$1 = $2",
	"load_const_empty/1/$1 = empty",
	"load_const_undefined/1/$1 = undefined",
	"load_const_null/1/$1 = null",
	"load_const_true/1/$1 = true",
	"load_const_false/1/$1 = false",
	"load_const_zero/1/$1 = 0",

	/* Property access - get_by_id has 4 args: dest, obj, cache_idx, prop_name */
	"get_by_id/4/$1 = $2.$4",
	"get_by_id_long/4/$1 = $2.$4",
	"get_by_id_short/4/$1 = $2.$4",
	"get_by_val/3/$1 = $2[$3]",
	"put_by_id/4/$1.$4 = $3",
	"put_by_id_long/4/$1.$4 = $3",
	"put_by_val/3/$1[$2] = $3",
	"put_new_own_by_id/3/$1.$3 = $2",
	"put_new_own_by_id_short/3/$1.$3 = $2",
	"put_new_own_by_id_long/3/$1.$3 = $2",
	"put_new_own_ne_by_id/3/$1.$3 = $2",
	"put_new_own_ne_by_id_long/3/$1.$3 = $2",
	"try_get_by_id/4/$1 = try_get($2, $4)",
	"try_get_by_id_long/4/$1 = try_get($2, $4)",
	"try_put_by_id/4/try_put($1, $4, $3)",
	"try_put_by_id_long/4/try_put($1, $4, $3)",
	"del_by_id/3/delete $1.$3",
	"del_by_id_long/3/delete $1.$3",
	"del_by_val/3/delete $1[$2]",

	/* Arithmetic operations */
	"add/3/$1 = $2 + $3",
	"add_n/3/$1 = $2 + $3",
	"add_32/3/$1 = (int32)($2 + $3)",
	"add_empty_string/2/$1 = \"\" + $2",
	"sub/3/$1 = $2 - $3",
	"sub_n/3/$1 = $2 - $3",
	"sub_32/3/$1 = (int32)($2 - $3)",
	"mul/3/$1 = $2 * $3",
	"mul_n/3/$1 = $2 * $3",
	"mul_32/3/$1 = (int32)($2 * $3)",
	"div/3/$1 = $2 / $3",
	"div_n/3/$1 = $2 / $3",
	"divi32/3/$1 = (int32)($2 / $3)",
	"divu32/3/$1 = (uint32)($2 / $3)",
	"mod/3/$1 = $2 % $3",
	"inc/2/$1 = $2 + 1",
	"dec/2/$1 = $2 - 1",
	"negate/2/$1 = -$2",

	/* Bitwise operations */
	"bit_and/3/$1 = $2 & $3",
	"bit_or/3/$1 = $2 | $3",
	"bit_xor/3/$1 = $2 ^ $3",
	"bit_not/2/$1 = ~$2",
	"lshift/3/$1 = $2 << $3",
	"rshift/3/$1 = $2 >> $3",
	"urshift/3/$1 = (unsigned)$2 >> $3",

	/* Logical operations */
	"not/2/$1 = !$2",
	"eq/3/$1 = $2 == $3",
	"strict_eq/3/$1 = $2 === $3",
	"neq/3/$1 = $2 != $3",
	"strict_neq/3/$1 = $2 !== $3",
	"less/3/$1 = $2 < $3",
	"greater/3/$1 = $2 > $3",
	"less_eq/3/$1 = $2 <= $3",
	"greater_eq/3/$1 = $2 >= $3",

	/* Type operations */
	"typeof/2/$1 = typeof($2)",
	"is_in/3/$1 = ($2 in $3)",
	"instanceof/3/$1 = ($2 instanceof $3)",
	"to_number/2/$1 = Number($2)",
	"to_numeric/2/$1 = Numeric($2)",
	"to_int32/2/$1 = (int32)$2",

	/* Object/Array creation */
	"new_object/1/$1 = {}",
	"new_object_with_parent/2/$1 = Object.create($2)",
	"new_object_with_buffer/5/$1 = {/*buffer*/}",
	"new_object_with_buffer_long/5/$1 = {/*buffer*/}",
	"new_array/2/$1 = []",
	"new_array_with_buffer/4/$1 = [/*buffer*/]",
	"new_array_with_buffer_long/4/$1 = [/*buffer*/]",
	"create_closure/3/$1 = closure($3)",
	"create_closure_long_index/3/$1 = closure($3)",
	"create_generator_closure/3/$1 = gen_closure($3)",
	"create_generator/3/$1 = generator($3)",
	"create_regexp/3/$1 = regexp($3)",

	/* Control flow */
	"unreachable/0/unreachable",
	"jmp/1/goto $1",
	"jmp_long/1/goto $1",
	"name/3/if ($2) goto $1",
	"name##_long/2/if ($2) goto $1",
	"jmp_true/2/if ($2) goto $1",
	"jmp_true_long/2/if ($2) goto $1",
	"jmp_false/2/if (!$2) goto $1",
	"jmp_false_long/2/if (!$2) goto $1",
	"jmp_undefined/2/if ($2 === undefined) goto $1",
	"jmp_undefined_long/2/if ($2 === undefined) goto $1",
	"jless/3/if ($1 < $2) goto $3",
	"jless_long/3/if ($1 < $2) goto $3",
	"jless_eq/3/if ($1 <= $2) goto $3",
	"jless_eq_long/3/if ($1 <= $2) goto $3",
	"jgreater/3/if ($1 > $2) goto $3",
	"jgreater_long/3/if ($1 > $2) goto $3",
	"jgreater_eq/3/if ($1 >= $2) goto $3",
	"jgreater_eq_long/3/if ($1 >= $2) goto $3",
	"jequal/3/if ($1 == $2) goto $3",
	"jequal_long/3/if ($1 == $2) goto $3",
	"jstrict_equal/3/if ($1 === $2) goto $3",
	"jstrict_equal_long/3/if ($1 === $2) goto $3",
	"jnot_equal/3/if ($1 != $2) goto $3",
	"jnot_equal_long/3/if ($1 != $2) goto $3",
	"jstrict_not_equal/3/if ($1 !== $2) goto $3",
	"jstrict_not_equal_long/3/if ($1 !== $2) goto $3",

	/* Function calls and returns */
	/* call: result = callee (this, args...) */
	"call/2/$1($2)",
	"call1/3/$1 = $2($3)",
	"call2/4/$1 = $2($4)",
	"call3/5/$1 = $2($4, $5)",
	"call4/6/$1 = $2($4, $5, $6)",
	"call_long/2/$1($2)",
	"call_builtin/3/$1 = builtin.$2($3)",
	"call_builtin_long/3/$1 = builtin.$2($3)",
	"call_direct/3/$1 = $2($3)",
	"call_direct_long_index/3/$1 = $2($3)",
	"construct/3/$1 = new $2($3)",
	"construct_long/3/$1 = new $2($3)",
	"ret/1/return $1",
	"ret_undefined/0/return",

	/* Exception handling */
	"throw/1/throw $1",
	"throw_if_empty/2/if (empty($1)) throw $2",
	"catch/2/$1 = catch $2",

	/* Parameter handling */
	"load_param/2/$1 = param[$2]",
	"load_param_long/2/$1 = param[$2]",
	"reify_arguments/1/arguments = reify($1)",
	"get_arguments_length/2/$1 = arguments.length",
	"get_arguments_prop_by_val/3/$1 = arguments[$2]",

	/* Environment operations */
	"get_environment/2/$1 = env[$2]",
	"load_from_environment/3/$1 = $2[$3]",
	"load_from_environment_l/3/$1 = $2[$3]",
	"store_to_environment/3/$2[$3] = $1",
	"store_to_environment_l/3/$2[$3] = $1",
	"store_np_to_environment/3/$2[$3] = $1",
	"store_np_to_environment_l/3/$2[$3] = $1",
	"create_environment/1/$1 = new_env()",
	"create_inner_environment/1/$1 = new_inner_env()",

	/* Generator operations */
	"start_generator/0/start_generator()",
	"resume_generator/2/$1 = resume_generator($2)",
	"save_generator/1/save_generator($1)",
	"complete_generator/0/complete_generator()",

	/* Miscellaneous */
	"debugger/0/debugger",
	"profile_point/1/profile($1)",
	"select_object/3/$1 = select($2, $3)",
	"catch/2/$1 = catch_value($2)",
	"get_builtin_closure/2/$1 = builtin_closure($2)",
	"get_global_object/1/$1 = global",
	"get_new_target/1/$1 = new.target",
	"get_this_ns/1/$1 = this",
	"coerce_this_ns/1/$1 = coerce_this()",

	/* Iterator operations */
	"iterator_begin/2/$1 = iterator_begin($2)",
	"iterator_next/3/$1 = iterator_next($2, $3)",
	"iterator_close/2/iterator_close($1, $2)",
	"get_pname_list/2/$1 = property_names($2)",
	"get_next_pname/4/$1 = next_property_name($2, $3, $4)",

	/* Switch */
	"switch_imm/3/switch($1) { cases in $2 }",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	(void)aps;
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_r2hermes = {
	.meta = {
		.name = "hbc.pseudo",
		.desc = "Hermes bytecode pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
