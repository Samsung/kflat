/**
 * @file unit_flatten_struct_array_specialize.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

// Common structures
struct spec_array {
	union {
		int *integers;
		char *string;
		size_t magic;
	};
};

/********************************/
#ifdef __KERNEL__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(ints, spec_array, sizeof(struct spec_array),
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(int, integers, offsetof(struct spec_array, integers), 10);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(strs, spec_array, sizeof(struct spec_array),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(string, offsetof(struct spec_array, string));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(magic, spec_array, sizeof(struct spec_array));

static int kflat_flatten_struct_array_specialize_unit_test(struct kflat *kflat) {
	int numbers[10];
	char *str = "Hello kflat!";
	struct spec_array spec_int, spec_str, spec_magic;

	for (int i = 0; i < 10; i++)
		numbers[i] = (2 * i) % 7;

	spec_int.integers = numbers;
	spec_str.string = str;
	spec_magic.magic = 0xCAFECAFE;

	FOR_ROOT_POINTER(&spec_int,
		FLATTEN_STRUCT_ARRAY_SPECIALIZE(ints, spec_array, &spec_int, 1);
	);

	FOR_ROOT_POINTER(&spec_str,
		FLATTEN_STRUCT_ARRAY_SPECIALIZE(strs, spec_array, &spec_str, 1);
	);

	FOR_ROOT_POINTER(&spec_magic,
		FLATTEN_STRUCT_ARRAY_SPECIALIZE(magic, spec_array, &spec_magic, 1);
	);

	return 0;
}

/********************************/
#else
/********************************/

static int kflat_flatten_struct_array_specialize_unit_validate(void *memory, size_t size, CFlatten flatten) {
	struct spec_array *spec_int = flatten_root_pointer_seq(flatten, 0);
	struct spec_array *spec_str = flatten_root_pointer_seq(flatten, 1);
	struct spec_array *spec_magic = flatten_root_pointer_seq(flatten, 2);

	ASSERT(spec_int != NULL);
	ASSERT(spec_str != NULL);
	ASSERT(spec_magic != NULL);

	for (int i = 0; i < 10; i++)
		ASSERT(spec_int->integers[i] == (2 * i) % 7);
	ASSERT(!strcmp(spec_str->string, "Hello kflat!"));
	ASSERT(spec_magic->magic == 0xCAFECAFE);

	return 0;
}

/********************************/
#endif
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_struct_array_specialize", kflat_flatten_struct_array_specialize_unit_test, kflat_flatten_struct_array_specialize_unit_validate);
