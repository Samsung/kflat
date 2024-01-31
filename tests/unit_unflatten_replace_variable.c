/**
 * @file unit_unflatten_replace_variable.c
 * @author Samsung R&D Poland - Mobile Security Group
 *
 */

#include "common.h"


struct replace_test;
struct replace_test {
	struct replace_test *new, *old;
	unsigned long long integer;
	const char* str;
	struct replace_test* another;
};

static const char* strs[3] = {
	"test1", "test_some_else", "literally-anything"
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(replace_test);
FUNCTION_DEFINE_FLATTEN_STRUCT(replace_test,
	AGGREGATE_FLATTEN_STRUCT(replace_test, new);
	AGGREGATE_FLATTEN_STRUCT(replace_test, old);
	AGGREGATE_FLATTEN_STRUCT(replace_test, another);
	AGGREGATE_FLATTEN_STRING(str);
);

static int kflat_unflatten_replace_unit_test(struct flat *flat) {

	struct replace_test tests[10];
	struct replace_test replace_target = {
		.str = "Hello dummy world!",
		.integer = 213,
		.old = &tests[0],
		.new = &tests[5],
		.another = &replace_target
	};

	FLATTEN_SETUP_TEST(flat);

	for(int i = 0; i < 10; i++) {
		tests[i].str = strs[i % 3];
		tests[i].integer = i * 20;
		tests[i].new = &tests[(i + 1) % 10];
		tests[i].old = &tests[(i + 9) % 10];
		tests[i].another = &replace_target;
	}

	FOR_ROOT_POINTER(&tests[0],
		FLATTEN_STRUCT(replace_test, &tests[0]);
	);

	FOR_ROOT_POINTER(&replace_target,
		FLATTEN_STRUCT(replace_test, &replace_target);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static struct replace_test my_global = {
	.str = "My local new string!",
	.integer = 4567,
	.old = (struct replace_test*) 0x1234,
	.new = (struct replace_test*) 0x4444,
	.another = (struct replace_test*) 0x6666
};

static int kflat_unflatten_replace_unit_validate(void *memory, size_t size, CUnflatten flatten) {

	struct replace_test* tests = (struct replace_test*)unflatten_root_pointer_seq(flatten, 0);
	struct replace_test* replace_target = (struct replace_test*)unflatten_root_pointer_seq(flatten, 1);

	for(int i = 0; i < 10; i++) {
		ASSERT(!strcmp(tests[i].str, strs[i % 3]));
		ASSERT_EQ(tests[i].integer, i * 20);
		ASSERT_EQ(tests[i].another, replace_target);
		ASSERT_EQ(tests[i].new, &tests[(i + 1) % 10]);
		ASSERT_EQ(tests[i].old, &tests[(i + 9) % 10]);
	}
	ASSERT_EQ(replace_target->another, replace_target);

	// Replace all pointers to `replace_target` with `my_global` variable
	ssize_t result = unflatten_replace_variable(flatten, replace_target, &my_global, sizeof(struct replace_test));
	ASSERT(result > 0);

	struct replace_test* target_after_replace = (struct replace_test*)unflatten_root_pointer_seq(flatten, 1);
	ASSERT_EQ(target_after_replace, &my_global);

	for(int i = 0; i < 10; i++) {
		ASSERT(!strcmp(tests[i].str, strs[i % 3]));
		ASSERT_EQ(tests[i].integer, i * 20);
		ASSERT_EQ(tests[i].another, &my_global);
		ASSERT_EQ(tests[i].new, &tests[(i + 1) % 10]);
		ASSERT_EQ(tests[i].old, &tests[(i + 9) % 10]);
	}

	// Verify that the content of global variable have been preserved
	ASSERT_EQ(my_global.integer, 4567);
	ASSERT(!strcmp(my_global.str, "My local new string!"));
	ASSERT_EQ(my_global.old, (struct replace_test*) 0x1234);
	ASSERT_EQ(my_global.new, (struct replace_test*) 0x4444);
	ASSERT_EQ(my_global.another, (struct replace_test*) 0x6666);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] unflatten_replace_variable", kflat_unflatten_replace_unit_test, kflat_unflatten_replace_unit_validate, KFLAT_TEST_ATOMIC);
