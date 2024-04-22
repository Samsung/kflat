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

struct linux_list_head {
	struct linux_list_head* next;
	struct linux_list_head* prev;
};

struct dbg_dump {
	const char* dbg_name;
	unsigned long version;
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

FUNCTION_DECLARE_FLATTEN_STRUCT(linux_list_head);
FUNCTION_DEFINE_FLATTEN_STRUCT(linux_list_head,
	AGGREGATE_FLATTEN_STRUCT(linux_list_head, next);
	AGGREGATE_FLATTEN_STRUCT(linux_list_head, prev);
);

FUNCTION_DECLARE_FLATTEN_STRUCT(dbg_dump);
FUNCTION_DEFINE_FLATTEN_STRUCT(dbg_dump,
	AGGREGATE_FLATTEN_STRING(dbg_name);
);

static struct linux_list_head global_linux_list = {&global_linux_list,&global_linux_list};

static struct dbg_dump *p_dbg_dump;

static int kflat_unflatten_replace_unit_test(struct flat *flat) {

	struct replace_test tests[10];
	struct replace_test replace_target = {
		.str = "Hello dummy world!",
		.integer = 213,
		.old = &tests[0],
		.new = &tests[5],
		.another = &replace_target
	};
	struct dbg_dump dbg_dump = {"dbg_dump",0xBABADEDE};
	void* p_dbg_dump_addr = &p_dbg_dump;

	FLATTEN_SETUP_TEST(flat);

	for(int i = 0; i < 10; i++) {
		tests[i].str = strs[i % 3];
		tests[i].integer = i * 20;
		tests[i].new = &tests[(i + 1) % 10];
		tests[i].old = &tests[(i + 9) % 10];
		tests[i].another = &replace_target;
	}
	p_dbg_dump = &dbg_dump;

	FOR_ROOT_POINTER(&tests[0],
		FLATTEN_STRUCT(replace_test, &tests[0]);
	);

	FOR_ROOT_POINTER(&replace_target,
		FLATTEN_STRUCT(replace_test, &replace_target);
	);

	FOR_ROOT_POINTER(&global_linux_list,
		FLATTEN_STRUCT(linux_list_head, &global_linux_list);
	);

	FOR_EXTENDED_ROOT_POINTER(p_dbg_dump_addr,"p_dbg_dump",sizeof(struct dbg_dump*),
		FOREACH_POINTER(struct dbg_dump*,__p_dbg_dump_1,__root_ptr,1,
			FLATTEN_STRUCT(dbg_dump,__p_dbg_dump_1);
		);
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

static struct linux_list_head replace_global_linux_list = {(void*)0xCAFECAFE,(void*)0xDEADBEEF};

static int kflat_unflatten_replace_unit_validate(void *memory, size_t size, CUnflatten flatten) {

	struct replace_test* tests = (struct replace_test*)unflatten_root_pointer_seq(flatten, 0);
	struct replace_test* replace_target = (struct replace_test*)unflatten_root_pointer_seq(flatten, 1);
	struct linux_list_head* replace_list = (struct linux_list_head*)unflatten_root_pointer_seq(flatten, 2);

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

	// Now replace the list structure to see if internal pointers to itself were properly replaced as well
	result = unflatten_replace_variable(flatten, replace_list, &replace_global_linux_list, sizeof(struct linux_list_head));
	ASSERT(result > 0);
	memcpy(&replace_global_linux_list,replace_list,sizeof(struct linux_list_head));
	ASSERT(replace_global_linux_list.next==&replace_global_linux_list);
	ASSERT(replace_global_linux_list.prev==&replace_global_linux_list);

	// Check the global pointer
	struct dbg_dump** p_dbg_dump = (struct dbg_dump**)unflatten_root_pointer_seq(flatten, 3);
	ASSERT(!strcmp((*p_dbg_dump)->dbg_name, "dbg_dump"));
	ASSERT_EQ((*p_dbg_dump)->version,0xBABADEDE);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] unflatten_replace_variable", kflat_unflatten_replace_unit_test, kflat_unflatten_replace_unit_validate, KFLAT_TEST_ATOMIC);
