/**
 * @file example_my_list_head.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct my_list_head {
	struct my_list_head *prev;
	struct my_list_head *next;
};

struct intermediate {
	struct my_list_head *plh;
};

struct my_task_struct {
	int pid;
	struct intermediate *im;
	struct my_list_head u;
	float w;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(my_list_head);

/* RECURSIVE version */
FUNCTION_DEFINE_FLATTEN_STRUCT(my_list_head,
	AGGREGATE_FLATTEN_STRUCT(my_list_head, prev);
	AGGREGATE_FLATTEN_STRUCT(my_list_head, next);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(intermediate,
	AGGREGATE_FLATTEN_STRUCT(my_list_head, plh);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(my_task_struct,
	AGGREGATE_FLATTEN_STRUCT(intermediate, im);
	AGGREGATE_FLATTEN_STRUCT(my_list_head, u.prev);
	AGGREGATE_FLATTEN_STRUCT(my_list_head, u.next);
);

static int kflat_overlaplist_test(struct flat *flat) {
	int err = 0;
	struct my_task_struct T;
	struct intermediate IM = { &T.u };

	FLATTEN_SETUP_TEST(flat);

	T.pid = 123;
	T.im = &IM;
	T.u.prev = T.u.next = &T.u;
	T.w = 1.0;

	FOR_ROOT_POINTER(&T,
		FLATTEN_STRUCT(my_task_struct, &T);
	);

	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_overlaplist_validate(void *memory, size_t size, CUnflatten flatten) {
	struct my_task_struct *task = (struct my_task_struct *)memory;
	ASSERT(task->pid == 123);
	ASSERT(task->w == 1.0);
	ASSERT(task->u.next == task->u.prev);
	ASSERT(task->u.next == &task->u);
	ASSERT(task->im->plh == &task->u);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("OVERLAP_LIST", kflat_overlaplist_test, kflat_overlaplist_validate, KFLAT_TEST_ATOMIC);
