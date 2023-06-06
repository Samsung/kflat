/**
 * @file example_list_traversal.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#if defined(__VALIDATOR__) && !defined(__TESTER__)
struct list_head {
	struct list_head *next, *prev;
};
#endif

struct myLongList {
	int k;
	struct list_head v;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(myLongList, sizeof(struct myLongList));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(myLongList, sizeof(struct myLongList),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongList, sizeof(struct myLongList), v.next, offsetof(struct myLongList,v.next), 1, -offsetof(struct myLongList,v));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongList, sizeof(struct myLongList), v.prev, offsetof(struct myLongList,v.prev), 1, -offsetof(struct myLongList,v));
);

static int kflat_list_test(struct flat *flat) {
	int i, err = 0;
	struct list_head *head;
	struct myLongList myhead = { -1 };
	FLATTEN_SETUP_TEST(flat);

	INIT_LIST_HEAD(&myhead.v);
	head = &myhead.v;
	for (i = 0; i < 100; ++i) {
		struct myLongList *item = FLATTEN_BSP_ZALLOC(sizeof(struct myLongList));
		item->k = i + 1;
		list_add(&item->v, head);
		head = &item->v;
	}

	FOR_ROOT_POINTER(&myhead,
		FLATTEN_STRUCT_ARRAY(myLongList, &myhead, 1);
	);

	while (!list_empty(&myhead.v)) {
		struct myLongList *entry = list_entry(myhead.v.next, struct myLongList, v);
		list_del(myhead.v.next);
		FLATTEN_BSP_FREE(entry);
	}
	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_list_validate(void *memory, size_t size, CUnflatten flatten) {
	struct list_head *p;
	size_t list_size = 0;
	struct myLongList *myhead = (struct myLongList *)memory;

	for (p = (&myhead->v)->next; p != (&myhead->v); p = p->next) {
		struct myLongList *entry = container_of(p, struct myLongList, v);
		list_size++;
		ASSERT(entry->k == list_size);
	}
	ASSERT(list_size == 100);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("LONG_LIST", kflat_list_test, kflat_list_validate);
