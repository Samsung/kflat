/**
 * @file example_large_list.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#define LIST_ELEMENT_COUNT	3000

#ifdef __KERNEL__
#include <linux/list.h>
#else
struct list_head {
	struct list_head *next, *prev;
};
#endif

struct myLongLargeList {
	int k;
	struct list_head v;
};

/********************************/
#ifdef __KERNEL__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(myLongLargeList, sizeof(struct myLongLargeList));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(myLongLargeList, sizeof(struct myLongLargeList),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongLargeList, sizeof(struct myLongLargeList), v.next, offsetof(struct myLongLargeList,v.next), 1, -offsetof(struct myLongLargeList,v));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongLargeList, sizeof(struct myLongLargeList), v.prev, offsetof(struct myLongLargeList,v.prev), 1, -offsetof(struct myLongLargeList,v));
);

static int kflat_large_list_test(struct kflat *kflat) {
	int i, err = 0;
	struct list_head *head;
	struct myLongLargeList myhead = { -1 };

	INIT_LIST_HEAD(&myhead.v);
	head = &myhead.v;
	for (i = 0; i < LIST_ELEMENT_COUNT; ++i) {
		struct myLongLargeList *item = kflat_zalloc(kflat,sizeof(struct myLongLargeList), 1);
		item->k = i + 1;
		list_add(&item->v, head);
		head = &item->v;
	}

	FOR_ROOT_POINTER(&myhead,
		FLATTEN_STRUCT_ARRAY(myLongLargeList, &myhead, 1);
	);

	while (!list_empty(&myhead.v)) {
		list_del(myhead.v.next);
	}
	return err;
}

/********************************/
#else
/********************************/

static int kflat_large_list_validate(void *memory, size_t size, CUnflatten flatten) {
	struct list_head *p;
	size_t list_size = 0;
	struct myLongLargeList *myhead = (struct myLongLargeList *)memory;
	int sum = 0;

	for (p = (&myhead->v)->next; p != (&myhead->v); p = p->next) {
		struct myLongLargeList *entry = container_of(p, struct myLongLargeList, v);
		list_size++;
		sum+=entry->k;
		ASSERT(entry->k == list_size);
	}
	ASSERT(list_size == LIST_ELEMENT_COUNT);
	ASSERT(sum == ((1+LIST_ELEMENT_COUNT)*(LIST_ELEMENT_COUNT))/2);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif
/********************************/

KFLAT_REGISTER_TEST_FLAGS("LARGE_LIST", kflat_large_list_test, kflat_large_list_validate,KFLAT_TEST_ATOMIC);
