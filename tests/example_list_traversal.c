/**
 * @file example_list_traversal.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#ifdef __KERNEL__
#include <linux/list.h>
#else
struct list_head {
	struct list_head *next, *prev;
};
#endif

struct myLongList {
	int k;
	struct list_head v;
};

#ifdef __KERNEL__

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongList,24,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongList,24,v.next,8,1,-8);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongList,24,v.prev,16,1,-8);
);

static int kflat_list_test_iter(struct kflat *kflat) {
	int i, err = 0;
    struct list_head* head;
	struct myLongList myhead = {-1};

	INIT_LIST_HEAD(&myhead.v);
	head = &myhead.v;
	for (i = 0; i < 100; ++i) {
		struct myLongList* item = kvzalloc(sizeof(struct myLongList), GFP_KERNEL);
		item->k = i + 1;
		list_add(&item->v, head);
		head = &item->v;
	}

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&myhead,
			FLATTEN_STRUCT_ARRAY_ITER(myLongList,&myhead,1);
		);
	);

	while(!list_empty(&myhead.v)) {
		struct myLongList *entry = list_entry(myhead.v.next, struct myLongList, v);
		list_del(myhead.v.next);
		kvfree(entry);
	}
	return err;
}

#else

static int kflat_list_validate(void* memory, size_t size, CFlatten flatten) {
    struct list_head *p;
	size_t list_size = 0;
    struct myLongList* myhead = (struct myLongList*) memory;
    
    for (p = (&myhead->v)->next; p != (&myhead->v); p = p->next) {
        struct myLongList *entry = container_of(p, struct myLongList, v);
        list_size++;
        ASSERT(entry->k == list_size);
    }
    ASSERT(list_size == 100);

    return 0;
}

#endif

KFLAT_REGISTER_TEST("LONG_LIST", kflat_list_test_iter, kflat_list_validate);
