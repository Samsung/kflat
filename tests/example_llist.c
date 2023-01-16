/**
 * @file example_llist.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#ifdef __KERNEL__
#include <linux/llist.h>
#else
struct llist_node {
	struct llist_node *next;
};

struct llist_head {
	struct llist_node *first;
};
#endif

struct myLongLList {
	int k;
	struct llist_node l;
};

/********************************/
#ifdef __KERNEL__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_node, 8);
FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(llist_node, 8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_node, 8, next, 0, 1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_head, 8);
FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(llist_head, 8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_node, 8, first, 0, 1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongLList, 24);
FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongLList, 16,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongLList, 16, l.next, 8, 1, -8);
);

static int kflat_llist_test_iter(struct kflat *kflat) {
	struct llist_head lhead;
	int i;
	struct llist_node *p;

	init_llist_head(&lhead);
	for (i = 0; i < 10; ++i) {
		struct myLongLList *item = kvzalloc(sizeof(struct myLongLList), GFP_KERNEL);
		item->k = i + 1;
		llist_add(&item->l, &lhead);
	}

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&lhead,
			FLATTEN_STRUCT_ARRAY_ITER(llist_head, &lhead, 1);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&lhead,
			llist_for_each (p, lhead.first) {
				struct myLongLList *entry = llist_entry(p, struct myLongLList, l);
				FLATTEN_STRUCT_ARRAY_ITER(myLongLList, entry, 1);
			}
		);
	);

	while (!(llist_empty(&lhead))) {
		struct myLongLList *entry = llist_entry(lhead.first, struct myLongLList, l);
		llist_del_first(&lhead);
		kvfree(entry);
	}

	return 0;
}

/********************************/
#else
/********************************/

static int kflat_llist_test_validate(void *memory, size_t size, CFlatten flatten) {
	size_t list_size = 0;
	struct llist_node *p;
	struct llist_head *lhead = (struct llist_head *)flatten_root_pointer_seq(flatten, 0);

	for ((p) = (lhead->first); p; (p) = (p)->next) {
		struct myLongLList *entry = container_of(p, struct myLongLList, l);
		ASSERT(entry->k == 10 - list_size);
		list_size++;
	}
	ASSERT(list_size == 10);

	// TODO: Test 2nd root pointer

	return 0;
}

/********************************/
#endif
/********************************/

KFLAT_REGISTER_TEST("LLIST", kflat_llist_test_iter, kflat_llist_test_validate);
