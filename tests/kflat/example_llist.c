/**
 * @file example_llist.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#if defined(__TESTER__)
#include <linux/llist.h>
#elif defined(__VALIDATOR__)
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
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(llist_node, sizeof(struct llist_node));
FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(llist_node, sizeof(struct llist_node),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(llist_node, sizeof(struct llist_node), next, offsetof(struct llist_node,next), 1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(llist_head, sizeof(struct llist_head));
FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(llist_head, sizeof(struct llist_head),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(llist_node, sizeof(struct llist_node), first, offsetof(struct llist_head,first), 1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(myLongLList, sizeof(struct myLongLList));
FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(myLongLList, sizeof(struct myLongLList),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongLList, sizeof(struct myLongLList), l.next, offsetof(struct myLongLList,l.next), 1, -offsetof(struct myLongLList,l));
);

static int kflat_llist_test(struct flat *flat) {
	struct llist_head lhead;
	int i;
	struct llist_node *p;

	FLATTEN_SETUP_TEST(flat);

	init_llist_head(&lhead);
	for (i = 0; i < 10; ++i) {
		struct myLongLList *item = kvzalloc(sizeof(struct myLongLList), GFP_KERNEL);
		item->k = i + 1;
		llist_add(&item->l, &lhead);
	}

	FOR_ROOT_POINTER(&lhead,
		FLATTEN_STRUCT_ARRAY(llist_head, &lhead, 1);
	);

	FOR_ROOT_POINTER(&lhead,
		llist_for_each (p, lhead.first) {
			struct myLongLList *entry = llist_entry(p, struct myLongLList, l);
			FLATTEN_STRUCT_ARRAY(myLongLList, entry, 1);
		}
	);

	while (!(llist_empty(&lhead))) {
		struct myLongLList *entry = llist_entry(lhead.first, struct myLongLList, l);
		llist_del_first(&lhead);
		kvfree(entry);
	}

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_llist_test_validate(void *memory, size_t size, CUnflatten flatten) {
	size_t list_size = 0;
	struct llist_node *p;
	struct llist_head *lhead = (struct llist_head *)unflatten_root_pointer_seq(flatten, 0);
	struct llist_head *lhead2 = (struct llist_head *)unflatten_root_pointer_seq(flatten, 1);

	for ((p) = (lhead->first); p; (p) = (p)->next) {
		struct myLongLList *entry = container_of(p, struct myLongLList, l);
		ASSERT(entry->k == 10 - list_size);
		list_size++;
	}
	ASSERT(list_size == 10);

	list_size = 0;
	for ((p) = (lhead2->first); p; (p) = (p)->next) {
		struct myLongLList *entry = container_of(p, struct myLongLList, l);
		ASSERT(entry->k == 10 - list_size);
		list_size++;
	}
	ASSERT(list_size == 10);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("LLIST", kflat_llist_test, kflat_llist_test_validate);
