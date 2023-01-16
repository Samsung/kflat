/**
 * @file example_padding.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#ifdef __KERNEL__
#include <linux/list_nulls.h>
#else
struct hlist_node {
	struct hlist_node *next, **pprev;
};
struct hlist_head {
	struct hlist_node *first;
};
#endif

struct myLongHList {
	int k;
	struct hlist_node r;
};

#ifdef __KERNEL__

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node, 16);
FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_node, 16,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node, 16, next, 0, 1);
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_node *, pprev, 8, 1);
	FOR_POINTER(struct hlist_node *, __pprev, OFFATTR(void **, 8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node, 16, __pprev, 1);
	);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_head, 8);
FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_head, 8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node, 16, first, 0, 1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHList, 24);
FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongHList, 24,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongHList, 24, r.next, 8, 1, -8);
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_node *, pprev, 8, 1);
	FOR_POINTER(struct hlist_node *, __pprev, OFFATTR(void **, 8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHList, 24, __pprev, 1);
	);
);

static int kflat_longhlist_test(struct kflat *kflat) {
	struct hlist_head harr[5];
	int i, j;
	struct hlist_node *p;

	for (i = 0; i < 5; ++i) {
		struct hlist_node *node;
		INIT_HLIST_HEAD(&harr[i]);
		node = harr[i].first;
		for (j = 0; j < 10; ++j) {
			struct myLongHList *item = kvzalloc(sizeof(struct myLongHList), GFP_KERNEL);
			item->k = i * 10 + j + 1;
			if (j == 0)
				hlist_add_head(&item->r, &harr[i]);
			else
				hlist_add_behind(&item->r, node);
			node = &item->r;
		}
	}

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(harr,
			FLATTEN_STRUCT_ARRAY_ITER(hlist_head, harr, 5);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(harr,
			for (i = 0; i < 5; ++i) {
				hlist_for_each(p, &harr[i]) {
					struct myLongHList *entry = hlist_entry(p, struct myLongHList, r);
					FLATTEN_STRUCT_ARRAY_ITER(myLongHList, entry, 1);
				}
			}
		);
	);

	for (i = 0; i < 5; ++i) {
		while (!hlist_empty(&harr[i])) {
			struct myLongHList *entry = hlist_entry(harr[i].first, struct myLongHList, r);
			hlist_del(harr[i].first);
			kvfree(entry);
		}
	}

	return 0;
	}

#else

static int kflat_longhlist_validate(void *memory, size_t size, CFlatten flatten) {
	int i;
	struct hlist_node *p;
	struct hlist_head *harr = (struct hlist_head *)flatten_root_pointer_seq(flatten, 0);

	for (i = 0; i < 5; ++i) {
		unsigned long list_size = 0;
		for (p = (&harr[i])->first; p; p = p->next) {
			struct myLongHList *entry = container_of(p, struct myLongHList, r);
			ASSERT(entry->k == i * 10 + list_size + 1);
			list_size++;
		}
		ASSERT(list_size == 10);
	}

	// TODO: Test 2nd root pointer

	return 0;
}

#endif

	KFLAT_REGISTER_TEST("LONGHLIST", kflat_longhlist_test, kflat_longhlist_validate);
