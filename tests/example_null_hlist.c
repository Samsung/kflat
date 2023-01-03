/**
 * @file example_padding.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"


#ifdef __KERNEL__
#include <linux/list_nulls.h>
#else
struct hlist_nulls_node {
	struct hlist_nulls_node *next, **pprev;
};
struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};
#endif

struct myLongHnullsList {
	int k;
	struct hlist_nulls_node n;
};



#ifdef __KERNEL__

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_nulls_node,16,
	if (!is_a_nulls(ATTR(next))) {
		AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16,next,0,1);
	}
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_nulls_node*,pprev,8,1);
	FOR_POINTER(struct hlist_nulls_node*,__pprev, OFFATTR(void**,8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16,__pprev,1);
	);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_head,8);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_nulls_head,8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16,first,0,1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHnullsList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongHnullsList,24,
	if (!is_a_nulls(ATTR(n).next)) {
		AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongHnullsList,24,n.next,8,1,-8);
	}
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_nulls_node*,n.pprev,8,1);
	FOR_POINTER(struct hlist_nulls_node*,__pprev, OFFATTR(void**,8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHnullsList,24,__pprev,1);
	);
);

static int kflat_hlist_nulls_test_iter(struct kflat *kflat) {

	struct hlist_nulls_head hnarr[5];
	int i, j;
	struct hlist_nulls_node *p;

	for (i = 0; i < 5; ++i) {
		INIT_HLIST_NULLS_HEAD(&hnarr[i],0);
		for (j = 0; j < 10; ++j) {
			struct myLongHnullsList* item = kvzalloc(sizeof(struct myLongHnullsList), GFP_KERNEL);
			item->k = i * 10 + j + 1;
			hlist_nulls_add_head(&item->n, &hnarr[i]);
		}
	}

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(hnarr,
			FLATTEN_STRUCT_ARRAY_ITER(hlist_nulls_head, hnarr, 5);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(hnarr,
			for (i = 0; i < 5; ++i) {
				struct myLongHnullsList *entry;
				hlist_nulls_for_each_entry(entry,p, &hnarr[i], n) {
					FLATTEN_STRUCT_ARRAY_ITER(myLongHnullsList, entry, 1);
				}
			}
		);
	);

	for(i = 0; i < 5; ++i) {
		while(!hlist_nulls_empty(&hnarr[i])) {
			struct myLongHnullsList *entry = hlist_nulls_entry(hnarr[i].first, struct myLongHnullsList, n);
			hlist_nulls_del(hnarr[i].first);
			kvfree(entry);
		}
	}
	return 0;
}

#else

static inline int is_a_nulls(const struct hlist_nulls_node *ptr) {
	return ((unsigned long)ptr & 1);
}

static int kflat_hlist_nulls_test_validate(void* memory, size_t size, CFlatten flatten) {
    int i;
    struct hlist_nulls_node *p;
    struct hlist_nulls_head* hnarr = (struct hlist_nulls_head*) flatten_root_pointer_seq(flatten, 0);

    for (i = 0; i < 5; ++i) {
        unsigned long list_size = 0;
        struct myLongHnullsList *entry;
        for (p = (&hnarr[i])->first;
                (!is_a_nulls(p)) && ({ entry = container_of(p, typeof(*entry), n); 1;});
                p = p->next) {
            ASSERT(entry->k == i * 10 + 10 - list_size);
            list_size++;
        }
        ASSERT(list_size == 10);
    }

    // TODO: Test 2nd root pointer
	
	return 0;
}

#endif


KFLAT_REGISTER_TEST("HNULLSLIST", kflat_hlist_nulls_test_iter, kflat_hlist_nulls_test_validate);
