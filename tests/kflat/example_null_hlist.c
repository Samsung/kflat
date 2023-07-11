/**
 * @file example_padding.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#ifdef __TESTER__
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

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(hlist_nulls_node, sizeof(struct hlist_nulls_node));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(hlist_nulls_node, sizeof(struct hlist_nulls_node),
	if (!is_a_nulls(ATTR(next))) {
		AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(hlist_nulls_node, sizeof(struct hlist_nulls_node), next, offsetof(struct hlist_nulls_node,next), 1);
	} 
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_nulls_node *, pprev, offsetof(struct hlist_nulls_node,pprev), 1);
	FOR_POINTER(struct hlist_nulls_node *, __pprev, OFFATTR(void **, offsetof(struct hlist_nulls_node,pprev)),
		FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(hlist_nulls_node, sizeof(struct hlist_nulls_node), __pprev, 1);
	);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(hlist_nulls_head, sizeof(struct hlist_nulls_head));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(hlist_nulls_head, sizeof(struct hlist_nulls_head),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(hlist_nulls_node, sizeof(struct hlist_nulls_node), first, offsetof(struct hlist_nulls_head,first), 1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(myLongHnullsList, sizeof(struct myLongHnullsList));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(myLongHnullsList, sizeof(struct myLongHnullsList),
	if (!is_a_nulls(ATTR(n).next)) {
		AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongHnullsList, sizeof(struct myLongHnullsList), n.next, offsetof(struct myLongHnullsList,n.next), 1, -offsetof(struct myLongHnullsList,n));
	} 
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_nulls_node *, n.pprev, offsetof(struct myLongHnullsList,n.pprev), 1);
	FOR_POINTER(struct hlist_nulls_node *, __pprev, OFFATTR(void **, offsetof(struct myLongHnullsList,n.pprev)),
		FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(myLongHnullsList, sizeof(struct myLongHnullsList), __pprev, 1);
	);
);

static int kflat_hlist_nulls_test(struct flat *flat) {
	struct hlist_nulls_head hnarr[5];
	int i, j;
	struct hlist_nulls_node *p;

	FLATTEN_SETUP_TEST(flat);

	for (i = 0; i < 5; ++i) {
		INIT_HLIST_NULLS_HEAD(&hnarr[i], 0);
		for (j = 0; j < 10; ++j) {
			struct myLongHnullsList *item = kvzalloc(sizeof(struct myLongHnullsList), GFP_KERNEL);
			item->k = i * 10 + j + 1;
			hlist_nulls_add_head(&item->n, &hnarr[i]);
		}
	}

	FOR_ROOT_POINTER(hnarr,
		FLATTEN_STRUCT_ARRAY(hlist_nulls_head, hnarr, 5);
	);

	FOR_ROOT_POINTER(hnarr,
		for (i = 0; i < 5; ++i) {
			struct myLongHnullsList *entry;
			hlist_nulls_for_each_entry (entry, p, &hnarr[i], n) {
				FLATTEN_STRUCT_ARRAY(myLongHnullsList, entry, 1);
			}
		}
	);

	for (i = 0; i < 5; ++i) {
		while (!hlist_nulls_empty(&hnarr[i])) {
			struct myLongHnullsList *entry = hlist_nulls_entry(hnarr[i].first, struct myLongHnullsList, n);
			hlist_nulls_del(hnarr[i].first);
			kvfree(entry);
		}
	}
	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static inline int is_a_nulls(const struct hlist_nulls_node *ptr) {
	return ((unsigned long)ptr & 1);
}

static int kflat_hlist_nulls_test_validate(void *memory, size_t size, CUnflatten flatten) {
	int i;
	struct hlist_nulls_node *p;
	struct hlist_nulls_head *hnarr = (struct hlist_nulls_head *)unflatten_root_pointer_seq(flatten, 0);
	struct hlist_nulls_head *hnarr2 = (struct hlist_nulls_head *)unflatten_root_pointer_seq(flatten, 1);

	for (i = 0; i < 5; ++i) {
		unsigned long list_size = 0;
		struct myLongHnullsList *entry;
		for (p = (&hnarr[i])->first;
		     (!is_a_nulls(p)) && ({ entry = container_of(p, typeof(*entry), n); 1; });
		     p = p->next) {
			ASSERT(entry->k == i * 10 + 10 - list_size);
			list_size++;
		}
		ASSERT(list_size == 10);
	}

	for (i = 0; i < 5; ++i) {
		unsigned long list_size = 0;
		struct myLongHnullsList *entry;
		for (p = (&hnarr2[i])->first;
		     (!is_a_nulls(p)) && ({ entry = container_of(p, typeof(*entry), n); 1; });
		     p = p->next) {
			ASSERT(entry->k == i * 10 + 10 - list_size);
			list_size++;
		}
		ASSERT(list_size == 10);
	}

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("HNULLSLIST", kflat_hlist_nulls_test, kflat_hlist_nulls_test_validate);
