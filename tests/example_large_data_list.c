/**
 * @file example_large_data_list.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#define LIST_ELEMENT_COUNT	3000
#define LIST_ELEMENT_DATASIZE 8000

#ifdef __KERNEL__
#include <linux/list.h>
#else
struct list_head {
	struct list_head *next, *prev;
};
#endif

struct myLongLargeDataList {
	int k;
	char* data;
	struct list_head v;
};

/********************************/
#ifdef __KERNEL__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(myLongLargeDataList, sizeof(struct myLongLargeDataList));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(myLongLargeDataList, sizeof(struct myLongLargeDataList),
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(char,data,offsetof(struct myLongLargeDataList,data),LIST_ELEMENT_DATASIZE);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongLargeDataList, sizeof(struct myLongLargeDataList), v.next, offsetof(struct myLongLargeDataList,v.next), 1, -offsetof(struct myLongLargeDataList,v));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myLongLargeDataList, sizeof(struct myLongLargeDataList), v.prev, offsetof(struct myLongLargeDataList,v.prev), 1, -offsetof(struct myLongLargeDataList,v));
);

static int kflat_large_data_list_test(struct kflat *kflat) {
	int i, err = 0;
	struct list_head *head;
	struct myLongLargeDataList myhead = { -1,0 };

	INIT_LIST_HEAD(&myhead.v);
	head = &myhead.v;
	for (i = 0; i < LIST_ELEMENT_COUNT; ++i) {
		struct myLongLargeDataList *item = kflat_zalloc(kflat,sizeof(struct myLongLargeDataList), 1);
		item->data = kflat_zalloc(kflat,LIST_ELEMENT_DATASIZE,1);
		item->k = i + 1;
		list_add(&item->v, head);
		head = &item->v;
	}

	FOR_ROOT_POINTER(&myhead,
		FLATTEN_STRUCT_ARRAY(myLongLargeDataList, &myhead, 1);
	);

	while (!list_empty(&myhead.v)) {
		list_del(myhead.v.next);
	}
	return err;
}

/********************************/
#else
/********************************/

static int kflat_large_data_list_validate(void *memory, size_t size, CUnflatten flatten) {
	struct list_head *p;
	size_t list_size = 0;
	struct myLongLargeDataList *myhead = (struct myLongLargeDataList *)memory;
	int sum = 0;

	for (p = (&myhead->v)->next; p != (&myhead->v); p = p->next) {
		struct myLongLargeDataList *entry = container_of(p, struct myLongLargeDataList, v);
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

KFLAT_REGISTER_TEST_FLAGS("LARGEDATA_LIST", kflat_large_data_list_test, kflat_large_data_list_validate,KFLAT_TEST_ATOMIC);
