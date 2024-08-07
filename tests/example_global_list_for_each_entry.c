/**
 * @file example_global_list_for_each_entry.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#if defined(__VALIDATOR__) && !defined(__TESTER__)
struct list_head {
	struct list_head *next, *prev;
};
#endif

struct intnodeg {
	int i;
	struct list_head link;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(list_head);
FUNCTION_DECLARE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, list_head, sizeof(struct list_head));

FUNCTION_DEFINE_FLATTEN_STRUCT(intnodeg,
	AGGREGATE_FLATTEN_STRUCT(list_head,link.next);
	AGGREGATE_FLATTEN_STRUCT(list_head,link.prev);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, intnodeg, sizeof(struct intnodeg),
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),link.next,offsetof(struct intnodeg,link.next));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),link.prev,offsetof(struct intnodeg,link.prev));
);

#define container_of_by_offset(ptr, offset) ({				\
	void *__mptr = (void *)(ptr);					\
	(__mptr - offset); })

#define list_entry_from_offset(ptr, offset) \
	container_of_by_offset(ptr, offset)

#define list_first_entry_from_offset(ptr, offset) \
	(list_entry_from_offset((ptr)->next, offset))

#define list_next_entry_from_offset(pos, offset) \
	(list_entry_from_offset(MOFFATTR(pos,struct list_head,offset).next, offset))

#define list_entry_is_head_by_offset(pos, head, offset)				\
	((typeof(head))((unsigned char*)pos+offset) == (head))

#define list_for_each_entry_from_offset(pos, head, offset)		\
	for (pos = list_first_entry_from_offset(head, offset);	\
	     !list_entry_is_head_by_offset(pos, head, offset);			\
	     pos = list_next_entry_from_offset(pos, offset))


struct list_head gvec;
struct list_head gvec2;

static int kflat_global_list_for_each_entry_test(struct flat *flat) {
	int i, err = 0;
	FLATTEN_SETUP_TEST(flat);

	INIT_LIST_HEAD(&gvec);
	for (i = 0; i < 100; ++i) {
		struct intnodeg *intnode = FLATTEN_BSP_ZALLOC(sizeof(struct intnodeg));
		intnode->i = i;
		list_add_tail(&intnode->link, &gvec);
	}
	INIT_LIST_HEAD(&gvec2);
	for (i = 0; i < 100; ++i) {
		struct intnodeg *intnode = FLATTEN_BSP_ZALLOC(sizeof(struct intnodeg));
		intnode->i = 100-1-i;
		list_add_tail(&intnode->link, &gvec2);
	}

	FOR_ROOT_POINTER(&gvec,
		FLATTEN_STRUCT(list_head, &gvec);
		{
			struct intnodeg* __entry;
			list_for_each_entry(__entry, &gvec, link ) {
				FLATTEN_STRUCT(intnodeg,__entry);
			}
		}
	);

	FOR_ROOT_POINTER(&gvec2,
		FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, list_head, sizeof(struct list_head), &gvec2);
		{
			struct intnodeg* __entry;
			list_for_each_entry_from_offset(__entry, &gvec2, offsetof(struct intnodeg,link) ) {
				FLATTEN_STRUCT_SELF_CONTAINED(intnodeg,sizeof(struct intnodeg),__entry);
			}
		}
	);

	err = FLATTEN_FINISH_TEST(flat);

	while (!list_empty(&gvec)) {
		struct intnodeg *entry = list_entry(gvec.next, struct intnodeg, link);
		list_del(gvec.next);
		FLATTEN_BSP_FREE(entry);
	}
	while (!list_empty(&gvec2)) {
		struct intnodeg *entry = list_entry(gvec2.next, struct intnodeg, link);
		list_del(gvec2.next);
		FLATTEN_BSP_FREE(entry);
	}
	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_global_list_for_each_entry_validate(void *memory, size_t size, CUnflatten flatten) {
	struct list_head *p;
	size_t list_size = 0;
	struct list_head *gvec = (struct list_head *)unflatten_root_pointer_seq(flatten, 0);
	struct list_head *gvec2 = (struct list_head *)unflatten_root_pointer_seq(flatten, 1);

	for (p = gvec->next; p != gvec; p = p->next) {
		struct intnodeg *entry = container_of(p, struct intnodeg, link);
		ASSERT(entry->i == list_size);
		list_size++;
	}
	ASSERT(list_size == 100);

	list_size = 0;
	for (p = gvec2->next; p != gvec2; p = p->next) {
		struct intnodeg *entry = container_of(p, struct intnodeg, link);
		ASSERT(entry->i == 100-1-list_size);
		list_size++;
	}
	ASSERT(list_size == 100);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("GLOBAL_LIST_FOR_EACH_ENTRY", kflat_global_list_for_each_entry_test, kflat_global_list_for_each_entry_validate);
