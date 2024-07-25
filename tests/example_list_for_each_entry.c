/**
 * @file example_list_for_each_entry.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#if defined(__VALIDATOR__) && !defined(__TESTER__)
struct list_head {
	struct list_head *next, *prev;
};
#endif

struct ivec {
	const char* name;
	struct list_head head;
};

struct intnode {
	int i;
	struct list_head link;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(list_head);

FUNCTION_DEFINE_FLATTEN_STRUCT(list_head,
	AGGREGATE_FLATTEN_STRUCT(list_head,next);
	AGGREGATE_FLATTEN_STRUCT(list_head,prev);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, list_head, sizeof(struct list_head),
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),next,offsetof(struct list_head,next));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),prev,offsetof(struct list_head,prev));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(intnode,
	AGGREGATE_FLATTEN_STRUCT(list_head,link.next);
	AGGREGATE_FLATTEN_STRUCT(list_head,link.prev);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, intnode, sizeof(struct intnode),
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),link.next,offsetof(struct intnode,link.next));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),link.prev,offsetof(struct intnode,link.prev));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(ivec,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT(list_head,head.next);
	AGGREGATE_FLATTEN_STRUCT(list_head,head.prev);
	{
		struct intnode* __entry;
		list_for_each_entry(__entry, &ATTR(head), link ) {
			FOR_VIRTUAL_POINTER(__entry,
				FLATTEN_STRUCT(intnode,__entry);
			);
		}
	}
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

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, ivec, sizeof(struct ivec),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(name,offsetof(struct ivec,name));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),head.next,offsetof(struct ivec,head.next));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),head.prev,offsetof(struct ivec,head.prev));
	{
		struct intnode* __entry;
		list_for_each_entry_from_offset(__entry, &OFFATTR(struct list_head,offsetof(struct ivec,head)), offsetof(struct intnode,link) ) {
			FOR_VIRTUAL_POINTER(__entry,
				FLATTEN_STRUCT_SELF_CONTAINED(intnode,sizeof(struct intnode),__entry);
			);
		}
	}
);

static int kflat_list_for_each_entry_test(struct flat *flat) {
	int i, err = 0;
	struct ivec vec = { "Vector of ints" };
	struct ivec vec2 = { "Another vector of ints" };

	FLATTEN_SETUP_TEST(flat);

	INIT_LIST_HEAD(&vec.head);
	for (i = 0; i < 100; ++i) {
		struct intnode *intnode = FLATTEN_BSP_ZALLOC(sizeof(struct intnode));
		intnode->i = i;
		list_add_tail(&intnode->link, &vec.head);
	}
	INIT_LIST_HEAD(&vec2.head);
	for (i = 0; i < 100; ++i) {
		struct intnode *intnode = FLATTEN_BSP_ZALLOC(sizeof(struct intnode));
		intnode->i = 100-1-i;
		list_add_tail(&intnode->link, &vec2.head);
	}

	FOR_ROOT_POINTER(&vec,
		FLATTEN_STRUCT(ivec, &vec);
	);

	FOR_ROOT_POINTER(&vec2,
		FLATTEN_STRUCT_SPECIALIZE(self_contained, ivec, &vec2);
	);

	err = FLATTEN_FINISH_TEST(flat);

	while (!list_empty(&vec.head)) {
		struct intnode *entry = list_entry(vec.head.next, struct intnode, link);
		list_del(vec.head.next);
		FLATTEN_BSP_FREE(entry);
	}
	while (!list_empty(&vec2.head)) {
		struct intnode *entry = list_entry(vec2.head.next, struct intnode, link);
		list_del(vec2.head.next);
		FLATTEN_BSP_FREE(entry);
	}
	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_list_for_each_entry_validate(void *memory, size_t size, CUnflatten flatten) {
	struct list_head *p;
	size_t list_size = 0;
	struct ivec *vec = (struct ivec *)unflatten_root_pointer_seq(flatten, 0);
	struct ivec *vec2 = (struct ivec *)unflatten_root_pointer_seq(flatten, 1);

	for (p = (&vec->head)->next; p != (&vec->head); p = p->next) {
		struct intnode *entry = container_of(p, struct intnode, link);
		ASSERT(entry->i == list_size);
		list_size++;
	}
	ASSERT(list_size == 100);

	list_size = 0;
	for (p = (&vec2->head)->next; p != (&vec2->head); p = p->next) {
		struct intnode *entry = container_of(p, struct intnode, link);
		ASSERT(entry->i == 100-1-list_size);
		list_size++;
	}
	ASSERT(list_size == 100);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("LIST_FOR_EACH_ENTRY", kflat_list_for_each_entry_test, kflat_list_for_each_entry_validate);
