/**
 * @file example_list_complex.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#if defined(__VALIDATOR__) && !defined(__TESTER__)
struct list_head {
	struct list_head *next, *prev;
};
#endif

#define ID_STR	"012346578901234569"

struct cvec {
	const char* name;
	struct list_head head;
};

/* Complicated structure with embedded list_head */
struct complexnode {
	char id[20];
	int number;

	struct list_head link;

	char* name;
	unsigned long long len_of_name;
	unsigned char data[128];

	struct cvec* parent;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(list_head);
FUNCTION_DECLARE_FLATTEN_STRUCT(cvec);
FUNCTION_DECLARE_FLATTEN_STRUCT(complexnode);

FUNCTION_DEFINE_FLATTEN_STRUCT(complexnode,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT(cvec, parent);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, complexnode, sizeof(struct complexnode),	
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(name, offsetof(struct complexnode, name));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(cvec, sizeof(struct cvec), parent, offsetof(struct complexnode, parent));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(cvec,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRUCT(list_head,head.next);
	AGGREGATE_FLATTEN_STRUCT(list_head,head.prev);
	{
		struct complexnode* __entry;
		list_for_each_entry(__entry, &ATTR(head), link ) {
			FOR_POINTER(struct complexnode*,____entry,&__entry,
				FLATTEN_STRUCT(complexnode,____entry);
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

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(self_contained, cvec, sizeof(struct cvec),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(name,offsetof(struct cvec,name));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),head.next,offsetof(struct cvec,head.next));
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(list_head,sizeof(struct list_head),head.prev,offsetof(struct cvec,head.prev));
	{
		struct complexnode* __entry;
		list_for_each_entry_from_offset(__entry, &OFFATTR(struct list_head,offsetof(struct cvec,head)), offsetof(struct complexnode,link) ) {
			FOR_POINTER(struct complexnode*,____entry,&__entry,
				FLATTEN_STRUCT_SELF_CONTAINED(complexnode,sizeof(struct complexnode),____entry);
			);
		}
	}
);

static int kflat_list_complex_test(struct flat *flat) {
	long i, err = 0;
	struct cvec vec = { "Vector of compilacted structs" };
	struct cvec vec2 = { "Another vector of structs" };

	FLATTEN_SETUP_TEST(flat);

	INIT_LIST_HEAD(&vec.head);
	for (i = 0; i < 200; ++i) {
		struct complexnode *complexnode = FLATTEN_BSP_ZALLOC(sizeof(struct complexnode));

		/* Fill structure with some semi-random pattern */
		strcpy(complexnode->id, ID_STR);
		complexnode->id[19] = i % 26 + 'A';
		complexnode->number = ((i + 117) * 2130) % 74;
		complexnode->name = FLATTEN_BSP_ZALLOC(32);
		for(int j = 0; j < 31; j++) complexnode->name[j] = 'A' +  (i + j) % 26;
		complexnode->len_of_name = 31;
		for(int j = 0; j < sizeof(complexnode->data); j++) complexnode->data[j] = (i + j * 774511) % 19999;

		list_add_tail(&complexnode->link, &vec.head);
	}

	INIT_LIST_HEAD(&vec2.head);
	for (i = 0; i < 200; ++i) {
		struct complexnode *complexnode = FLATTEN_BSP_ZALLOC(sizeof(struct complexnode));

		/* Fill structure with some semi-random pattern */
		strcpy(complexnode->id, ID_STR);
		complexnode->id[19] = (100 - i) % 26 + 'A';
		complexnode->number = ((i + 17) * 2130) % 74;
		complexnode->name = FLATTEN_BSP_ZALLOC(32);
		for(int j = 0; j < 31; j++) complexnode->name[j] = 'A' +  (i + 2 * j) % 26;
		complexnode->len_of_name = 31;
		for(int j = 0; j < sizeof(complexnode->data); j++) complexnode->data[j] = (i + j * 311853) % 758821;

		list_add_tail(&complexnode->link, &vec2.head);
	}

	FOR_ROOT_POINTER(&vec,
		FLATTEN_STRUCT(cvec, &vec);
	);

	FOR_ROOT_POINTER(&vec2,
		FLATTEN_STRUCT_SPECIALIZE(self_contained, cvec, &vec2);
	);

	while (!list_empty(&vec.head)) {
		struct complexnode *entry = list_entry(vec.head.next, struct complexnode, link);
		list_del(vec.head.next);
		FLATTEN_BSP_FREE(entry->name);
		FLATTEN_BSP_FREE(entry);
	}
	while (!list_empty(&vec2.head)) {
		struct complexnode *entry = list_entry(vec2.head.next, struct complexnode, link);
		list_del(vec2.head.next);
		FLATTEN_BSP_FREE(entry->name);
		FLATTEN_BSP_FREE(entry);
	}
	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_list_complex_validate(void *memory, size_t size, CUnflatten flatten) {
	struct list_head *p;
	long list_size = 0;
	struct cvec *vec = (struct cvec *)unflatten_root_pointer_seq(flatten, 0);
	struct cvec *vec2 = (struct cvec *)unflatten_root_pointer_seq(flatten, 1);

	for (p = (&vec->head)->next; p != (&vec->head); p = p->next) {
		struct complexnode *entry = container_of(p, struct complexnode, link);
		ASSERT(!strncmp(entry->id, ID_STR, 18));
		ASSERT_EQ(entry->id[19], list_size % 26 + 'A');
		ASSERT_EQ(entry->number, ((list_size + 117) * 2130) % 74);
		ASSERT_EQ(entry->len_of_name, 31);
		for(int j = 0; j < 31; j++) ASSERT_EQ(entry->name[j], 'A' +  (list_size + j) % 26);
		for(int j = 0; j < sizeof(entry->data); j++) ASSERT_EQ(entry->data[j], (unsigned char) ((list_size + j * 774511) % 19999));
		list_size++;
	}
	ASSERT(list_size == 200);

	list_size = 0;
	for (p = (&vec2->head)->next; p != (&vec2->head); p = p->next) {
		struct complexnode *entry = container_of(p, struct complexnode, link);
		ASSERT(!strncmp(entry->id, ID_STR, 18));
		ASSERT_EQ(entry->id[19], (100 - list_size) % 26 + 'A');
		ASSERT_EQ(entry->number, ((list_size + 17) * 2130) % 74);
		ASSERT_EQ(entry->len_of_name, 31);
		for(int j = 0; j < 31; j++) ASSERT_EQ(entry->name[j], 'A' +  (list_size + 2 * j) % 26);
		for(int j = 0; j < sizeof(entry->data); j++) ASSERT_EQ(entry->data[j], (unsigned char) ((list_size + j * 311853) % 758821));
		list_size++;
	}
	ASSERT(list_size == 200);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("LIST_COMPLEX", kflat_list_complex_test, kflat_list_complex_validate);
