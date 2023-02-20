/**
 * @file example_list_for_each_entry.c
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

struct ivec {
	const char* name;
	struct list_head head;
};

struct inode {
	int i;
	struct list_head link;
};

/********************************/
#ifdef __KERNEL__
/********************************/

static int kflat_list_for_each_entry_test(struct kflat *kflat) {
	int i, err = 0;
	struct ivec vec = { "Vector of ints" };
	struct ivec vec2 = { "Another vector of ints" };

	INIT_LIST_HEAD(&vec.head);
	for (i = 0; i < 100; ++i) {
		struct inode *inode = kvzalloc(sizeof(struct inode), GFP_KERNEL);
		inode->i = i;
		list_add_tail(&inode->link, &vec.head);
	}
	INIT_LIST_HEAD(&vec2.head);
	for (i = 0; i < 100; ++i) {
		struct inode *inode = kvzalloc(sizeof(struct inode), GFP_KERNEL);
		inode->i = 100-1-i;
		list_add_tail(&inode->link, &vec2.head);
	}

	FOR_ROOT_POINTER(&myhead,
		//FLATTEN_STRUCT_ARRAY(myLongList, &myhead, 1);
	);

	while (!list_empty(&vec.head)) {
		struct inode *entry = list_entry(vec.head.next, struct inode, );
		list_del(vec.v.next);
		kvfree(entry);
	}
	while (!list_empty(&vec2.head)) {
		struct inode *entry = list_entry(vec2.head.next, struct inode, );
		list_del(vec2.v.next);
		kvfree(entry);
	}
	return err;
}

/********************************/
#else
/********************************/

static int kflat_list_for_each_entry_validate(void *memory, size_t size, CFlatten flatten) {
	struct list_head *p;
	size_t list_size = 0;
	struct myLongList *myhead = (struct myLongList *)memory;

	for (p = (&myhead->v)->next; p != (&myhead->v); p = p->next) {
		struct myLongList *entry = container_of(p, struct myLongList, v);
		list_size++;
		ASSERT(entry->k == list_size);
	}
	ASSERT(list_size == 100);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif
/********************************/

KFLAT_REGISTER_TEST("LONG_LIST", kflat_list_test, kflat_list_validate);
