/**
 * @file example_rbtree.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#ifdef __KERNEL__
#include <linux/rbtree.h>
#else
#include <stdbool.h>
#include "../lib/include_priv/rbtree.h"
#endif

// Common structures
struct myTreeNode {
	int i;
	struct rb_node inode;
	struct K {
		char c;
		double d;
	} k;
	struct rb_node snode;
	char *s;
};

/********************************/
#ifdef __KERNEL__
/********************************/

static inline void *rbnode_remove_color(const void *ptr) {
	return (void *)((uintptr_t)ptr & ~3);
}

static inline struct flatten_pointer *rbnode_add_color(struct flatten_pointer *fptr, const void *ptr) {
	fptr->offset |= (size_t)((uintptr_t)ptr & 3);
	return fptr;
}

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myTreeNode, 80);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myTreeNode, 80,
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode, 80, inode.__rb_parent_color, 8,
										rbnode_remove_color, rbnode_add_color, 1, -8);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode, 80, inode.rb_right, 16, 1, -8);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode, 80, inode.rb_left, 24, 1, -8);
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode, 80, snode.__rb_parent_color, 48,
										rbnode_remove_color, rbnode_add_color, 1, -48);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode, 80, snode.rb_right, 56, 1, -48);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode, 80, snode.rb_left, 64, 1, -48);
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(s, 72);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SPECIALIZE(myTreeNode, rb_root, 8);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED_SPECIALIZE(myTreeNode, rb_root, 8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode, 80, rb_node, 0, 1, -8);
);

static int intset_insert(struct rb_root *root, struct myTreeNode *idata) {
	struct rb_node **new, *parent = 0;
	new = &(root->rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct myTreeNode *this = container_of(*new, struct myTreeNode, inode);

		parent = *new;
		if (idata->i < this->i)
			new = &((*new)->rb_left);
		else if (idata->i > this->i)
			new = &((*new)->rb_right);
		else
			return 0;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&idata->inode, parent, new);
	rb_insert_color(&idata->inode, root);

	return 1;
}

static void intset_destroy(struct rb_root *root) {
	struct rb_node *p = rb_first(root);
	while (p) {
		rb_erase(p, root);
		p = rb_next(p);
	}
}

static int strset_insert(struct rb_root *root, struct myTreeNode *sdata) {
	struct rb_node **new, *parent = 0;
	new = &(root->rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct myTreeNode *this = container_of(*new, struct myTreeNode, snode);

		parent = *new;
		if (strcmp(sdata->s, this->s) < 0)
			new = &((*new)->rb_left);
		else if (strcmp(sdata->s, this->s) > 0)
			new = &((*new)->rb_right);
		else
			return 0;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&sdata->snode, parent, new);
	rb_insert_color(&sdata->snode, root);

	return 1;
}

static void strset_destroy(struct rb_root *root) {
	struct rb_node *p = rb_first(root);
	while (p) {
		struct myTreeNode *data = container_of(p, struct myTreeNode, snode);
		rb_erase(p, root);
		p = rb_next(p);
		kvfree(data->s);
		data->s = NULL;
	}
}

static int kflat_rbtree_example(struct kflat *kflat) {
	int i;
	struct rb_root iroot = RB_ROOT;
	struct rb_root sroot = RB_ROOT;

	struct myTreeNode tarr[15] = {};
	for (i = 0; i < 10; ++i)
		tarr[i].s = kvzalloc(1, GFP_KERNEL);
	strcpy(tarr[0].s, "AA0");
	strcpy(tarr[1].s, "AA5");
	strcpy(tarr[2].s, "AA9");
	strcpy(tarr[3].s, "AA4");
	strcpy(tarr[4].s, "AA2");
	strcpy(tarr[5].s, "AA6");
	strcpy(tarr[6].s, "AA7");
	strcpy(tarr[7].s, "AA1");
	strcpy(tarr[8].s, "AA8");
	strcpy(tarr[9].s, "AA3");
	for (i = 5; i < 15; ++i)
		tarr[i].i = i - 5;

	for (i = 0; i < 10; ++i)
		strset_insert(&sroot, &tarr[i]);
	for (i = 5; i < 15; ++i)
		intset_insert(&iroot, &tarr[i]);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&iroot,
			FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE(myTreeNode, rb_root, &iroot, 1);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&sroot,
			FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE(myTreeNode, rb_root, &sroot, 1);
		);
	);

	strset_destroy(&sroot);
	intset_destroy(&iroot);
	iroot.rb_node = sroot.rb_node = 0;

	return 0;
}

/********************************/
#else
/********************************/

static int kflat_rbtree_validate(void *memory, size_t size, CFlatten flatten) {
	struct rb_root *iroot = (struct rb_root *)flatten_root_pointer_seq(flatten, 0);
	struct rb_root *sroot = (struct rb_root *)flatten_root_pointer_seq(flatten, 1);

	// Validate int set
	uint32_t visited = 0;
	size_t count = 0;
	struct rb_node *p = rb_first(iroot);
	while (p) {
		struct myTreeNode *entry = container_of(p, struct myTreeNode, inode);
		ASSERT((visited & (1 << entry->i)) == 0);
		visited |= 1 << entry->i;

		p = rb_next(p);
		count++;
	}
	ASSERT(visited == 0b1111111111);
	ASSERT(count == 10);

	// Validate string set
	visited = 0;
	count = 0;
	p = rb_first(sroot);
	while (p) {
		struct myTreeNode *entry = container_of(p, struct myTreeNode, snode);
		ASSERT(entry->s[0] == 'A' && entry->s[1] == 'A');

		int pos = entry->s[2] - '0';
		ASSERT((visited & (1 << pos)) == 0);
		visited |= 1 << pos;

		p = rb_next(p);
		count++;
	}
	ASSERT(visited == 0b1111111111);
	ASSERT(count == 10);

	return 0;
}

/********************************/
#endif
/********************************/

KFLAT_REGISTER_TEST("RBTREE", kflat_rbtree_example, kflat_rbtree_validate);
