/**
 * @file example_rbtree.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#if defined(__VALIDATOR__) && !defined(__TESTER__)
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
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(myTreeNode, sizeof(struct myTreeNode));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(myTreeNode, sizeof(struct myTreeNode),
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), inode.__rb_parent_color, offsetof(struct myTreeNode,inode.__rb_parent_color),
										ptr_clear_2lsb_bits, flatten_ptr_restore_2lsb_bits, 1, -offsetof(struct myTreeNode,inode));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), inode.rb_right, offsetof(struct myTreeNode,inode.rb_right), 1, -offsetof(struct myTreeNode,inode));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), inode.rb_left, offsetof(struct myTreeNode,inode.rb_left), 1, -offsetof(struct myTreeNode,inode));
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), snode.__rb_parent_color, offsetof(struct myTreeNode,snode.__rb_parent_color),
										ptr_clear_2lsb_bits, flatten_ptr_restore_2lsb_bits, 1, -offsetof(struct myTreeNode,snode.__rb_parent_color));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), snode.rb_right, offsetof(struct myTreeNode,snode.rb_right), 1, -offsetof(struct myTreeNode,snode.__rb_parent_color));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), snode.rb_left, offsetof(struct myTreeNode,snode.rb_left), 1, -offsetof(struct myTreeNode,snode.__rb_parent_color));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(s, offsetof(struct myTreeNode,s));
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(iroot, rb_root, sizeof(struct rb_root));
FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(sroot, rb_root, sizeof(struct rb_root));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(iroot, rb_root, sizeof(struct rb_root),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), rb_node, offsetof(struct rb_root,rb_node), 1, -offsetof(struct myTreeNode,inode));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(sroot, rb_root, sizeof(struct rb_root),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(myTreeNode, sizeof(struct myTreeNode), rb_node, offsetof(struct rb_root,rb_node), 1, -offsetof(struct myTreeNode,snode));
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
		FLATTEN_BSP_FREE(data->s);
		data->s = NULL;
	}
}

static int kflat_rbtree_example(struct flat *flat) {
	int i, err;
	struct rb_root iroot = RB_ROOT;
	struct rb_root sroot = RB_ROOT;
	struct myTreeNode tarr[15] = {};

	FLATTEN_SETUP_TEST(flat);

	for (i = 0; i < 10; ++i)
		tarr[i].s = FLATTEN_BSP_ZALLOC(4);
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

	FOR_ROOT_POINTER(&iroot,
		FLATTEN_STRUCT_ARRAY_SPECIALIZE(iroot, rb_root, &iroot, 1);
	);

	FOR_ROOT_POINTER(&sroot,
		FLATTEN_STRUCT_ARRAY_SPECIALIZE(sroot, rb_root, &sroot, 1);
	);

	err = FLATTEN_FINISH_TEST(flat);

	strset_destroy(&sroot);
	intset_destroy(&iroot);
	iroot.rb_node = sroot.rb_node = 0;

	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_rbtree_validate(void *memory, size_t size, CUnflatten flatten) {
	struct rb_root *iroot = (struct rb_root *)unflatten_root_pointer_seq(flatten, 0);
	struct rb_root *sroot = (struct rb_root *)unflatten_root_pointer_seq(flatten, 1);

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

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("RBTREE", kflat_rbtree_example, kflat_rbtree_validate);
