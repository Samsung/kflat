/**
 * @file example_large_data_stringset.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#define TREE_ELEMENT_COUNT	2000
#define TREE_ELEMENT_DATASIZE	8000

#ifdef __KERNEL__
#include <linux/rbtree.h>
#include <linux/random.h>
#else
#include <stdbool.h>
#include "../lib/include_priv/rbtree.h"
#endif

struct largestring_node_atomic {
	struct rb_node node;
	char *s;
};

#ifdef __KERNEL__

static struct rb_root stringset_root = RB_ROOT;

FUNCTION_DECLARE_FLATTEN_STRUCT(largestring_node_atomic);

FUNCTION_DEFINE_FLATTEN_STRUCT(largestring_node_atomic,
	STRUCT_ALIGN(4);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER(largestring_node_atomic, node.__rb_parent_color, ptr_clear_2lsb_bits, flatten_ptr_restore_2lsb_bits);
	AGGREGATE_FLATTEN_STRUCT(largestring_node_atomic, node.rb_right);
	AGGREGATE_FLATTEN_STRUCT(largestring_node_atomic, node.rb_left);
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SPECIALIZE(atomic_largestringset,rb_root,
	AGGREGATE_FLATTEN_STRUCT(largestring_node_atomic,rb_node);
);

static int stringset_insert(struct kflat* kflat, const char *s) {
	struct largestring_node_atomic *data = flat_zalloc(&kflat->flat,sizeof(struct largestring_node_atomic),1);
	struct rb_node **new, *parent = 0;
	data->s = flat_zalloc(&kflat->flat,strlen(s) + 1,1);
	strcpy(data->s, s);
	new = &(stringset_root.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct largestring_node_atomic *this = container_of(*new, struct largestring_node_atomic, node);

		parent = *new;
		if (strcmp(data->s, this->s) < 0)
			new = &((*new)->rb_left);
		else if (strcmp(data->s, this->s) > 0)
			new = &((*new)->rb_right);
		else {
			return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &stringset_root);

	return 1;
}

static void stringset_destroy(struct rb_root *root) {
	struct rb_node *p = rb_first(root);
	while (p) {
		struct rb_node *q = rb_next(p);
		rb_erase(p, root);
		p = q;
	}
}

static int kflat_large_data_stringset_test(struct kflat *kflat) {
	
	unsigned i, j;
	static const char chars[] = "ABCDEFGHIJKLMNOP";
	struct rnd_state rand_state;

	prandom_seed_state(&rand_state, ktime_get_real());

	for (j = 0; j < TREE_ELEMENT_COUNT; ++j) {
		char *s = flat_zalloc(&kflat->flat,TREE_ELEMENT_DATASIZE+1,1);
		for (i = 0; i < TREE_ELEMENT_DATASIZE/8; ++i) {
			u32 r = prandom_u32_state(&rand_state);
			s[i*8] = chars[(r>>0)&0xf];
			s[i*8+1] = chars[(r>>4)&0xf];
			s[i*8+2] = chars[(r>>8)&0xf];
			s[i*8+3] = chars[(r>>12)&0xf];
			s[i*8+4] = chars[(r>>16)&0xf];
			s[i*8+5] = chars[(r>>20)&0xf];
			s[i*8+6] = chars[(r>>24)&0xf];
			s[i*8+7] = chars[(r>>28)&0xf];
		}
		stringset_insert(kflat,s);
	}

	FOR_ROOT_POINTER(&stringset_root,
		FLATTEN_STRUCT_SPECIALIZE(atomic_largestringset, rb_root, &stringset_root);
	);

	stringset_destroy(&stringset_root);
	stringset_root.rb_node = 0;
	return 0;
}

#else

static size_t stringset_count(const struct rb_root *root) {
	struct rb_node *p = rb_first(root);
	size_t count = 0;
	while (p) {
		count++;
		p = rb_next(p);
	}
	return count;
}

static int kflat_large_data_stringset_validate(void *memory, size_t size, CUnflatten flatten) {
	const struct rb_root *root = (struct rb_root *)memory;
	ASSERT(stringset_count(root) == TREE_ELEMENT_COUNT);

	PRINT("Stringset size: %ld", stringset_count(root));

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST_FLAGS("LARGEDATA_STRINGSET", kflat_large_data_stringset_test, kflat_large_data_stringset_validate,KFLAT_TEST_ATOMIC);
