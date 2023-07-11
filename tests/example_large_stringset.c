/**
 * @file example_large_stringset.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#define TREE_ELEMENT_COUNT	2000

#if defined(__VALIDATOR__) && !defined(__TESTER__)
#include <stdbool.h>
#include "../lib/include_priv/rbtree.h"
#endif

struct string_node_atomic {
	struct rb_node node;
	char *s;
};

/********************************/
#ifdef __TESTER__
/********************************/

static struct rb_root stringset_root = RB_ROOT;

FUNCTION_DECLARE_FLATTEN_STRUCT(string_node_atomic);

FUNCTION_DEFINE_FLATTEN_STRUCT(string_node_atomic,
	STRUCT_ALIGN(4);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER(string_node_atomic, node.__rb_parent_color, ptr_clear_2lsb_bits, flatten_ptr_restore_2lsb_bits);
	AGGREGATE_FLATTEN_STRUCT(string_node_atomic, node.rb_right);
	AGGREGATE_FLATTEN_STRUCT(string_node_atomic, node.rb_left);
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SPECIALIZE(atomic_stringset,rb_root,
	AGGREGATE_FLATTEN_STRUCT(string_node_atomic,rb_node);
);

static int stringset_insert(struct flat* flat, const char *s) {
	struct string_node_atomic *data = flat_zalloc(flat,sizeof(struct string_node_atomic),1);
	struct rb_node **new, *parent = 0;
	data->s = flat_zalloc(flat,strlen(s) + 1,1);
	strcpy(data->s, s);
	new = &(stringset_root.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct string_node_atomic *this = container_of(*new, struct string_node_atomic, node);

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
	// TODO: flat_free
}

static int kflat_large_stringset_test(struct flat *flat) {
	
	unsigned i, j;
	static const char chars[] = "ABCDEFGHIJKLMNOPQRST";
	unsigned int r = 0;

	FLATTEN_SETUP_TEST(flat);

	for (j = 0; j < TREE_ELEMENT_COUNT; ++j) {
		char *s = flat_zalloc(flat, 11, 1);
		r++;
		for (i = 0; i < 10; ++i) {
			s[i] = chars[(r >> (4*i)) & 0xf];
		}
		stringset_insert(flat,s);
	}

	FOR_ROOT_POINTER(&stringset_root,
		FLATTEN_STRUCT_SPECIALIZE(atomic_stringset, rb_root, &stringset_root);
	);

	stringset_destroy(&stringset_root);
	stringset_root.rb_node = 0;
	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static size_t stringset_count(const struct rb_root *root) {
	struct rb_node *p = rb_first(root);
	size_t count = 0;
	while (p) {
		count++;
		p = rb_next(p);
	}
	return count;
}

static int kflat_large_stringset_validate(void *memory, size_t size, CUnflatten flatten) {
	const struct rb_root *root = (struct rb_root *)memory;
	ASSERT(stringset_count(root) == TREE_ELEMENT_COUNT);

	PRINT("Stringset size: %ld", stringset_count(root));

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/


KFLAT_REGISTER_TEST_FLAGS("LARGE_STRINGSET", kflat_large_stringset_test, kflat_large_stringset_validate,KFLAT_TEST_ATOMIC);
