/**
 * @file example_stringset.c
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

struct string_node {
	struct rb_node node;
	char *s;
};

#ifdef __KERNEL__

static struct rb_root stringset_root = RB_ROOT;

static inline void* ptr_remove_color(const void* ptr) {
	return (void*)((uintptr_t)ptr & ~3);
}

static inline struct flatten_pointer *fptr_add_color(struct flatten_pointer *fptr, const struct flatten_base *ptr) {
	fptr->offset |= (size_t)((uintptr_t)ptr & 3);
	return fptr;
}

FUNCTION_DECLARE_FLATTEN_STRUCT(string_node);

FUNCTION_DEFINE_FLATTEN_STRUCT(string_node,
	STRUCT_ALIGN(4);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER(string_node, node.__rb_parent_color, ptr_remove_color, fptr_add_color);
	AGGREGATE_FLATTEN_STRUCT(string_node, node.rb_right);
	AGGREGATE_FLATTEN_STRUCT(string_node, node.rb_left);
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(rb_root,
	AGGREGATE_FLATTEN_STRUCT(string_node, rb_node);
);

static int stringset_insert(const char *s) {
	struct string_node *data = kvzalloc(sizeof(struct string_node), GFP_KERNEL);
	struct rb_node **new, *parent = 0;
	data->s = kvzalloc(strlen(s) + 1, GFP_KERNEL);
	strcpy(data->s, s);
	new = &(stringset_root.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct string_node *this = container_of(*new, struct string_node, node);

		parent = *new;
		if (strcmp(data->s, this->s) < 0)
			new = &((*new)->rb_left);
		else if (strcmp(data->s, this->s) > 0)
			new = &((*new)->rb_right);
		else {
			kvfree((void *)data->s);
			kvfree(data);
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
		struct string_node *data = (struct string_node *)p;
		rb_erase(p, root);
		p = rb_next(p);
		kvfree((void *)data->s);
		kvfree(data);
	}
}

static int kflat_stringset_test(struct kflat *kflat) {
	unsigned i, j;

	for (j = 0; j < 50; ++j) {
		char *s = kvzalloc(11, GFP_KERNEL);
		for (i = 0; i < 10; ++i) {
			s[i] = i + j + 1;
		}
		stringset_insert(s);
		kvfree(s);
	}

	FOR_ROOT_POINTER(&stringset_root,
		FLATTEN_STRUCT(rb_root, &stringset_root);
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

static int kflat_stringset_validate(void *memory, size_t size, CFlatten flatten) {
	const struct rb_root *root = (struct rb_root *)memory;
	ASSERT(stringset_count(root) == 50);

	PRINT("Stringset size: %ld", stringset_count(root));

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("STRINGSET", kflat_stringset_test, kflat_stringset_validate);
