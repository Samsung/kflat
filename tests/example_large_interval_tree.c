/**
 * @file example_large_interval_tree.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

#define INTERVAL_COUNT	5000

#if defined(__VALIDATOR__) && !defined(__TESTER__)
#include <stdbool.h>
#include "../lib/include_priv/rbtree.h"
#endif

struct my_interval_tree_node {
    struct rb_node rb;
    uint64_t __subtree_last;

    uint64_t start;
    uint64_t end;
    uint64_t phys_addr;
};

struct my_interval_tree_map {
    struct rb_root_cached imap_root;
};

size_t my_interval_tree_count(const struct my_interval_tree_map* interval_tree_map) {
    size_t count = 0;
    const struct rb_root* root;
    struct rb_node* p;

    root = &interval_tree_map->imap_root.rb_root;
    for(p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        count++;
    }
    return count;
}

/********************************/
#ifdef __TESTER__
/********************************/

static struct my_interval_tree_map interval_tree_map;

/*******************************************************
 * INTERVAL TREE
 *******************************************************/
#define START(node) ((node)->start)
#define END(node)  ((node)->end)

INTERVAL_TREE_DEFINE(struct my_interval_tree_node, rb,
		     uintptr_t, __subtree_last,
		     START, END,
             static __attribute__((used)), my_interval_tree)

FUNCTION_DECLARE_FLATTEN_STRUCT(my_interval_tree_node);
FUNCTION_DEFINE_FLATTEN_STRUCT(my_interval_tree_node,
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER(my_interval_tree_node, rb.__rb_parent_color, ptr_clear_2lsb_bits, flatten_ptr_restore_2lsb_bits);
    AGGREGATE_FLATTEN_STRUCT(my_interval_tree_node, rb.rb_right);
    AGGREGATE_FLATTEN_STRUCT(my_interval_tree_node, rb.rb_left);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(my_interval_tree_map,
    AGGREGATE_FLATTEN_STRUCT(my_interval_tree_node, imap_root.rb_root.rb_node);
    AGGREGATE_FLATTEN_STRUCT(my_interval_tree_node, imap_root.rb_leftmost);
);

static int kflat_large_interval_tree_test(struct flat *flat) {
	
	unsigned j;
	unsigned long i=0;
	unsigned char *bytes = flat_zalloc(flat,INTERVAL_COUNT*10,1);
	FLATTEN_SETUP_TEST(flat);
	interval_tree_map.imap_root.rb_root = RB_ROOT;

	for (j = 0; j < INTERVAL_COUNT; ++j) {
		struct my_interval_tree_node* node = flat_zalloc(flat,sizeof(*node),1);
	    node->start = i+bytes[j*10];
	    node->end = node->start+bytes[j*10+1]-1;
	    node->phys_addr = *((uint64_t*)&bytes[j*10+2]);;
	    my_interval_tree_insert(node, &interval_tree_map.imap_root);
	}

	flat_infos("Created %zu intervals in the interval tree",my_interval_tree_count(&interval_tree_map));

	FOR_ROOT_POINTER(&interval_tree_map,
		FLATTEN_STRUCT(my_interval_tree_map, &interval_tree_map);
	);

	interval_tree_map.imap_root.rb_root = RB_ROOT;
	// TODO: flat_free
	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_large_interval_tree_validate(void *memory, size_t size, CUnflatten flatten) {
	const struct my_interval_tree_map *interval_tree_map = (struct my_interval_tree_map *)memory;
	size_t count = my_interval_tree_count(interval_tree_map);
	ASSERT(count == INTERVAL_COUNT);

	PRINT("Interval tree size: %ld", count);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("LARGE_INTERVAL_TREE", kflat_large_interval_tree_test, kflat_large_interval_tree_validate,KFLAT_TEST_ATOMIC);
