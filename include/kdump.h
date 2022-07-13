#include <linux/rbtree.h>
#include <linux/mm.h>

/*******************************************************
 * Exported structures
 *******************************************************/
struct kdump_memory_node {
    struct rb_node rb;
    uint64_t __subtree_last;

    uint64_t start;
    uint64_t end;
    uint64_t phys_addr;
};

struct kdump_memory_map {
    struct rb_root_cached imap_root;
};

struct kdump_memory_flat {
    uint64_t start;
    uint64_t end;
} __packed;

/*******************************************************
 * Exported functions
 *******************************************************/
int kdump_init(void);
void kdump_exit(void);

void kdump_dump_vma(struct kdump_memory_map* kdump);
int kdump_tree_remap(struct kdump_memory_map* kdump, struct vm_area_struct* vma);
int kdump_tree_flatten(struct kdump_memory_map* kdump, void* __user buf, size_t buf_size);
int kdump_tree_destroy(struct kdump_memory_map* kdump);
bool kdump_tree_contains(struct kdump_memory_map* kdump, uint64_t addr, size_t len);
size_t kdump_tree_total_size(struct kdump_memory_map* kdump);
bool kdump_test_address(void* addr);
