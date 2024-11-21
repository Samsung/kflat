/**
 * @file kdump.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Structures and functions responsible of memory disovery
 *  and pointers validation
 *
 */
#ifndef _LINUX_KDUMP_H
#define _LINUX_KDUMP_H

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
int kdump_tree_flatten(struct kdump_memory_map* kdump, void* __user buf, size_t buf_size);
int kdump_tree_destroy(struct kdump_memory_map* kdump);
#ifdef KFLAT_VM_TREE_SUPPORT
int kdump_tree_remap(struct kdump_memory_map* kdump, struct vm_area_struct* vma);
bool kdump_tree_contains(struct kdump_memory_map* kdump, uint64_t addr, size_t len);
size_t kdump_tree_total_size(struct kdump_memory_map* kdump);
#endif

/**
 * @brief Check whether provided address range is valid
 *
 * @param addr starting address
 * @param size size of memory range to be checked
 * @return size_t number of bytes from `addr` pointer that are valid kernel memory.
 *                i.e. when whole address range is valid, returned_value == size
 */
size_t kdump_test_address(void* addr, size_t size);

void* hwasan_safe_memcpy(void* dst, const void* src, size_t size);

/**
 * @brief Check whether provided address belongs to CMA allocator
 *
 * @param ptr pointer to memory
 * @return true CMA area
 * @return false other memory
 */
bool is_cma_memory(void* ptr);

#endif /* _LINUX_KDUMP_H */
