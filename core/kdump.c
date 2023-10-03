/**
 * @file kdump.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Collection of functions for testing kernel address and
 *   dumping virtual memory layout
 * 
 */

#include "kdump.h"

#include <linux/interval_tree_generic.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#ifdef CONFIG_X86_64
#include <asm/io.h>
#include <asm/processor.h>
#endif

#undef pr_fmt
#define pr_fmt(fmt) "kflat: " fmt

/*******************************************************
 * INTERVAL TREE
 *******************************************************/
#define START(node) ((node)->start)
#define END(node)  ((node)->end)

INTERVAL_TREE_DEFINE(struct kdump_memory_node, rb,
		     uintptr_t, __subtree_last,
		     START, END,
             static __attribute__((used)), interval_tree)

struct interval_nodelist {
	struct interval_nodelist* next;
	struct kdump_memory_node* node;
};

int kdump_tree_destroy(struct kdump_memory_map* kdump) {
    int rv = 0;
	struct rb_node* p;
    struct rb_root* root;
    struct kdump_memory_node* node;
    struct interval_nodelist *h = 0, *i = 0, *v;

    root = &kdump->imap_root.rb_root;

	for(p = rb_first(root); p != NULL; p = rb_next(p)) {
		node = (struct kdump_memory_node*) p;
		v = kzalloc(sizeof(struct interval_nodelist), GFP_KERNEL);
		if (!v) {
			rv = -ENOMEM;
			break;
		}
		interval_tree_remove(node, &kdump->imap_root);
	    v->node = node;
	    if (!h) {
	        h = v;
	        i = v;
	    }
	    else {
	        i->next = v;
	        i = i->next;
	    }
	};

	while(h) {
    	struct interval_nodelist* p = h;
    	h = h->next;
    	kfree(p->node);
    	kfree(p);
    }
	return rv;
}

/*
 * kdump_tree_add_range - adds new memory range to interval tree, merging it
 *          with existing one when possible
 */
static int kdump_tree_add_range(struct kdump_memory_map* kdump, uint64_t start, uint64_t end, uint64_t phys_addr) {
    int rv = 0;
    struct kdump_memory_node* node;

    if(interval_tree_iter_first(&kdump->imap_root, start, end) != NULL) {
        WARN_ONCE(1, "Kflat: Attempted to insert the same memory range multiple times");
        return -EFAULT;
    }

    node = interval_tree_iter_first(&kdump->imap_root, start - 1, start - 1);
    if(node && node->phys_addr + (node->end - node->start + 1) == phys_addr) {
        // Extend the existing node to the right
        interval_tree_remove(node, &kdump->imap_root);
        node->end = end;
        interval_tree_insert(node, &kdump->imap_root);
        return rv;
    }

    node = interval_tree_iter_first(&kdump->imap_root, end + 1, end + 1);
    if(node && node->phys_addr == phys_addr + (end - start + 1)) {
        // Extend node to the left
        interval_tree_remove(node, &kdump->imap_root);
        node->start = start;
        node->phys_addr = phys_addr;
        interval_tree_insert(node, &kdump->imap_root);
        return rv;
    }

    // Create a new node
    node = kmalloc(sizeof(*node), GFP_KERNEL);
    if(node == NULL)
        return -ENOMEM;
    node->start = start;
    node->end = end;
    node->phys_addr = phys_addr;
    interval_tree_insert(node, &kdump->imap_root);

    return rv;
}

int kdump_tree_flatten(struct kdump_memory_map* kdump, void* __user buf, size_t buf_size) {
    int ret, cnt = 0;
    off_t offset = 4;
    struct rb_root* root;
    struct rb_node* p;
    struct kdump_memory_flat mem;

    root = &kdump->imap_root.rb_root;
    for(p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        struct kdump_memory_node* node = (struct kdump_memory_node*) p;
        mem.start = node->start;
        mem.end = node->end;

        if(offset + sizeof(mem) > buf_size)
            return -ENOSPC;

        ret = copy_to_user(buf + offset, &mem, sizeof(mem));
        if(ret)
            return -EFAULT;
        offset += sizeof(mem);
    }

    cnt = (offset - 4) / sizeof(mem);
    ret = copy_to_user(buf, &cnt, sizeof(cnt));
    if(ret)
        return -EFAULT;
    
    return 0;
}

int kdump_tree_remap(struct kdump_memory_map* kdump, struct vm_area_struct* vma) {
    int ret;
    int warned = 0;
    struct rb_root* root;
    struct rb_node* p;
    off_t offset = 0;

    if(vma->vm_flags & (VM_WRITE | VM_EXEC))
        return -EPERM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
    vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_flags &= ~VM_MAYWRITE;
#else
    vm_flags_set(vma, VM_IO);
    vm_flags_set(vma, VM_PFNMAP);
    vm_flags_set(vma, VM_DONTEXPAND);
    vm_flags_set(vma, VM_DONTDUMP);
    vm_flags_clear(vma, VM_MAYWRITE);
#endif

    root = &kdump->imap_root.rb_root;
    for(p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        struct kdump_memory_node* node = (struct kdump_memory_node*) p;
        if(node->phys_addr == 0)
            continue;

        ret = remap_pfn_range(vma, vma->vm_start + offset,
                            __phys_to_pfn(node->phys_addr), node->end - node->start + 1,
                            vma->vm_page_prot);
        if(ret && warned < 10) {
            // Warn and keep going!
            pr_warn("failed to remap physical page to userspace mapping (%zu), err=%d", offset, ret);
            warned++;
        }
        
        offset += node->end - node->start + 1;
    }

    return 0;
}

/*
 * Check whether provided address is in virtual memory layout dump
 */
bool kdump_tree_contains(struct kdump_memory_map* kdump, uint64_t addr, size_t len) {
    return interval_tree_iter_first(&kdump->imap_root, addr, addr + len) != NULL;
}
EXPORT_SYMBOL_GPL(kdump_tree_contains);

size_t kdump_tree_total_size(struct kdump_memory_map* kdump) {
    size_t size = 0;
    struct rb_root* root;
    struct rb_node* p;

    root = &kdump->imap_root.rb_root;
    for(p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        struct kdump_memory_node* node = (struct kdump_memory_node*) p;
        size += node->end - node->start + 1;
    }
    return size;
}

/*******************************************************
 * LOW LEVEL STUFF
 *******************************************************/
/*
 * kdump_get_kernel_pgd - get pointer to kernel's Global Page Directory
 *
 * This is kinda tricky. Normally to acquire translation table we would
 *  directly use swapper_pg_dir global or _init_mm structure (which also
 *  holds the reference to swapper_pg_dir). However, kernel developers
 *  decided to limit access to some kernel symbols from loadable modules,
 *  including the ones we need.
 * 
 * Therefore, instead of giving up, we're directly extracting pointer to 
 *  Global Page Directory (PGD) from processor's register TTBR1_EL1 (ARM)
 *  or CR3 (x86).
 * 
 * For more details, please refer to "ARMv8-A Architecture Reference Manual"
 *  section D13.2.138 (p. 3764) and "Intel 64 and IA-32 Architectures 
 *  Software Developer’s Manuals" volume 3 section 4.5.2 (p. 2934)
 */

#ifdef CONFIG_ARM64
static pgd_t* kdump_get_kernel_pgd(void) {
    pgd_t* swapper_pgd;
    uint64_t ttbr1_el1, baddr;

    asm volatile(
        "mrs %0, TTBR1_EL1;" 
        : "=r"(ttbr1_el1)
    );

    baddr = ttbr1_el1 & 0xFFFFFFFFFFFEULL;
    swapper_pgd = (pgd_t*) __phys_to_kimg(baddr);

    return swapper_pgd;
}

#elif CONFIG_X86_64
static pgd_t* kdump_get_kernel_pgd(void) {
    pgd_t* swapper_pgd;

    swapper_pgd = (pgd_t*) __va(read_cr3_pa());
    
    return swapper_pgd;
}

#else 
#error "Kflat module supports only x86 and ARM64 architectures"
#endif

/*
 * Linux virutal memory abstraction layer is not as abstract as you
 *  might think. Therefore, we need to declare same wrappers for
 *  code compatibility between ARM and x86_64 architectures
 */
#ifdef CONFIG_X86_64
static inline int pud_sect(pud_t pud) {
    return pud_large(pud);
}

static inline int pmd_sect(pmd_t pmd) {
    return pmd_large(pmd);
}
#endif


/*
 * Handle disabled Top-Byte-Ignore (TBI) feature
 *  Before testing address in walk_addr function, we optionally
 *  clear the top bits of address using kernel's arch_kasan_reset_tag
 *  function. This is done, because on newer ARM processors with MTE
 *  extension, the top byte of address is used for storing TAG and
 *  should be ignored in VA translation.
 * 
 *  Kernel's macro arch_kasan_reset_tag assumes that when kernel is built
 *  with CONFIG_KASAN_HW_TAGS, it will have TBI feature enabled. However
 *  on our test devices, there were a few kernel builds that eventhough
 *  had this kernel config enabled, TBI feature remained disabled.
 * 
 *  Therefore we're manually checking the content of MMU configuration
 *  register (TCR_EL1) to see if TBI is enabled or not and handle
 *  top-byte clearing accordingly.
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
static void* kasan_reset_tag(void* addr) { return addr; }
#endif

#ifdef CONFIG_ARM64
static int tbi_is_enabled = 0;

static inline void tbi_check(void) {
    uint64_t tcr_el1;
    asm volatile(
        "mrs %0, TCR_EL1;" 
        : "=r"(tcr_el1)
    );

    if(tcr_el1 & (1ULL << 38))
        tbi_is_enabled = 1;
    
#ifdef CONFIG_KASAN_HW_TAGS
    if(!tbi_is_enabled)
        pr_notice("Top-bytes-ignore feature is disabled even"
            " though CONFIG_KASAN_HW_TAGS is enabled");
#endif
}

static inline void* ptr_reset_tag(void* addr) {
    if(tbi_is_enabled)
        return kasan_reset_tag(addr);
    return addr;
}

#elif CONFIG_X86_64
static inline void* ptr_reset_tag(void* addr) {
    return kasan_reset_tag(addr);
}
#endif


/*******************************************************
 * RESOURCES DISCOVERING
 *******************************************************/
struct kdump_iomem_res_entry {
    struct list_head list;
    uint64_t start;
    uint64_t end;
};
LIST_HEAD(kdump_system_ram);

static struct resource* r_next(struct resource* p) {
    if (p->child)
        return p->child;
    while (!p->sibling && p->parent)
        p = p->parent;
    return p->sibling;
}

static void kdump_uncollect_iomem(void) {
    struct kdump_iomem_res_entry* entry, *n;

    list_for_each_entry_safe(entry, n, &kdump_system_ram, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

static int kdump_collect_iomem_ram(void) {
    int ret, cnt = 0;
    struct resource* res = &iomem_resource;
    struct kdump_iomem_res_entry* entry;

    // xxx In theory race condition could occur here,
    //  but it's hard to lock mutex which isn't exported...

    for(res = res->child; res != NULL; res = r_next(res)) {
        if((res->flags & IORESOURCE_SYSTEM_RAM) == IORESOURCE_SYSTEM_RAM) {
            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
            if(entry == NULL) {
                ret = -ENOMEM;
                goto err;
            }
            
            entry->start = res->start;
            entry->end = res->end;
            list_add(&entry->list, &kdump_system_ram);
            cnt++;
        }
    }

    pr_info("discovered %d regions of System Ram", cnt);
    return 0;

err:
    kdump_uncollect_iomem();
    return ret;
}

static int kdump_is_phys_in_ram(uint64_t addr) {
    struct kdump_iomem_res_entry* entry;

    list_for_each_entry(entry, &kdump_system_ram, list) {
        if(entry->start <= addr && addr < entry->end)
            return true;
    }

    return false;
}


/*******************************************************
 * PAGE WALKING
 *******************************************************/
#define SIZE_TO_NEXT_PAGE(ADDR, LEVEL)      (LEVEL ## _SIZE - (addr & ~LEVEL ## _MASK))

static size_t walk_addr(pgd_t* swapper_pgd, uint64_t addr, struct page** pagep) {
    pgd_t* pgdp, pgd;
    p4d_t* p4dp, p4d;
    pud_t* pudp, pud;
    pmd_t* pmdp, pmd;
    pte_t* ptep, pte;

#ifdef CONFIG_X86_64
    uint64_t top_bits;
#endif

    *pagep = NULL;

#ifdef CONFIG_ARM64

    // Check whether address belongs to kernel VA space
    if(addr < PAGE_OFFSET)
        return SIZE_TO_NEXT_PAGE(addr, PGDIR);

#elif CONFIG_X86_64

    // Check whether provided address is canonical
    top_bits = (int64_t)addr >> __VIRTUAL_MASK_SHIFT;
    if(top_bits != -1ULL && top_bits != 0)
        return SIZE_TO_NEXT_PAGE(addr, PGDIR);

#endif

    // Walk through top-level table
    pgdp = pgd_offset_pgd(swapper_pgd, addr);
    pgd = READ_ONCE(*pgdp);
    if(pgd_none(pgd) || pgd_bad(pgd))
        return SIZE_TO_NEXT_PAGE(addr, PGDIR);

    // Proceed to second level table
    p4dp = p4d_offset(pgdp, addr);
    p4d = READ_ONCE(*p4dp);
    if(p4d_none(p4d) || p4d_bad(p4d))
        return SIZE_TO_NEXT_PAGE(addr, P4D);

    // Check PUD table - look out for Huge page entries
    pudp = pud_offset(p4dp, addr);
    pud = READ_ONCE(*pudp);
    if(pud_none(pud))
        return SIZE_TO_NEXT_PAGE(addr, PUD);
    else if(pud_sect(pud)) {
        if(pud_present(pud) && pfn_valid(pud_pfn(pud)))
            *pagep = pud_page(pud);
        return SIZE_TO_NEXT_PAGE(addr, PUD);
    }

    // Check PMD table - again, be aware of huge pages
    pmdp = pmd_offset(pudp, addr);
    pmd = READ_ONCE(*pmdp);
    if(pmd_none(pmd))
        return SIZE_TO_NEXT_PAGE(addr, PMD);
    else if(pmd_sect(pmd)) {
        if(pmd_present(pmd) && pfn_valid(pmd_pfn(pmd)))        
            *pagep = pmd_page(pmd);
        return SIZE_TO_NEXT_PAGE(addr, PMD);
    }

    // Finally, check PTE table for page entry
    ptep = pte_offset_kernel(pmdp, addr);
    pte = READ_ONCE(*ptep);
    if(!pte_none(pte) && pte_present(pte) && pfn_valid(pte_pfn(pte)))    
        *pagep = pte_page(pte);

    return SIZE_TO_NEXT_PAGE(addr, PAGE);
}

static void kdump_walk_page_range(struct kdump_memory_map* kdump, pgd_t* swapper_pgd, uint64_t start, uint64_t end) {
    int ret;
    struct page* page;
    size_t size;

    while(start < end) {
        size = walk_addr(swapper_pgd, start, &page);
        
        if(page != NULL && kdump_is_phys_in_ram(page_to_phys(page))) {
            ret = kdump_tree_add_range(kdump, start, start + size - 1, page_to_phys(page));
            if(ret)
                WARN_ONCE(1, "Kflat: kdump_tree_add_range managed to fail somehow");
        }

        // Catch pointer overflow
        if(start + size < start)
            break;
        start += size;
    }
}

void kdump_dump_vma(struct kdump_memory_map* kdump) {
    pgd_t* kernel_pgd = kdump_get_kernel_pgd();
    pr_info("Start kernel memory dump...");

#ifdef CONFIG_ARM64
    kdump_walk_page_range(kdump, kernel_pgd, (~0ULL) << VA_BITS, ~0ULL);
#elif CONFIG_X86_64
    kdump_walk_page_range(kdump, kernel_pgd, VMALLOC_START, MODULES_END);
#endif

    pr_info("Finished kernel memory dump");
}

size_t kdump_test_address(void* addr, size_t size) {
    size_t walked_size = 0;
    struct page* page;
    pgd_t* kernel_pgd;
    size_t page_offset = (uint64_t)addr & (~PAGE_MASK);

    addr = ptr_reset_tag(addr);
    addr = (void*)((unsigned long)addr & ~(PAGE_SIZE - 1)); 

    /* Fast path for NULL pointer addresses */
	if (addr == NULL)
		return 0;
    
    kernel_pgd = kdump_get_kernel_pgd();
    for(walked_size = 0; walked_size < size + page_offset;) {
        size_t ret_size = walk_addr(kernel_pgd, (uint64_t) addr + walked_size, &page);
        if(page == NULL || !kdump_is_phys_in_ram(page_to_phys(page)))
            break;
        
        walked_size += ret_size;
    }

    if(walked_size > 0)
        walked_size -= page_offset;

    return walked_size;
}
EXPORT_SYMBOL_GPL(kdump_test_address);

/*******************************************************
 * KASAN misc tools
 *******************************************************/
#if defined(KASAN)
/**
 * @brief Perform mempcy after clearing KASAN tags from both pointers and with
 *      kasan report temprarly disable. This allows us to memcpy incorrect memory
 *      (for instance, SLUB redzone) without triggering Kernel panic
 */
void* hwasan_safe_memcpy(void* dst, const void* src, size_t size) {
    void* ret;
    dst = ptr_reset_tag(dst);
    src = ptr_reset_tag(src);

    kasan_disable_current();
    ret = memcpy(dst, src, size);
    kasan_enable_current();
    
    return ret;
}
#else
void* hwasan_safe_memcpy(void* dst, const void* src, size_t size) {
    return memcpy(dst, src, size);
}
#endif

/*******************************************************
 * (De)initialization
 *******************************************************/
int kdump_init(void) {

#ifdef CONFIG_ARM64
    tbi_check();
#endif

    return kdump_collect_iomem_ram();
}

void kdump_exit(void) {
    kdump_uncollect_iomem();
}
