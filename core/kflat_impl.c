/**
 * @file kflat_impl.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Main implementation of kflat fast serialization
 *
 */

#include "kflat.h"

#include <linux/interval_tree_generic.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>

#ifdef KFLAT_GET_OBJ_SUPPORT
#include <linux/sched/task_stack.h>

/* Nasty include, but we need some of the macros that for whatever
 *  reasons are stored in header files located outside of include/ dir */
#include "../../mm/slab.h"
#endif /* KFLAT_GET_OBJ_SUPPORT */

#ifndef __nocfi
#define __nocfi
#endif

/*******************************************************
 * GLOBAL VARIABLES SUPPORT
 *******************************************************/
lookup_kallsyms_name_t kflat_lookup_kallsyms_name;
kallsyms_lookup_t kflat_kallsyms_lookup;

__nocfi void* flatten_global_address_by_name(const char* name) {
    void* addr;

    if(kflat_lookup_kallsyms_name == NULL) {
        pr_warn("failed to obtain an address of global variable '%s' - kallsyms is not initialized", name);
        return NULL;
    }

    addr = (void*)kflat_lookup_kallsyms_name(name);

    if(addr == NULL)
        pr_warn("failed to obtain an address of global variable '%s'", name);
    return addr;
}
EXPORT_SYMBOL_GPL(flatten_global_address_by_name);

/***************************************************************
 * Detect compilier optimizations that shrink variables' size
 ***************************************************************/
/*
 * If optimization was detected, return the actual in-memory size.
 * If no optimization was detected, return 0.
 */
__nocfi int flatten_validate_inmem_size(unsigned long address, size_t expected_size) {
    char namebuf[KSYM_NAME_LEN];
    char orig_name[KSYM_NAME_LEN];
    char* modname;
    const char* ret;
    unsigned long offset;

    if(kflat_kallsyms_lookup == NULL) {
        pr_warn("failed to lookup kernel symbols - kallsyms is not initialized");
        return -EFAULT;
    }

    if(kflat_kallsyms_lookup(address, NULL, NULL, &modname, orig_name) == NULL)
        return -EINVAL;

    for(size_t i = 1; i < expected_size; i++) {
        ret = kflat_kallsyms_lookup(address + i, NULL, &offset, NULL, namebuf);
        // If a symbol is found and its offset is zero, we hit exactly the beginning of some symbol.
        if(ret && offset == 0) {
            if(modname)
                pr_warn("Found compiler optimization. Symbol %s [%s] was optimized to %zu bytes.\n", orig_name, modname, i);
            else
                pr_warn("Found compiler optimization. Symbol %s was optimized to %zu bytes.\n", orig_name, i);
            return i;
        }
    }

    return 0;
}
EXPORT_SYMBOL_GPL(flatten_validate_inmem_size);

/*******************************************************
 * DYNAMIC OBJECTS RESOLUTION
 *******************************************************/
#ifdef KFLAT_GET_OBJ_SUPPORT
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
static void* kasan_reset_tag(void* addr) {
    return addr;
}
#endif

bool check_kfence_address(void* ptr, void** start, void** end) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
    // KFENCE support has been added in Linux kernel 5.12.0
    return false;
#else

    /* Use __kfence_pool from kallsyms to support devices that does not export
     *  this symbol to loadable kernel modules
     */
    static char* _kfence_pool = NULL;
    if(READ_ONCE(_kfence_pool) == NULL) {
        WRITE_ONCE(_kfence_pool, flatten_global_address_by_name("__kfence_pool"));
        if(_kfence_pool == NULL) {
            WARN_ONCE(1, "__kfence_pool is not available in kallsyms");
            return false;
        }
    }

    if((unsigned long)((char*)ptr - _kfence_pool) >= KFENCE_POOL_SIZE)
        return false;

    // KFENCE always allocates full kernel page
    *start = (void*)((uint64_t)ptr & PAGE_MASK);
    *end = (void*)((uint64_t)*start + PAGE_SIZE);
    return true;
#endif
}

bool is_percpu_address(void* ptr) {
    // Extract neccessary functions from kallsyms
    static typeof(is_module_percpu_address)* func_is_module_percpu_address = NULL;
    static typeof(is_kernel_percpu_address)* func_is_kernel_percpu_address = NULL;

    if(func_is_module_percpu_address == NULL) {
        func_is_module_percpu_address = flatten_global_address_by_name("is_module_percpu_address");
        if(func_is_module_percpu_address == NULL) {
            WARN_ONCE(1, "is_module_percpu_address is not available in kallsyms");
            return false;
        }
    }

    if(func_is_kernel_percpu_address == NULL) {
        func_is_kernel_percpu_address = flatten_global_address_by_name("is_kernel_percpu_address");
        if(func_is_kernel_percpu_address == NULL) {
            WARN_ONCE(1, "is_kernel_percpu_address is not available in kallsyms");
            return false;
        }
    }

    return func_is_kernel_percpu_address((unsigned long)ptr) || func_is_module_percpu_address((unsigned long)ptr);
}

/*
 * Original implementation of kmem_cache_debug_flags can be
 * 	found in mm/slab.h
 */
static inline bool _kmem_cache_debug_flags(struct kmem_cache* s, slab_flags_t flags) {
#ifdef CONFIG_SLUB_DEBUG
    return s->flags & flags;
#else
    return false;
#endif
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 16, 0)
/* Based on __check_heap_object@mm/slub.c */
static bool _flatten_get_heap_obj(struct page* page, void* ptr, void** start, void** end) {
    off_t offset;
    size_t object_size;
    struct kmem_cache* cache;

    cache = page->slab_cache;
    ptr = kasan_reset_tag(ptr);
    if(ptr < page_address(page))
        return false;

    if(check_kfence_address(ptr, start, end))
        return true;

    /*
     * Calculate the offset between ptr and the start of the object.
     * Each object on kmem_cache heap has constant size - use modulo
     * to determine offset of pointer
     */
    offset = (ptr - page_address(page)) % cache->size;

    /*
     * When SLAB_RED_ZONE is enabled, the first few bytes of an
     *  object is in fact allocator private data.
     */
    if(_kmem_cache_debug_flags(cache, SLAB_RED_ZONE))
        offset -= cache->red_left_pad;

    if((ptr - offset) < page_address(page))
        return false;

    object_size = slab_ksize(cache);
    if(object_size <= offset)
        return false;

    if(cache->usersize != 0)
        object_size = cache->usersize;

    if(offset < cache->useroffset || cache->useroffset + object_size < offset)
        return false;

    if(start)
        *start = ptr - offset + cache->useroffset;
    if(end)
        *end = ptr - offset + cache->useroffset + object_size - 1;
    return true;
}

static void* flatten_find_heap_object(void* ptr) {
    struct page* page;

    page = compound_head(kmap_to_page(ptr));
    if(page == NULL)
        return NULL;

    if(PageSlab(page))
        return page;
    return NULL;
}

#else
/* Based on __check_heap_object@mm/slub.c */
static bool _flatten_get_heap_obj(struct slab* slab, void* orig_ptr,
                                  void** start, void** end) {
    off_t offset;
    size_t object_size;
    struct kmem_cache* cache;
    void* ptr;

    cache = slab->slab_cache;
    ptr = kasan_reset_tag(orig_ptr);
    if(ptr < slab_address(slab))
        return false;

    if(check_kfence_address(ptr, start, end))
        return true;

    /*
     * Calculate the offset between ptr and the start of the object.
     * Each object on kmem_cache heap has constant size - use modulo
     * to determine offset of pointer
     */
    offset = (ptr - slab_address(slab)) % cache->size;

    /*
     * When SLAB_RED_ZONE is enabled, the first few bytes of an
     *  object is in fact allocator private data.
     */
    if(_kmem_cache_debug_flags(cache, SLAB_RED_ZONE))
        offset -= cache->red_left_pad;
    if((ptr - offset) < slab_address(slab))
        return false;

    object_size = slab_ksize(cache);
    if(object_size <= offset)
        return false;

    if(start)
        *start = orig_ptr - offset;
    if(end)
        *end = orig_ptr - offset + object_size - 1;
    return true;
}

static void* flatten_find_heap_object(void* ptr) {
    struct folio* folio;

    folio = virt_to_folio(ptr);

    if(folio == NULL)
        return NULL;

    if(folio_test_slab(folio))
        return folio_slab(folio);
    return NULL;
}

#endif

/*
 * flatten_get_object - check whether `ptr` points to the heap or vmalloc
 *		object and if so retrieve its start and end address
 *  For instance, if there's an array `char tab[32]` allocated on heap,
 *   invoking this func with &tab[10] will set `start` to &tab[0] and
 *   `end` to &tab[31].
 *  Returns false, when pointer does not point to valid heap memory location
 */
bool flatten_get_object(struct flat* flat, void* ptr, void** start, void** end) {
    void* obj;
    struct page* head;

#ifdef CONFIG_ARM64
    static void* kernel_start = NULL;
    static void* kernel_end = NULL;
    static void* modules_start = NULL;
    static void* modules_end = NULL;

    if(kernel_start == NULL) {
        kernel_start = flatten_global_address_by_name("_stext");
        DBGS("flatten_get_object - discovered kernel start at %llx\n", kernel_start);
    }
    if(kernel_end == NULL) {
        kernel_end = flatten_global_address_by_name("_end");
        DBGS("flatten_get_object - discovered kernel start at %llx\n", kernel_end);
    }
    if(modules_start == NULL) {
#ifndef CONFIG_RKP
        u64* tmp = flatten_global_address_by_name("module_alloc_base");
        if(tmp != NULL) {
            modules_start = (void*)*tmp;
            modules_end = (void*)((uintptr_t)modules_start + MODULES_VSIZE);
            DBGS("flatten_get_object - discovered modules memory region at %llx - %llx\n", modules_start, modules_end);
        }
#endif
    }

    // Is it pointing to kernel binary (.text or .data sections)?
    if(kernel_start != kernel_end && ptr >= kernel_start && ptr <= kernel_end) {
        DBGS("flatten_get_object - ptr(%llx) is pointing to kernel image (KIMAGE)\n", ptr);
        return false;
    }

    // Is it pointing to modules section?
    if(modules_start != modules_end && ptr >= modules_start && ptr <= modules_end) {
        DBGS("flatten_get_object - ptr(%llx) is pointing to modules section\n", ptr);
        return false;
    }
#endif

    if(object_is_on_stack(ptr)) {
        DBGS("flatten_get_object - ptr(%llx) is on stack\n", ptr);
        return false;
    }

    if(is_percpu_address(ptr)) {
        DBGS("flatten_get_object - ptr(%llx) is in per_cpu section\n", ptr);
        return false;
    }

    if(is_vmalloc_addr(ptr)) {
        size_t size = kdump_test_address(ptr, INT_MAX);
        if(size == 0)
            return false;

        DBGS("flatten_get_object - ptr (%llx) is a valid vmalloc object\n", ptr);
        if(end)
            *end = ptr + size - 1;

        // Search for the start of memory
        if(start) {
            unsigned long long p = (unsigned long long)ptr;
            p &= PAGE_MASK;
            do {
                p -= PAGE_SIZE;
                size = kdump_test_address((void*)p, PAGE_SIZE);
            } while(size);
            *start = (void*)p + PAGE_SIZE;
        }
        return true;
    }

    // Vmalloc is not a valid virt_addr according to this macro
    if(!virt_addr_valid(ptr)) {
        DBGS("flatten_get_object - invalid virt ptr(%llx)\n", ptr);
        return false;
    }

    obj = flatten_find_heap_object(ptr);
    if(obj != NULL) {
        DBGS("flatten_get_object - ptr (%llx) is a valid SLAB object\n", ptr);
        return _flatten_get_heap_obj(obj, ptr, start, end);
    }

    // Check for CMA memory
    if(is_cma_memory(ptr)) {
        pr_warn("flatten_get_object - ptr (%llx) is a pointer to CMA area: return false", (unsigned long long)ptr);
        return false;
    }

    // Try retrieving object size from compound_page (used by kmalloc_large)
    head = virt_to_head_page(ptr);
    if(head != NULL) {
        DBGS("flatten_get_object - ptr (%llx) is a compound_page\n", ptr);
        if(start)
            *start = page_address(head);
        if(end) {
            unsigned int order = compound_order(head);
            size_t size = ((size_t)PAGE_SIZE) << order;
            *end = (void*)(((uintptr_t)*start) + size - 1);
        }
        return true;
    }

    DBGS("flatten_get_object - failed to detect ptr(%llx) allocation method (is it global var?)\n", ptr);
    return false;
}
#else  /* KFLAT_GET_OBJ_SUPPORT */
bool flatten_get_object(struct flat* flat, void* ptr, void** start, void** end) {
    return false;
}
#endif /* KFLAT_GET_OBJ_SUPPORT */

EXPORT_SYMBOL_GPL(flatten_get_object);

/*******************************************************
 * KFLAT RECIPES REGISTRY
 *******************************************************/
LIST_HEAD(kflat_recipes_registry);
DEFINE_MUTEX(kflat_recipes_registry_lock);

int kflat_recipe_register(struct kflat_recipe* recipe) {
    int ret = 0;
    struct kflat_recipe* entry = NULL;

    if(!recipe || !recipe->owner || !recipe->symbol || !recipe->handler) {
        pr_err("cannot register incomplete recipe");
        return -EINVAL;
    }

    mutex_lock(&kflat_recipes_registry_lock);

    // Check for name duplicates
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(!strcasecmp(entry->symbol, recipe->symbol)) {
            pr_err("cannot register the same recipe twice");
            ret = -EBUSY;
            goto exit;
        }
    }
    list_add(&recipe->list, &kflat_recipes_registry);

exit:
    mutex_unlock(&kflat_recipes_registry_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(kflat_recipe_register);

int kflat_recipe_unregister(struct kflat_recipe* recipe) {
    int ret = -EINVAL;
    struct kflat_recipe* entry;

    mutex_lock(&kflat_recipes_registry_lock);
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(entry == recipe) {
            list_del(&entry->list);
            goto exit;
        }
    }

exit:
    mutex_unlock(&kflat_recipes_registry_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(kflat_recipe_unregister);

int kflat_recipe_get_all(char* buf, size_t bufsize) {
    int i = 0;
    char* name;
    struct kflat_recipe* entry = NULL;

    memset(buf, 0, bufsize);

    mutex_lock(&kflat_recipes_registry_lock);
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        name = entry->symbol;
        if(i + strlen(name) + 1 >= bufsize)
            break;

        i += strscpy(buf + i, name, bufsize - i) + 1;
    }
    mutex_unlock(&kflat_recipes_registry_lock);

    return i;
}

struct kflat_recipe* kflat_recipe_get(char* name) {
    struct kflat_recipe *entry, *ret = NULL;

    mutex_lock(&kflat_recipes_registry_lock);
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(!strcasecmp(entry->symbol, name)) {
            ret = entry;
            break;
        }
    }
    mutex_unlock(&kflat_recipes_registry_lock);

    if(ret)
        try_module_get(ret->owner); // TODO: Error handling
    return ret;
}

void kflat_recipe_put(struct kflat_recipe* recipe) {
    if(recipe == NULL)
        return;
    module_put(recipe->owner);
}

/*******************************************************
 * FUNCTION NAME RESOLUTION
 *******************************************************/
size_t flatten_func_to_name(char* name, size_t size, void* func_ptr) {
    return scnprintf(name, size, "%ps", func_ptr);
}
