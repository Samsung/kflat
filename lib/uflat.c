/**
 * @file uflat.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Userspace FLAT (UFLAT) API implementation
 * 
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "uflat.h"

enum mem_prot {
    UFLAT_MEM_PROT_READ     = (1 << 0),
    UFLAT_MEM_PROT_WRITE    = (1 << 1),
    UFLAT_MEM_PROT_EXEC     = (1 << 2),
};

struct udump_memory_node {
    struct rb_node rb;
    uint64_t __subtree_last;

    uint64_t start;
    uint64_t end;
    uint16_t prot;
};

struct udump_memory_map {
    struct rb_root_cached imap_root;
};


void udump_destroy(struct udump_memory_map* mem);
int udump_dump_vma(struct udump_memory_map* mem);


/*
 * Flatten API
 */
volatile int debug_flag = false;
int verbose_flag = false;
func_symbol_info *func_sym_table = NULL;
size_t func_sym_table_n_entries = 0;


struct uflat* uflat_init(const char* path) {
    int rv;
    struct uflat* uflat;

    uflat = (struct uflat*) calloc(1, sizeof(*uflat));
    if(uflat == NULL) {
        FLATTEN_LOG_ERROR("Failed to initialize uflat - out-of-memory");
        return NULL;
    }

    uflat->udump_memory = (struct udump_memory_map*) calloc(1, sizeof(struct udump_memory_map));
    if(uflat->udump_memory == NULL) {
        FLATTEN_LOG_ERROR("Failed to initialize kflat - out-of-memory on udump_memory");
        free(uflat);
        return NULL;
    }

    rv = udump_dump_vma(uflat->udump_memory);
    if(rv) {
        FLATTEN_LOG_ERROR("Failed to initialize uflat - udump_dump_vma returned (%d)", rv);
        goto err_flat_allocated;
    }

    flatten_init(&uflat->flat);
    rv = uflat->flat.error;
    if(rv) {
        FLATTEN_LOG_ERROR("Failed to initialize uflat - flatten_init returned (%d)", rv);
        goto err_udump_created;
    }

    // Prepare output file
    uflat->out_size = UFLAT_DEFAULT_OUTPUT_SIZE;
    uflat->out_name = strdup(path);
    uflat->out_fd = open(path, O_RDWR | O_CREAT, 0664);
    if(uflat->out_fd < 0) {
        FLATTEN_LOG_ERROR("Failed to create output file - %s", strerror(errno));
        goto err_open;
    }
    
    rv = ftruncate(uflat->out_fd, uflat->out_size);
    if(rv) {
        FLATTEN_LOG_ERROR("Failed to truncate output file - %s", strerror(errno));
        goto err_mmap;
    }
    uflat->out_mem = mmap(0, uflat->out_size, PROT_READ | PROT_WRITE, 
        MAP_SHARED, uflat->out_fd, 0);
    if(uflat->out_mem == MAP_FAILED) {
        FLATTEN_LOG_ERROR("Failed to mmap output file - %s", strerror(errno));
        goto err_mmap;
    }

    uflat->flat.area = uflat->out_mem;
    uflat->flat.size = uflat->out_size;

    // Initialize symbol address resolution engine
    func_sym_table = get_symbol_to_name_mapping(&func_sym_table_n_entries);

    return uflat;

err_mmap:
    close(uflat->out_fd);
err_open:
    free(uflat->out_name);
err_udump_created:
    udump_destroy(uflat->udump_memory);
err_flat_allocated:
    free(uflat->udump_memory);
    free(uflat);
    return NULL;
}

void uflat_fini(struct uflat* uflat) {
    if(uflat == NULL)
        return;

    munmap(uflat->out_mem, uflat->out_size);
    close(uflat->out_fd);
    free(uflat->out_name);

    flatten_fini(&uflat->flat);
    udump_destroy(uflat->udump_memory);
    free(uflat->udump_memory);
    free(uflat);

    cleanup_symbol_to_name_mapping(func_sym_table, func_sym_table_n_entries);

    FLATTEN_LOG_DEBUG("Deinitialized uflat");
}

int uflat_set_option(struct uflat* uflat, enum uflat_options option, unsigned long value) {
    if(option >= UFLAT_OPT_MAX) {
        FLATTEN_LOG_ERROR("Invalid option %d provided to uflat_set_option", (int)option);
        return -EINVAL;
    }

    switch(option) {
        case UFLAT_OPT_DEBUG:
            uflat->flat.FLCTRL.debug_flag = value;
            debug_flag = value;
            // [[fallthrough]];
        
        case UFLAT_OPT_VERBOSE:
            // TODO:
            verbose_flag = value;
            // uflat->flat.FLCTRL.vebose_flag = 1;
            break;

        case UFLAT_OPT_OUTPUT_SIZE: {
                munmap(uflat->out_mem, uflat->out_size);
                uflat->out_size = value;
                
                int rv = ftruncate(uflat->out_fd, uflat->out_size);
                if(rv) {
                    FLATTEN_LOG_ERROR("Failed to truncate output file - %s", strerror(errno));
                    uflat->flat.error = EIO;
                    return errno;
                }

                uflat->out_mem = mmap(0, uflat->out_size, PROT_READ | PROT_WRITE, 
                    MAP_SHARED, uflat->out_fd, 0);
                if(uflat->out_mem == MAP_FAILED) {
                    FLATTEN_LOG_ERROR("Failed to mmap output file - %s", strerror(errno));
                    uflat->flat.error = EIO;
                    return errno;
                }

                uflat->flat.area = uflat->out_mem;
                uflat->flat.size = uflat->out_size;
            }
            break;

        case UFLAT_OPT_SKIP_MEM_FRAGMENTS:
            uflat->flat.FLCTRL.mem_fragments_skip = value & 1;
            break;

        case UFLAT_OPT_SKIP_MEM_COPY:
            uflat->flat.FLCTRL.mem_copy_skip = value & 1;
            break;
        
        default:
            FLATTEN_LOG_ERROR("Invalid option provided to uflat_set_option (%d)", option);
            break;
    }
    FLATTEN_LOG_DEBUG("Set option %d to value %ld", option, value);
    return 0;
}

int uflat_write(struct uflat* uflat) {
    int rv = 0;

    if(uflat == NULL)
        return -EFAULT;

    FLATTEN_LOG_DEBUG("Starting uflat_write to file `%s`", uflat->out_name);
    rv = flatten_write(&uflat->flat);
    if(rv != 0) {
        FLATTEN_LOG_ERROR("Failed to write uflat image - flatten_write returned (%d)", rv);
        return rv;
    }

    size_t to_write = ((struct flatten_header*)uflat->out_mem)->image_size;
    rv = ftruncate(uflat->out_fd, to_write);
    if(rv)
        FLATTEN_LOG_ERROR("Failed to truncute output file to its final size - %s", strerror(errno));
    FLATTEN_LOG_DEBUG("Saved uflat image of size %zu bytes", to_write);

    return 0;
}


/*
 * Debug logging
 */
void uflat_dbg_log_clear(void) {}

void uflat_dbg_log_printf(const char* fmt, ...) {
    va_list args;

    if(!debug_flag)
        return;

    va_start(args, fmt);
    vprintf(fmt, args);
	va_end(args);
}

void uflat_info_log_print(const char* fmt, ...) {
    va_list args;
    
    if(!verbose_flag)
        return;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/*
 * Memory regions collection
 */
#define START(node) ((node)->start)
#define END(node)  ((node)->end)

INTERVAL_TREE_DEFINE(struct udump_memory_node, rb,
		     uintptr_t, __subtree_last,
		     START, END,
			 static __attribute__((used)), memory_tree)

static uint16_t udump_str_to_prot(char str[4]) {
    uint16_t prot = 0;

    if(str[0] == 'r')
        prot |= UFLAT_MEM_PROT_READ;
    if(str[1] == 'w')
        prot |= UFLAT_MEM_PROT_WRITE;
    if(str[2] == 'x')
        prot |= UFLAT_MEM_PROT_EXEC;

    return prot;
}

static int udump_tree_add_range(struct udump_memory_map* mem, uint64_t start, uint64_t end, uint16_t prot) {
    struct udump_memory_node* node;

    if(memory_tree_iter_first(&mem->imap_root, start, end) != NULL) {
        // There's already such interval in our tree
        return -EFAULT;
    }

    node = memory_tree_iter_first(&mem->imap_root, start - 1, start - 1);
    if(node && node->prot == prot) {
        // Extend the existing node to the right
        memory_tree_remove(node, &mem->imap_root);
        node->end = end;
        memory_tree_insert(node, &mem->imap_root);
        return 0;
    }

    node = memory_tree_iter_first(&mem->imap_root, end + 1, end + 1);
    if(node && node->prot == prot) {
        // Extend node to the left
        memory_tree_remove(node, &mem->imap_root);
        node->start = start;
        memory_tree_insert(node, &mem->imap_root);
        return 0;
    }

    // Create a new node
    size_t alloc_size = ALIGN(sizeof(*node),__alignof__(unsigned long long));
    node = (struct udump_memory_node*) malloc(alloc_size);
    if(node == NULL)
        return -ENOMEM;
    node->start = start;
    node->end = end;
    node->prot = prot;
    memory_tree_insert(node, &mem->imap_root);
    return 0;
}

void udump_print_vma(struct udump_memory_map* mem) {
    struct rb_root* root;
    struct rb_node* p;

    FLATTEN_LOG_INFO("Content of VMA tree map:");
    root = &mem->imap_root.rb_root;
    for(p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        char mode[4] = {0};
        struct udump_memory_node* node = (struct udump_memory_node*) p;
        
        if(node->prot & UFLAT_MEM_PROT_READ)
            mode[0] = 'r';
        if(node->prot & UFLAT_MEM_PROT_WRITE)
            mode[1] = 'w';
        if(node->prot & UFLAT_MEM_PROT_EXEC)
            mode[2] = 'x';

        FLATTEN_LOG_INFO("\t%lx-%lx %s", node->start, node->end, mode);
    }
}

void udump_destroy(struct udump_memory_map* mem) {
    struct rb_node * p = rb_first(&mem->imap_root.rb_root);
    while(p) {
        struct udump_memory_node* node = (struct udump_memory_node*)p;
        rb_erase(p, &mem->imap_root.rb_root);
        p = rb_next(p);
        free(node);
    }
}

int udump_dump_vma(struct udump_memory_map* mem) {
    FILE* fp;
    char* line = NULL;
    size_t len = 0, count = 0;
    ssize_t read;

    fp = fopen("/proc/self/maps", "r");
    if(fp == NULL) {
        FLATTEN_LOG_ERROR("Failed to open /proc/self/maps - %s", strerror(errno));
        return -EFAULT;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        uint64_t start, end;
        char prot[5];
        
        if(read < 0)
            continue;

        int n = sscanf(line, "%lx-%lx %4s", &start, &end, prot);
        if(n == 3) {
            udump_tree_add_range(mem, start, end - 1, udump_str_to_prot(prot));
            count++;
        }
    }

    free(line);
    fclose(fp);

    if(count <= 0) {
        FLATTEN_LOG_ERROR("Failed to parse any line (count == 0)");
        return -EFAULT;
    }

    FLATTEN_LOG_DEBUG("Detected %zu continous regions in process VMA", count);
    return 0;
}

static size_t uflat_test_address(struct uflat* uflat, void* ptr, size_t size) {
    struct udump_memory_node* node;

    node = memory_tree_iter_first(&uflat->udump_memory->imap_root, (uintptr_t)ptr, (uintptr_t)ptr + size - 1);
    if(node == NULL || !(node->prot & UFLAT_MEM_PROT_READ))
        return 0;
    
    ssize_t remaining = (uintptr_t)node->end - (uintptr_t)ptr + 1;
    return (remaining < (ssize_t) size) ? remaining : size;
}

bool uflat_test_address_range(struct flat* flat, void* ptr, size_t size) {
    struct uflat* uflat = container_of(flat, struct uflat, flat);
    
    if(size == 0 || ptr == NULL)
        return false;

    ssize_t remaining = uflat_test_address(uflat, ptr, size);
    if(remaining <= 0 || (size_t) remaining < size) {
        // Check if there are any new mapping
        udump_destroy(uflat->udump_memory);
        udump_dump_vma(uflat->udump_memory);

        ssize_t remaining = uflat_test_address(uflat, ptr, size);
        if(remaining <= 0 || (size_t) remaining < size) {
            FLATTEN_LOG_INFO("Failed to access memory at %lx@%zu - access violation", (uintptr_t) ptr, size);
            return false;
        }
    }

    return true;
}

bool uflat_test_exec_range(struct flat* flat, void* ptr) {
    struct udump_memory_node* node;
    struct uflat* uflat = container_of(flat, struct uflat, flat);

    node = memory_tree_iter_first(&uflat->udump_memory->imap_root, (uintptr_t)ptr, (uintptr_t)ptr);
    if (node == NULL) {
        // Check if there are any new mapping
        udump_destroy(uflat->udump_memory);
        udump_dump_vma(uflat->udump_memory);

        node = memory_tree_iter_first(&uflat->udump_memory->imap_root, (uintptr_t)ptr, (uintptr_t)ptr);
        if(node == NULL) {
            FLATTEN_LOG_INFO("Failed to access memory at %lx - access violation", (uintptr_t) ptr);
            return false;
        }
    }

    if(!(node->prot & UFLAT_MEM_PROT_EXEC)) {
        FLATTEN_LOG_INFO("Failed to access code memory at %p - non-executable area", ptr);
        return false;
    }

    return true;
}

__attribute__((no_sanitize("address"))) size_t uflat_test_string_len(struct flat* flat, const char* str) {
	size_t str_size, avail_size, test_size;
    struct uflat* uflat = container_of(flat, struct uflat, flat);
	
	// 1. Fast-path. Check whether first 1000 bytes are maped
	//  and look for null-terminator in there
	avail_size = uflat_test_address(uflat, (void*) str, 1000);
	if(avail_size == 0)
		return 0;

	str_size = strnlen(str, avail_size);
	if(str_size < avail_size)
		// Return string length + null terminator
		return str_size + 1;
	
	// 2. Slow-path. We haven't encountered null-terminator in first
	//  1000 bytes, let's look futher
	test_size = 8 * 4096;
	while(test_size < INT_MAX) {
		size_t partial_size;
		size_t off = avail_size;

		partial_size = uflat_test_address(uflat, (char*)str + off, test_size);
		if(partial_size == 0)
			return avail_size;
		avail_size += partial_size;
		
		str_size = strnlen(str + off, partial_size);
		if(str_size < partial_size)
			return off + str_size + 1;
		test_size *= 2;
	}

	return avail_size;
}


/*
 * Function names resolution
 */
size_t flatten_func_to_name(char* name, size_t size, void* func_ptr) {
    int rv;
    Dl_info info;
    static bool not_ready_warn_issued = false;

    if (func_sym_table == NULL) {
        if(!not_ready_warn_issued) {
            FLATTEN_LOG_ERROR("Failed to initialize symbol address resolution engine");
            not_ready_warn_issued = true;
        }
        memset(name, 0, size);
        return 0;
    }

    if (func_ptr == NULL) {
        FLATTEN_LOG_INFO("Failed to symbolize function - NULL pointer given", func_ptr);
        memset(name, 0, size);
        return 0;
    }

    rv = dladdr(func_ptr, &info);

    // If dladdr returned 0, the address could not be matched to a shared object. Then, search local symbols. 
    if (rv == 0 || info.dli_sname == NULL) {
        if (func_sym_table == NULL){
            FLATTEN_LOG_INFO("Failed to symbolize function at address %p - symbol name lookup engine is not initialized", func_ptr);
            memset(name, 0, size);
            return 0;
        }
    
        const char *symbol_name = lookup_func_by_address(func_sym_table, func_sym_table_n_entries, (unsigned long) func_ptr);

        if(symbol_name == NULL) {
            FLATTEN_LOG_INFO("Failed to symbolize function at address %p - no symbol found with given address", func_ptr);
            memset(name, 0, size);
            return 0;
        } 
        else {
            strncpy(name, symbol_name, size);
            FLATTEN_LOG_DEBUG("Resolved func ptr %p to name `%s` (found among local symbols)", func_ptr, name);
            return strlen(name);
        }
    } 
    // Address matched to a symbol from a shared object 
    else {
        strncpy(name, info.dli_sname, size);
        FLATTEN_LOG_DEBUG("Resolved func ptr %p to name `%s` (found in %s)", func_ptr, info.dli_sname, info.dli_fname);
        return strlen(name);
    }
}

void* hwasan_safe_memcpy(void* dst, const void* src, size_t size) {
    return memcpy(dst, src, size);
}

/*
 * Image relocation
 */
#define UFLAT_IMAGE_REGION_START    0x100000000000ULL
#define UFLAT_IMAGE_REGION_SIZE     0x200000000000ULL
#define UFLAT_IMAGE_SLICE_SIZE      0x400000000
#define UFLAT_IMAGE_SLICE_COUNT     ((UFLAT_IMAGE_REGION_SIZE - 1) / UFLAT_IMAGE_SLICE_SIZE)

uintptr_t uflat_image_base_addr(void) {
    int number;
    srand(time(NULL));
    number = rand() % UFLAT_IMAGE_SLICE_COUNT;
    return UFLAT_IMAGE_REGION_START + number * UFLAT_IMAGE_SLICE_SIZE;
}
