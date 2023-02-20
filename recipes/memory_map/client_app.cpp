/**
 * @file client_app.c
 * @author Pawel Wieczorek (p.wieczorek@samsung.com)
 * @brief User application presenting the content of memory dump performed
 *      by mem_map_recipe.ko module
 */
#include <cerrno>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <unflatten.hpp>
#include <unordered_set>

#define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

extern "C" {
#include <kflat_uapi.h>
#include "interval_tree_generic.h"
}


/*
 * Data types and global constants
 */
const char* KFLAT_NODE = "/sys/kernel/debug/kflat";

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

#define START(node) ((node)->start)
#define LAST(node)  ((node)->end)

INTERVAL_TREE_DEFINE(struct kdump_memory_node, rb,
		     uint64_t, __subtree_last,
		     START, LAST, __attribute__((used)), intervals)

/*
 * Intializes KFLAT, invokes target function and saves memory dump
 */
void perform_dump() {
    int fd;
    size_t mem_size = 50 * 1000 * 1000; // 50MB

    fd = open(KFLAT_NODE, O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "Failed to open %s - %s\n", KFLAT_NODE, strerror(errno));
        exit(1);
    }

    void* mem = mmap(NULL, mem_size, PROT_READ, MAP_PRIVATE, fd, KFLAT_MMAP_FLATTEN);
    if(mem == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap KFLAT vmalloc memory - %s\n", strerror(errno));
        exit(1);
    }

    struct kflat_ioctl_enable enable = {0};
    enable.pid = getpid();
    enable.debug_flag = 1;
    strcpy(enable.target_name, "kdump_tree_destroy");
    
    int ret = ioctl(fd, KFLAT_PROC_ENABLE, &enable);
    if(ret) {
        fprintf(stderr, "Failed to enable KFLAT IOCTL - %s\n", strerror(errno));
        exit(1);
    }
    
    // Execute target function
    struct kflat_ioctl_mem_map map = {0};
    ioctl(fd, KFLAT_MEMORY_MAP, &map);

    // Dump image
    struct kflat_ioctl_disable disable ={0};
    ret = ioctl(fd, KFLAT_PROC_DISABLE, &disable);
    if(ret) {
        fprintf(stderr, "Failed to disable KFLAT IOCTL - %s\n", strerror(errno));
        exit(1);
    }

    if(!disable.invoked) {
        fprintf(stderr, "KFLAT probe hasn't been invoked\n");
        exit(1);
    } else if(disable.error != 0) {
        fprintf(stderr, "KFLAT flattening engine encountered an error\n");
        exit(1);
    }

    // Save dumped kernel memory to file
    FILE* f = fopen("mem_map.bin", "w");
    if(f == NULL) {
        fprintf(stderr, "Failed to fopen output file - %s\n", strerror(errno));
        exit(1);
    }
    fwrite(mem, disable.size, 1, f);
    fclose(f);

    // Cleanup
    munmap(mem, mem_size);
    close(fd);
}

/*
 * Set of functions extracting useful data from memory dump
 */
void print_kallsyms_info(struct kdump_memory_map* mem, const char* symbol) {
    uint64_t addr, phys_addr = 0;
    char name[256], mod[256];
    struct kdump_memory_node* node;

    FILE* file = fopen("/proc/kallsyms", "rb");
    if(file == NULL) {
        printf("Failed to open /proc/kallsyms\n");
        exit(1);
    }

    int ret;
    do {
        ret = fscanf(file, "%lx %*c %256s\t[%256s]\n", &addr, name, mod);
        if(ret >= 2 && !strcmp(name, symbol))
            break;
        addr = -1;
    } while(ret > 0);

    if(addr == -1) {
        printf("Failed to locate symbol `%s` in kallsyms\n", symbol);
        exit(1);
    }

    node = intervals_iter_first(&mem->imap_root, addr, addr + 1);
    if(node) {
        phys_addr = node->phys_addr + (addr - node->start);
    }
    printf("\t [%s]: 0x%lx ==> 0x%lx\n", symbol, addr, phys_addr);
}

size_t calc_size_of_va_mem(struct kdump_memory_map* mem) {
    size_t size = 0;
    struct kdump_memory_node* node;
    
    struct rb_root* root = &mem->imap_root.rb_root;
    for(struct rb_node* p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        node = (struct kdump_memory_node*) p;
        size += node->end - node->start;
	}

    return size;
}

size_t calc_size_of_phys_mem(struct kdump_memory_map* mem) {
    // Do the same things as in calc_size_of_va_mem(...), but
    //  ignore repeating phys_addr nodes
    size_t size = 0;
    struct kdump_memory_node* node;
    std::unordered_set<uint64_t> phys_addresses;

    struct rb_root* root = &mem->imap_root.rb_root;
    for(struct rb_node* p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        node = (struct kdump_memory_node*) p;
        if(phys_addresses.end() == phys_addresses.find(node->phys_addr)) {
            size += node->end - node->start;
            phys_addresses.emplace(node->phys_addr);
        }
	}

    return size;
}

/*
 * Present human-friendly content to user
 */
void process_dump() {
    int ret;
    Flatten flatten;

    FILE* f = fopen("mem_map.bin", "r");
    flatten.load(f, NULL);

    // Process loaded image
    struct kdump_memory_node* node;
    struct kdump_memory_map* mem = (struct kdump_memory_map*) flatten.get_named_root("memory_map", NULL);

    // Print a few kernel pages
    printf("First few Kernel pages: \n");
    int i = 0;
    struct rb_root* root = &mem->imap_root.rb_root;
    for(struct rb_node* p = rb_first_postorder(root); p != NULL && i < 20; i++, p = rb_next_postorder(p)) {
        node = (struct kdump_memory_node*) p;
        printf("\t(0x%lx-0x%lx) => 0x%lx\n", node->start, node->end, node->phys_addr);
	}

    // Resolve example kallsyms symbols
    printf("\nLooking up physical address of common kernel functions:\n");
    print_kallsyms_info(mem, "__kmalloc");
    print_kallsyms_info(mem, "__memcpy");
    print_kallsyms_info(mem, "flatten_write");

    // Print amount of system memory
    printf("\nTotal amount of virtual memory allocated: %zuMB\n", calc_size_of_va_mem(mem) / 1024 / 1024);
    printf("Total amount of physical memory allocated: %zuMB\n", calc_size_of_phys_mem(mem) / 1024 / 1024);

    // Clean up
    flatten.unload();
    fclose(f);
}


int main() {
    perform_dump();
    process_dump();
}