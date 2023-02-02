/**
 * @file client_app.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-02-02
 * 
 * @copyright Copyright (c) 2023
 * 
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <kflat_uapi.h>
#include <unflatten.hpp>

#define KFLAT_NODE "/sys/kernel/debug/kflat"


#define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

#include "interval_tree_generic.h"


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
		     START, LAST, __attribute__((used)), interval_tree)

/*
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

void print_kallsyms_info(struct kdump_memory_map* mem, const char* symbol) {
    printf("\t [%s]: 0x%lx\n", symbol, 0UL);
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

    struct rb_root* root = &mem->imap_root.rb_root;
    for(struct rb_node* p = rb_first_postorder(root); p != NULL; p = rb_next_postorder(p)) {
        node = (struct kdump_memory_node*) p;
        if(node->phys_addr)     // TODO: ME
            size += node->end - node->start;
	}

    return size;
}

void process_dump() {
    int ret;

    CFlatten flatten = flatten_init(0);
    if(flatten == NULL) {
        fprintf(stderr, "Failed to initialize flatten library\n");
        exit(1);
    }

    FILE* f = fopen("mem_map.bin", "r");
    ret = flatten_load(flatten, f, NULL);
    if(ret) {
        fprintf(stderr, "Failed to load flattne library");
        exit(1);
    }

    // Process loaded image
    struct kdump_memory_node* node;
    struct kdump_memory_map* mem = flatten_root_pointer_named(flatten, "memory_map", NULL);
    if(mem == NULL) {
        fprintf(stderr, "Failed to extract root pointer from kflat image\n");
        exit(1);
    }

    printf("First few Kernel pages: \n");
    int i = 0;
    struct rb_root* root = &mem->imap_root.rb_root;
    for(struct rb_node* p = rb_first_postorder(root); p != NULL && i < 20; i++, p = rb_next_postorder(p)) {
        node = (struct kdump_memory_node*) p;
        printf("\t(0x%lx-0x%lx) => 0x%lx\n", node->start, node->end, node->phys_addr);
	}

    printf("\nLooking up physical address of common kernel functions:\n");
    print_kallsyms_info(mem, "__kmalloc");
    print_kallsyms_info(mem, "__memcpy");
    print_kallsyms_info(mem, "__strcpy");

    printf("\nTotal amount of virtual memory allocated: %zuMB\n", calc_size_of_va_mem(mem) / 1024 / 1024);
    printf("Total amount of physical memory allocated: %zuMB\n", calc_size_of_phys_mem(mem) / 1024 / 1024);

    // Clean up
    flatten_deinit(flatten);
    fclose(f);
}


int main() {
    perform_dump();
    process_dump();
}