/**
 * @file flatten_image.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Definition of flatten image header
 *
 */
#ifndef FLATTEN_IMAGE_H
#define FLATTEN_IMAGE_H

#define KFLAT_IMG_MAGIC   0x4e455454414c46ULL // 'FLATTEN\0'
#define KFLAT_IMG_VERSION 0x2

struct flatten_header {
    uint64_t magic;
    uint32_t version;

    uintptr_t last_load_addr;
    uintptr_t last_mem_addr;

    size_t image_size;
    size_t memory_size;
    size_t ptr_count;
    size_t fptr_count;
    size_t root_addr_count;
    size_t root_addr_extended_count;
    size_t root_addr_extended_size;
    size_t fptrmapsz;
    size_t mcount;
};

#endif /* FLATTEN_IMAGE_H */
