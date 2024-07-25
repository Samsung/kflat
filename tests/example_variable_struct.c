/**
 * @file example_variable_struct.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

// Common structures
struct iommu_ranges {
    uint32_t    size;
    uint32_t    fd;
    uint32_t    num_ranges;
    uint32_t*   ranges;
    uint32_t    padding;
};

struct iommu_result {
    uint32_t    size;
    uint32_t    fd;
    uint32_t*   result;
};

struct iommu_data {
    uint32_t    size;
    uint32_t    fd;
    uint8_t     data[128];
    char*       name;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(iommu_ranges,
    AGGREGATE_FLATTEN_TYPE_ARRAY(uint32_t, ranges, ATTR(num_ranges));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(iommu_result,
    AGGREGATE_FLATTEN_TYPE(uint32_t, result);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(iommu_data,
    AGGREGATE_FLATTEN_STRING(name);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(iommu_base, OFFATTR(uint32_t, 0),
    switch(OFFATTR(uint32_t, 0)) {
        case sizeof(struct iommu_ranges):
            AGGREGATE_FLATTEN_STRUCT_STORAGE_SELF_CONTAINED(iommu_ranges, OFFATTR(uint32_t, 0), self, 0);
            break;
        case sizeof(struct iommu_result):
            AGGREGATE_FLATTEN_STRUCT_STORAGE_SELF_CONTAINED(iommu_result, OFFATTR(uint32_t, 0), self, 0);
            break;
        case sizeof(struct iommu_data):
            AGGREGATE_FLATTEN_STRUCT_STORAGE_SELF_CONTAINED(iommu_data, OFFATTR(uint32_t, 0), self, 0);
            break;
        default:
            break;
    }
);

static int kflat_variable_struct_example(struct flat *flat) {
    uint32_t local_int = 666;
    uint32_t array[5] = {1, 2, 3, 4, 5};
    struct iommu_ranges ranges = {
        .size = sizeof(struct iommu_ranges),
        .fd = 2,
        .num_ranges = 5,
        .ranges = array,
        .padding = 3
    };
    struct iommu_result result = {
        .size = sizeof(struct iommu_result),
        .fd = 5,
        .result = &local_int
    };
    struct iommu_data data = {
        .size = sizeof(struct iommu_data),
        .fd = 22,
        .name = "test string",
    };

    FLATTEN_SETUP_TEST(flat);

    for(int i = 0; i < sizeof(data.data); i++)
        data.data[i] = i * 17;

    FOR_ROOT_POINTER(&ranges,
        FLATTEN_STRUCT_SELF_CONTAINED(iommu_base, sizeof(uint32_t), &ranges);
    );
    FOR_ROOT_POINTER(&result,
        FLATTEN_STRUCT_SELF_CONTAINED(iommu_base, sizeof(uint32_t), &result);
    );
    FOR_ROOT_POINTER(&data,
        FLATTEN_STRUCT_SELF_CONTAINED(iommu_base, sizeof(uint32_t), &data);
    );

    return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_variable_struct_validate(void *memory, size_t size, CUnflatten flatten) {
    struct iommu_ranges* ranges = (struct iommu_ranges*)unflatten_root_pointer_seq(flatten, 0);
    struct iommu_result* result = (struct iommu_result*)unflatten_root_pointer_seq(flatten, 1);
    struct iommu_data* data = (struct iommu_data*)unflatten_root_pointer_seq(flatten, 2);

    ASSERT_EQ(ranges->size, sizeof(struct iommu_ranges));
    ASSERT_EQ(ranges->fd, 2);
    ASSERT_EQ(ranges->num_ranges, 5);
    ASSERT_EQ(ranges->padding, 3);
    for(int i = 0; i < ranges->num_ranges; i++)
        ASSERT_EQ(ranges->ranges[i], i + 1);
    
    ASSERT_EQ(result->size, sizeof(struct iommu_result));
    ASSERT_EQ(result->fd, 5);
    ASSERT_EQ(*result->result, 666);

    ASSERT_EQ(data->size, sizeof(struct iommu_data));
    ASSERT_EQ(data->fd, 22);
    ASSERT(!strcmp(data->name, "test string"));
    for(int i = 0; i < sizeof(data->data); i++)
        ASSERT_EQ(data->data[i], (uint8_t)(i * 17));

    return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("VARIABLE_STRUCT", kflat_variable_struct_example, kflat_variable_struct_validate, KFLAT_TEST_ATOMIC);
