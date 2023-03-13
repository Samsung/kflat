/**
 * @file unit_flatten_struct_shifted.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct my_device {
	const char* dev_name;
	unsigned long* code;
	unsigned long code_size;
};

struct my_product {
	const char* name;
	struct my_device dev;
	unsigned long SN;
};

typedef struct my_product product_t;

static unsigned long dev_code[] = {3,3,7,2,4,1,8,5};

#ifdef __KERNEL__

#include <linux/vmalloc.h>

FUNCTION_DEFINE_FLATTEN_STRUCT(my_product,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRING(dev.dev_name);
	AGGREGATE_FLATTEN_TYPE_ARRAY(unsigned long,dev.code,ATTR(dev.code_size));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(product_t,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRING(dev.dev_name);
	AGGREGATE_FLATTEN_TYPE_ARRAY(unsigned long,dev.code,ATTR(dev.code_size));
);

static int kflat_flatten_struct_shifted_unit_test(struct kflat *kflat) {

	struct my_product prod = {"productX",{"dev0",dev_code,sizeof(dev_code)/sizeof(unsigned long)},0x33449182};
	product_t prod2 = {"productY",{"dev1",dev_code,sizeof(dev_code)/sizeof(unsigned long)},0x55664356};
	struct my_device* dev = &prod.dev;
	struct my_device* dev2 = &prod2.dev;

	FOR_ROOT_POINTER(dev,
		FLATTEN_STRUCT_SHIFTED(my_product, dev, -offsetof(struct my_product,dev));
	);

	FOR_ROOT_POINTER(dev2,
		FLATTEN_STRUCT_TYPE_SHIFTED(product_t, dev2, -offsetof(product_t,dev));
	);

	return 0;
}

#else

static int kflat_flatten_struct_shifted_unit_validate(void *memory, size_t size, CFlatten flatten) {

	struct my_device *dev = (struct my_device *)flatten_root_pointer_seq(flatten, 0);
	struct my_device *dev2 = (struct my_device *)flatten_root_pointer_seq(flatten, 1);
	struct my_product* prod = container_of(dev,struct my_product,dev);
	product_t* prod2 = container_of(dev2,product_t,dev);

	ASSERT(!strcmp(prod->name, "productX"));
	ASSERT(!strcmp(prod->dev.dev_name, "dev0"));
	for (unsigned long i=0; i<prod->dev.code_size; ++i) {
		ASSERT_EQ(prod->dev.code[i],dev_code[i]);
	}
	ASSERT_EQ(prod->SN,0x33449182);

	ASSERT(!strcmp(prod2->name, "productY"));
	ASSERT(!strcmp(prod2->dev.dev_name, "dev1"));
	for (unsigned long i=0; i<prod2->dev.code_size; ++i) {
		ASSERT_EQ(prod2->dev.code[i],dev_code[i]);
	}
	ASSERT_EQ(prod2->SN,0x55664356);

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] flatten_struct_shifted", kflat_flatten_struct_shifted_unit_test, kflat_flatten_struct_shifted_unit_validate);
