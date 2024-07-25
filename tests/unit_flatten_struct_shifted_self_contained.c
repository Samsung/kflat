/**
 * @file unit_flatten_struct_shifted_self_contained.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct my_device_sc {
	const char* dev_name;
	unsigned long* code;
	unsigned long code_size;
};

struct my_product_sc {
	const char* name;
	struct my_device_sc dev;
	unsigned long SN;
};

typedef struct my_product_sc product_sc_t;

static unsigned long dev_code[] = {3,3,7,2,4,1,8,5};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(my_product_sc,sizeof(struct my_product_sc),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(name,offsetof(struct my_product_sc,name));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(dev.dev_name,offsetof(struct my_product_sc,dev.dev_name));
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(unsigned long,dev.code,offsetof(struct my_product_sc,dev.code),OFFATTR(unsigned long,offsetof(struct my_product_sc,dev.code_size)));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(product_sc_t,sizeof(product_sc_t),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(name,offsetof(product_sc_t,name));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(dev.dev_name,offsetof(product_sc_t,dev.dev_name));
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(unsigned long,dev.code,offsetof(product_sc_t,dev.code),OFFATTR(unsigned long,offsetof(product_sc_t,dev.code_size)));
);

static int kflat_flatten_struct_shifted_self_contained_unit_test(struct flat *flat) {

	struct my_product_sc prod = {"productX",{"dev0",dev_code,sizeof(dev_code)/sizeof(unsigned long)},0x33449182};
	product_sc_t prod2 = {"productY",{"dev1",dev_code,sizeof(dev_code)/sizeof(unsigned long)},0x55664356};
	struct my_device_sc* dev = &prod.dev;
	struct my_device_sc* dev2 = &prod2.dev;

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(dev,
		FLATTEN_STRUCT_SHIFTED_SELF_CONTAINED(my_product_sc, sizeof(struct my_product_sc), dev, -offsetof(struct my_product_sc,dev));
	);

	FOR_ROOT_POINTER(dev2,
		FLATTEN_STRUCT_TYPE_SHIFTED_SELF_CONTAINED(product_sc_t, sizeof(product_sc_t), dev2, -offsetof(product_sc_t,dev));
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_struct_shifted_self_contained_unit_validate(void *memory, size_t size, CUnflatten flatten) {

	struct my_device_sc *dev = (struct my_device_sc *)unflatten_root_pointer_seq(flatten, 0);
	struct my_device_sc *dev2 = (struct my_device_sc *)unflatten_root_pointer_seq(flatten, 1);
	struct my_product_sc* prod = container_of(dev,struct my_product_sc,dev);
	product_sc_t* prod2 = container_of(dev2,product_sc_t,dev);

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

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_struct_shifted_self_contained", kflat_flatten_struct_shifted_self_contained_unit_test, kflat_flatten_struct_shifted_self_contained_unit_validate);
