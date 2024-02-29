	/**
 * @file example_pointer_array.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct my_data {
	unsigned long ul;
};

struct large_data {
	char hash[20];
	struct my_data* batch[40][5];
};

struct larger_data {
	char hash[20];
	struct my_data* batch[][40][5];
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(my_data,sizeof(struct my_data));

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(large_data,sizeof(struct large_data),
	FOREACH_POINTER(struct my_data*,my_data_ptr,OFFADDR(void**,offsetof(struct large_data,batch)),40*5,
		FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(my_data,sizeof(struct my_data),my_data_ptr,1);
	);
);

typedef struct my_data* my_data_ptrs_t[40][5];

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(larger_data,sizeof(struct larger_data),
	{
	AGGREGATE_FLATTEN_TYPE_ARRAY_FLEXIBLE_SELF_CONTAINED(my_data_ptrs_t,sizeof(my_data_ptrs_t),batch,offsetof(struct larger_data,batch));
	FOREACH_POINTER(
			struct my_data*,
			my_data_ptr,
			OFFADDR(void**,offsetof(struct larger_data,batch)),
			FLATTEN_DETECT_OBJECT_SIZE(OFFADDR(void**,offsetof(struct larger_data,batch)),sizeof(struct my_data*))/sizeof(struct my_data*),
		FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(my_data,sizeof(struct my_data),my_data_ptr,1);
	);
	}
);

static int kflat_pointer_array_test(struct flat *flat) {

	int get_obj_supported;
	struct large_data large_data = {"ABCDEFGHIJKLMNOPRSTV"};
	struct larger_data* larger_data;

	FLATTEN_SETUP_TEST(flat);
	get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);

	for (int i=0; i<40; ++i) {
		for (int j=0; j<5; ++j) {
			struct my_data* subdata = kmalloc(sizeof(struct my_data), GFP_KERNEL);
			subdata->ul = i*10+j*16;
			large_data.batch[i][j] = subdata;
		}
	}

	larger_data = kmalloc(sizeof(struct larger_data) + 8*40*5*sizeof(struct my_data*), GFP_KERNEL);
	memcpy(larger_data->hash,"0123456789xyzabchwiq",20);
	for (int k=0; k<8; ++k) {
		for (int i=0; i<40; ++i) {
			for (int j=0; j<5; ++j) {
				struct my_data* subdata = kmalloc(sizeof(struct my_data), GFP_KERNEL);
				subdata->ul = 1000000-k*50000-i*10-j*16;
				larger_data->batch[k][i][j] = subdata;
			}
		}
	}

	FOR_ROOT_POINTER(&get_obj_supported,
		FLATTEN_TYPE(int, &get_obj_supported);
	);

	#ifdef KFLAT_GET_OBJ_SUPPORT

	FOR_ROOT_POINTER(&large_data,
		FLATTEN_STRUCT_SELF_CONTAINED(large_data, sizeof(struct large_data), &large_data);
    );

	FOR_ROOT_POINTER(larger_data,
		FLATTEN_STRUCT(larger_data, larger_data);
    );
	
	#endif

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_pointer_array_validate(void *memory, size_t size, CUnflatten flatten) {

	int* get_obj_supported = (int*)unflatten_root_pointer_seq(flatten, 0);
	struct large_data* large_data;
	struct larger_data* larger_data;

	if(get_obj_supported == NULL || *get_obj_supported == false)
		return KFLAT_TEST_UNSUPPORTED;
	
	large_data = (struct large_data*)unflatten_root_pointer_seq(flatten, 1);
	larger_data = (struct larger_data*)unflatten_root_pointer_seq(flatten, 2);

	ASSERT(memcmp(large_data->hash,"ABCDEFGHIJKLMNOPRSTV",20) == 0);
	for (int i=0; i<40; ++i) {
		for (int j=0; j<5; ++j) {
			ASSERT(large_data->batch[i][j]->ul == i*10+j*16);
		}
	}

	ASSERT(memcmp(larger_data->hash,"0123456789xyzabchwiq",20) == 0);
	for (int k=0; k<8; ++k) {
		for (int i=0; i<40; ++i) {
			for (int j=0; j<5; ++j) {
				ASSERT(larger_data->batch[k][i][j]->ul == 1000000-k*50000-i*10-j*16);
			}
		}
	}

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("POINTER_ARRAY", kflat_pointer_array_test, kflat_pointer_array_validate);
