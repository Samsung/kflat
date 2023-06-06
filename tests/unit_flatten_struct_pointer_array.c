/**
 * @file unit_flatten_struct_pointer_array.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

#define FB_MAX 4

struct fb_info {
	const char* fb_name;
	unsigned long fb_id;
};

static struct fb_info fb0 = { "fb0",0};
static struct fb_info fb1 = { "fb1",1};
static struct fb_info fb2 = { "fb2",2};
static struct fb_info fb3 = { "fb3",3};

static struct fb_info *registered_fb[FB_MAX] = {&fb0,&fb1,&fb2,&fb3};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(fb_info,
	AGGREGATE_FLATTEN_STRING(fb_name);
);

static int kflat_flatten_struct_pointer_array_unit_test(struct flat *flat) {

	void* addr = &registered_fb;

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(addr,
		FLATTEN_TYPE_ARRAY(struct fb_info*, addr, FB_MAX);
	    FOREACH_POINTER(struct fb_info*, p, addr, FB_MAX,
	        FLATTEN_STRUCT(fb_info, p);
    	)
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_struct_pointer_array_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct fb_info** registered_fb = (struct fb_info**)memory;

	for (int i=0; i<FB_MAX; ++i) {
		char fbname[4];
		struct fb_info* fb_info = registered_fb[i];
		snprintf(fbname,4,"fb%d",i);
		ASSERT(!strcmp(fb_info->fb_name, fbname));
		ASSERT_EQ(fb_info->fb_id,i);
	}

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_struct_pointer_array", kflat_flatten_struct_pointer_array_unit_test, kflat_flatten_struct_pointer_array_unit_validate, KFLAT_TEST_ATOMIC);
