/**
 * @file unit_flatten_embedded_pointer.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

//--AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER
// #define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,pre_f,post_f,n,_shift)	\

#include "common.h"

struct EA {
	long l;
	char ptr[8];
	char ptr2[8];
	uintptr_t ptr3;
};

typedef struct {
	const char* s;
} B_t;

struct EC {
	const char* s;
};

struct FC {
	char* s;
	void* q;
};

const char* info[5] = {
	"Everything",
	"worked",
	"as",
	"expected",
	"!",
};

#ifdef __KERNEL__

static inline void *char_array_to_ptr(const void *ptr) {
	return *((void**)ptr);
}

static inline struct flatten_pointer *ptr_to_char_array(struct flatten_pointer *fptr, const void *ptr) {
	return fptr;
}

static inline void *long_to_ptr(const void *ptr) {
	return (void*)ptr;
}

static inline struct flatten_pointer *ptr_to_long(struct flatten_pointer *fptr, const void *ptr) {
	return fptr;
}

FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(B_t);
FUNCTION_DECLARE_FLATTEN_STRUCT(EC);
FUNCTION_DECLARE_FLATTEN_STRUCT(FC);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(EA,sizeof(struct EA),
	AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED(B_t,sizeof(B_t),ptr,offsetof(struct EA,ptr),char_array_to_ptr,ptr_to_char_array);
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED(EC,sizeof(struct EC),ptr2,offsetof(struct EA,ptr2),char_array_to_ptr,ptr_to_char_array);
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED(FC,sizeof(struct FC),ptr3,offsetof(struct EA,ptr3),long_to_ptr,ptr_to_long,5);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(B_t,
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(EC,
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(FC,
	AGGREGATE_FLATTEN_STRING(s);
);

struct EA EAarr[5];

static int kflat_flatten_embedded_pointer_unit_test(struct kflat *kflat) {
	
	B_t Bnfo[5] = { {info[0]},{info[1]},{info[2]},{info[3]},{info[4]}, };
	struct EC Cnfo[5] = { {info[0]},{info[1]},{info[2]},{info[3]},{info[4]}, };
	struct FC crr[20] = {};

	for (int i=0; i<20; ++i) {
		crr[i].s = kvzalloc(4, GFP_KERNEL);
		snprintf(crr[i].s,4,"%d",40*i+5);
	}

	for (int i=0; i<5; ++i) {
		EAarr[i].l = 1000*i;
		*( (const B_t**)EAarr[i].ptr ) = &Bnfo[i];
		*( (const struct EC**)EAarr[i].ptr2 ) = &Cnfo[i];
		EAarr[i].ptr3 = ((uintptr_t)(&crr[2*i]));
	}

	FOR_ROOT_POINTER(EAarr,
		FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(EA,sizeof(struct EA),EAarr,5);
	);

	for (int i=0; i<20; ++i) {
		kvfree(crr[i].s);
	}

	return 0;
}

#else

static int kflat_flatten_embedded_pointer_unit_validate(void *memory, size_t size, CFlatten flatten) {

	struct EA* pEA = (struct EA*)flatten_root_pointer_seq(flatten, 0);

	for (int i=0; i<5; ++i) {
		char n[4];
		ASSERT((pEA+i)->l==1000*i);
		ASSERT( !strcmp((*((const B_t**)(pEA+i)->ptr))->s,info[i]) );
		ASSERT( !strcmp((*((const struct EC**)(pEA+i)->ptr2))->s,info[i]) );
		memset(n,0,4);
		snprintf(n,4,"%d",40*2*i+5);
		ASSERT( !strcmp(((struct FC*)((pEA+i)->ptr3))->s,n) );
	}

	return 0;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] flatten_embedded_pointer", kflat_flatten_embedded_pointer_unit_test, kflat_flatten_embedded_pointer_unit_validate);
