/**
 * @file unit_flatten_embedded_pointer.c
 * @author Samsung R&D Poland - Mobile Security Group
 *
 */

#include "common.h"

struct EA {
	long l;
	char ptr[8];		// --> B_t*
	char ptr1[8];		// --> B_t*
	char ptr2[8];		// --> EC*
	uintptr_t ptr3;		// --> FC*
	uintptr_t ptr4;		// --> FC*
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
	return (void*)ptr;
}

static inline struct flatten_pointer *ptr_to_char_array(struct flatten_pointer *fptr, const struct flatten_base *ptr) {
	return fptr;
}

static inline void *long_to_ptr(const void *ptr) {
	return (void*)ptr;
}

static inline struct flatten_pointer *ptr_to_long(struct flatten_pointer *fptr, const struct flatten_base *ptr) {
	return fptr;
}

FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(B_t);
FUNCTION_DECLARE_FLATTEN_STRUCT(EC);
FUNCTION_DECLARE_FLATTEN_STRUCT(FC);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(EA,sizeof(struct EA),
	AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED(B_t,sizeof(B_t),ptr,offsetof(struct EA,ptr),char_array_to_ptr,ptr_to_char_array,1);
	AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_SELF_CONTAINED(B_t,sizeof(B_t),ptr1,offsetof(struct EA,ptr1),char_array_to_ptr,ptr_to_char_array);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_SELF_CONTAINED(EC,sizeof(struct EC),ptr2,offsetof(struct EA,ptr2),char_array_to_ptr,ptr_to_char_array);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED(FC,sizeof(struct FC),ptr3,offsetof(struct EA,ptr3),long_to_ptr,ptr_to_long,5);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED(FC,sizeof(struct FC),ptr4,offsetof(struct EA,ptr4),long_to_ptr,ptr_to_long,5,-offsetof(struct FC,q));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SPECIALIZE(no_self_contained,EA,
	AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_ARRAY(B_t,ptr,char_array_to_ptr,ptr_to_char_array,1);
	AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER(B_t,ptr1,char_array_to_ptr,ptr_to_char_array);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER(EC,ptr2,char_array_to_ptr,ptr_to_char_array);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY(FC,ptr3,long_to_ptr,ptr_to_long,5);
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SHIFTED(FC,ptr4,long_to_ptr,ptr_to_long,5,-offsetof(struct FC,q));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SPECIALIZE(no_embedded,EA,
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(B_t,ptr,1);
	AGGREGATE_FLATTEN_STRUCT_TYPE(B_t,ptr1);
	AGGREGATE_FLATTEN_STRUCT(EC,ptr2);
	AGGREGATE_FLATTEN_STRUCT_ARRAY(FC,ptr3,5);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SHIFTED(FC,ptr4,5,-offsetof(struct FC,q));
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
struct EA g_EA;
struct EA g_EA2;
B_t g_B[4] = { {"ABC"},{"DEF"},{"GHI"},{"JKL"} };

static int kflat_flatten_embedded_pointer_unit_test(struct kflat *kflat) {

	B_t Bnfo[5] = { {info[0]},{info[1]},{info[2]},{info[3]},{info[4]}, };
	struct EC Cnfo[5] = { {info[0]},{info[1]},{info[2]},{info[3]},{info[4]}, };
	struct FC crr[40] = {};

	for (int i=0; i<40; ++i) {
		crr[i].s = kvzalloc(4, GFP_KERNEL);
		snprintf(crr[i].s,4,"%d",25*i+5);
	}

	for (int i=0; i<5; ++i) {
		EAarr[i].l = 1000*i;
		*( (const B_t**)EAarr[i].ptr ) = &Bnfo[i];
		*( (const B_t**)EAarr[i].ptr1 ) = &Bnfo[4-i];
		*( (const struct EC**)EAarr[i].ptr2 ) = &Cnfo[i];
		EAarr[i].ptr3 = ((uintptr_t)(&crr[2*i]));
		EAarr[i].ptr4 = ((uintptr_t)(&crr[7*i].q));
	}

	g_EA.l = 8888;
	*( (const B_t**)g_EA.ptr ) = &Bnfo[0];
	*( (const B_t**)g_EA.ptr1 ) = &Bnfo[4];
	*( (const struct EC**)g_EA.ptr2 ) = &Cnfo[0];
	g_EA.ptr3 = ((uintptr_t)(&crr[0]));
	g_EA.ptr4 = ((uintptr_t)(&crr[30].q));

	g_EA2.l = 6666;
	*( (const B_t**)g_EA2.ptr ) = &Bnfo[1];
	*( (const B_t**)g_EA2.ptr1 ) = &Bnfo[3];
	*( (const struct EC**)g_EA2.ptr2 ) = &Cnfo[4];
	g_EA2.ptr3 = ((uintptr_t)(&crr[10]));
	g_EA2.ptr4 = ((uintptr_t)(&crr[20].q));


	FOR_ROOT_POINTER(EAarr,
		FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(EA,sizeof(struct EA),EAarr,5);
	);

	FOR_ROOT_POINTER(&g_EA,
		FLATTEN_STRUCT_ARRAY_SPECIALIZE(no_self_contained,EA,&g_EA,1);
	);

	FOR_ROOT_POINTER(&g_EA2,
		FLATTEN_STRUCT_SPECIALIZE(no_embedded,EA,&g_EA2);
	);

	FOR_ROOT_POINTER(&g_B,
		FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(B_t,sizeof(B_t),&g_B,4);
	);

	for (int i=0; i<40; ++i) {
		kvfree(crr[i].s);
	}

	return 0;
}

#else

static int kflat_flatten_embedded_pointer_unit_validate(void *memory, size_t size, CUnflatten flatten) {

	struct EA* pEA = (struct EA*)unflatten_root_pointer_seq(flatten, 0);
	struct EA* gEA = (struct EA*)unflatten_root_pointer_seq(flatten, 1);
	struct EA* gEA2 = (struct EA*)unflatten_root_pointer_seq(flatten, 2);
	B_t* g_B = (B_t*)unflatten_root_pointer_seq(flatten, 3);

	for (int i=0; i<5; ++i) {
		char n[4];
		ASSERT((pEA+i)->l==1000*i);
		ASSERT( !strcmp((*((const B_t**)(pEA+i)->ptr))->s,info[i]) );
		ASSERT( !strcmp((*((const B_t**)(pEA+i)->ptr1))->s,info[4-i]) );
		ASSERT( !strcmp((*((const struct EC**)(pEA+i)->ptr2))->s,info[i]) );
		memset(n,0,4);
		snprintf(n,4,"%d",25*2*i+5);
		ASSERT( !strcmp(((struct FC*)((pEA+i)->ptr3))->s,n) );
		memset(n,0,4);
		snprintf(n,4,"%d",25*7*i+5);
		ASSERT( !strcmp(((struct FC*)((pEA+i)->ptr4-offsetof(struct FC,q)))->s,n) );
	}

	ASSERT(gEA->l==8888);
	ASSERT( !strcmp((*((const B_t**)gEA->ptr))->s,info[0]) );
	ASSERT( !strcmp((*((const B_t**)gEA->ptr1))->s,info[4]) );
	ASSERT( !strcmp((*((const struct EC**)gEA->ptr2))->s,info[0]) );
	ASSERT( !strcmp(((struct FC*)(gEA->ptr3))->s,"5") );
	ASSERT( !strcmp(((struct FC*)(gEA->ptr4-offsetof(struct FC,q)))->s,"755") );

	ASSERT(gEA2->l==6666);
	ASSERT( !strcmp((*((const B_t**)gEA2->ptr))->s,info[1]) );
	ASSERT( !strcmp((*((const B_t**)gEA2->ptr1))->s,info[3]) );
	ASSERT( !strcmp((*((const struct EC**)gEA2->ptr2))->s,info[4]) );
	ASSERT( !strcmp(((struct FC*)(gEA2->ptr3))->s,"255") );
	ASSERT( !strcmp(((struct FC*)(gEA2->ptr4-offsetof(struct FC,q)))->s,"505") );

	ASSERT( !strcmp(g_B[0].s,"ABC") );
	ASSERT( !strcmp(g_B[1].s,"DEF") );
	ASSERT( !strcmp(g_B[2].s,"GHI") );
	ASSERT( !strcmp(g_B[3].s,"JKL") );

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] flatten_embedded_pointer", kflat_flatten_embedded_pointer_unit_test, kflat_flatten_embedded_pointer_unit_validate);
