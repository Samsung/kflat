/**
 * @file example_fragment.c
 * @author Samsung R&D Poland - Mobile Security Group
 *
 */

#include "common.h"

struct X {
	char name[20];
};

struct Q {
	long l;
	char carr[4];
};

struct P {
	long l;
	const char* tp;
	int iarr[10];
	float f;
	struct X* pX;
	struct Q q;
	unsigned long a;
	unsigned long b;
	unsigned long c;
};

struct S {
	char padding0[10];
	struct P obP;
	char padding1[10];
};

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT(X);

FUNCTION_DEFINE_FLATTEN_STRUCT(Q);

FUNCTION_DEFINE_FLATTEN_STRUCT(P,
	AGGREGATE_FLATTEN_STRING(tp);
	AGGREGATE_FLATTEN_STRUCT(X,pX);
);

static int kflat_fragment_test(struct kflat *kflat) {
	struct X xarr[10];
	struct S stack = {"ABCDEFGHIJ",{1000,"Pobject",{-3,-2,-1,0,1,2,3,4,5,6},1.0,0,{1000000,"ABCD"},0,50,100},"KLMNOPQRST"};

	for (int i=0; i<10; ++i) {
		struct X* pX = &xarr[i];
		for (int j=i; j<i+10; ++j) {
			pX->name[j] = (j%10)+(int)'0';
		}
	}

	stack.obP.pX = &xarr[5];

	FOR_ROOT_POINTER(&stack,
		FLATTEN_TYPE_ARRAY(char, &stack,20);
	);

	FOR_ROOT_POINTER(&stack.obP.q,
		FLATTEN_STRUCT(Q,&stack.obP.q);
	);

	FOR_ROOT_POINTER(&stack.obP.c,
		FLATTEN_TYPE_ARRAY(unsigned long,&stack.obP.c,2);
	);

	FOR_ROOT_POINTER(&stack.obP,
		FLATTEN_STRUCT(P,&stack.obP);
	);

	return 0;
}

#else /* __USER__ */

static int kflat_fragment_validate(void* memory, size_t size, CFlatten flatten) {
	struct P* pP = (struct P*)flatten_root_pointer_seq(flatten,3);

	CFlattenHeader hdr = flatten_get_image_header(flatten);
	ASSERT(flatten_header_memory_size(hdr) == sizeof(struct P)+offsetof(struct S,obP)+sizeof(unsigned long)+8+sizeof(struct X));

	ASSERT(pP->l == 1000);
	ASSERT(!strcmp(pP->tp, "Pobject"));
	for (int i=0; i<10; ++i) {
		ASSERT(pP->iarr[i] == -3+i);
	}
	ASSERT(pP->f == 1.0);

	for (int i=0; i<10; ++i) {
		ASSERT(pP->pX->name[5+i] == ((5+i)%10)+'0');
	}

	ASSERT(pP->q.l == 1000000);
	ASSERT(pP->q.carr[0] == 'A');
	ASSERT(pP->q.carr[1] == 'B');
	ASSERT(pP->q.carr[2] == 'C');
	ASSERT(pP->q.carr[3] == 'D');

	ASSERT(pP->a == 0);
	ASSERT(pP->b == 50);
	ASSERT(pP->c == 100);

	ASSERT(flatten_header_fragment_count(hdr) == 3);

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("FRAGMENT", kflat_fragment_test, kflat_fragment_validate);
