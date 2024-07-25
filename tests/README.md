# KFLAT tests framework

This directory contains a set of KFLAT example programs and unit tests. Our aim is to test all flattening macros defined in kflat.h and verify that dumped memory is correct after restoring it in userspace.

## Building

Simply run `make` command as described in root README.md. Make command will automatically build test files for both userspace and kernelspace code.

Due to the limitation of our Makefile, after adding new test remember to run target `clean`, otherwise they won't be visible in kernel module and userspace test app.

## Test format

Test files looks as below. Code in `__TESTER__` macro block will be compiled for kernelspace module and the second block (`__USER__`) will be build for userspace test app. First one is allocating structure, defining recipe and performing flattening, while userspace loads dump into memory and validates it contents with custom `ASSERT` macros.

```c
// Generic include for both kernel and user targets
#include "common.h"

// Common data types
struct B {
	int x;
};

/**************************/
#ifdef __TESTER__
/**************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(B);

static int kflat_test(struct flat *flat) {
	int rv;
	struct B b = { 0x123 };

	FLATTEN_SETUP_TEST(flat);
	FOR_ROOT_POINTER(&b,
		FLATTEN_STRUCT(B, &b);
	);
	rv = FLATTEN_FINISH_TEST(flat);
	
	// Release any allocated memory here:
	// ...

	return rv;
}

/**************************/
#else /* __USER__ */
/**************************/

static int kflat_validate(void* memory, size_t size, CUnflatten flatten) {
	struct B* pB = (struct B*) memory;
	ASSERT(pB->x == 0x123);
	return 0;
}

/**************************/
#endif
/**************************/

KFLAT_REGISTER_TEST("TEST_NAME", kflat_test, kflat_validate);
```

Macro `KFLAT_REGISTER_TEST` apart from test name, defines entry points for both userspace and kernelspace code.
