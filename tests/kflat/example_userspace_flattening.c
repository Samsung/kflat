/**
 * @file example_userspace_flattening.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */
#include "common.h"
#ifdef __TESTER__
#include <linux/mman.h>
#include "kflat_uaccess.h"
#endif

struct array_element {
    int l;
};

struct inner_struct {
    int k;
    char str[64];
    struct array_element *tab;
    int array_size;
};

struct outer_struct {
    int a;
    int b;
    struct inner_struct *inner;
};

struct support_check {
    bool smap_enabled;
};

#define TEST_ARRAY_SIZE 10
#define TEST_STRING "Userspace test string."


/********************************/
#ifdef __TESTER__
/********************************/

#ifndef __nocfi
#define __nocfi
#endif

FUNCTION_DEFINE_FLATTEN_STRUCT(support_check);

FUNCTION_DECLARE_FLATTEN_STRUCT(array_element);

FUNCTION_DEFINE_FLATTEN_STRUCT(inner_struct, 
    AGGREGATE_FLATTEN_TYPE_ARRAY(struct array_element, tab, ATTR(array_size));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(outer_struct,
	AGGREGATE_FLATTEN_STRUCT(inner_struct, inner);
);

typedef unsigned long (*ksys_mmap_pgoff_t)(unsigned long addr, unsigned long len,
			      unsigned long prot, unsigned long flags,
			      unsigned long fd, unsigned long pgoff);

ksys_mmap_pgoff_t my_ksys_mmap_pgoff;


__nocfi static int userspace_flattening_test(struct flat *flat) {
    struct array_element *uarray[2], *karray[2];
    struct inner_struct *uinner[2], *kinner[2];
    struct outer_struct *uouter[2], *kouter[2];
    struct support_check support;
    int err;

    FLATTEN_SETUP_TEST(flat);

    /* ========= ALLOCATE USERSPACE MEMORY ============== */

    my_ksys_mmap_pgoff = flatten_global_address_by_name("ksys_mmap_pgoff");
    if (my_ksys_mmap_pgoff == 0)
        return -EFAULT;

    for (int i = 0; i < 2; i++) {
        uarray[i] = (struct array_element *) my_ksys_mmap_pgoff(0, sizeof(struct array_element) * TEST_ARRAY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        uinner[i] = (struct inner_struct *) my_ksys_mmap_pgoff(0, sizeof(struct inner_struct), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        uouter[i] = (struct outer_struct *) my_ksys_mmap_pgoff(0, sizeof(struct outer_struct), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    arch_enable_ua();

    for (int j = 0; j < 2; j++) {
        for (int i = 0; i < 10; i++) {
            uarray[j][i].l = i;
        }

        uinner[j]->k = 42;

        uinner[j]->tab = uarray[j];
        uinner[j]->array_size = TEST_ARRAY_SIZE;

        uouter[j]->inner = uinner[j];
        uouter[j]->a = 12;
        uouter[j]->b = 24;

    }
    arch_disable_ua();

    // Do it seperately because copy_to_user may disable UA depending on arch
    for (int j = 0; j < 2; j++) {
        if(copy_to_user(uinner[j]->str, TEST_STRING, strlen(TEST_STRING))) {}
    }

    /* ========= ALLOCATE KERNEL MEMORY ============== */

    for (int i = 0; i < 2; i++) {
        karray[i] = kmalloc(sizeof(struct array_element) * TEST_ARRAY_SIZE, GFP_KERNEL);
        kinner[i] = kmalloc(sizeof(struct inner_struct), GFP_KERNEL);
        kouter[i] = kmalloc(sizeof(struct outer_struct), GFP_KERNEL);
    }

    for (int j = 0; j < 2; j++) {
        for (int i = 0; i < 10; i++) {
            karray[j][i].l = i;
        }

        kinner[j]->k = 42;
        strcpy(kinner[j]->str, TEST_STRING);
        kinner[j]->tab = karray[j];
        kinner[j]->array_size = TEST_ARRAY_SIZE;

        kouter[j]->inner = kinner[j];
        kouter[j]->a = 12;
        kouter[j]->b = 24;
    }

    /* SUPPORT CHECK */
#ifdef CONFIG_X86_64
    support.smap_enabled = cpu_feature_enabled(X86_FEATURE_SMAP);
#elif CONFIG_ARM64
    support.smap_enabled = true;
#endif

    FOR_ROOT_POINTER(&support,
        FLATTEN_STRUCT(support_check, &support);
    );
    
    // User memory with UA == true
    FOR_USER_ROOT_POINTER(uouter[0],
        FLATTEN_STRUCT(outer_struct, uouter[0]);
    );

    // User memory with UA == false
    FOR_ROOT_POINTER(uouter[1],
        FLATTEN_STRUCT(outer_struct, uouter[1]);
    );

    // Kernel memory with UA == true
    FOR_USER_ROOT_POINTER(kouter[0],
        FLATTEN_STRUCT(outer_struct, kouter[0]);
    );

    // Kernel memory with UA == false
    FOR_ROOT_POINTER(kouter[1],
        FLATTEN_STRUCT(outer_struct, kouter[1]);
    );


    for (int i = 0; i < 2; i++) {
        err = vm_munmap((unsigned long) uouter[i], sizeof(struct outer_struct));
        err = vm_munmap((unsigned long) uinner[i], sizeof(struct inner_struct));
        err = vm_munmap((unsigned long) uarray[i], sizeof(struct array_element) * TEST_ARRAY_SIZE);

        kfree(kouter[i]);
        kfree(kinner[i]);
        kfree(karray[i]);
    }

    return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/
static int userspace_flattening_test_validate(void *memory, size_t size, CUnflatten flatten) {
    struct support_check *support = (struct support_check *) unflatten_root_pointer_seq(flatten, 0);
    struct outer_struct *u_valid = (struct outer_struct *) unflatten_root_pointer_seq(flatten, 1);
    struct outer_struct *u_invalid = (struct outer_struct *) unflatten_root_pointer_seq(flatten, 2);
    struct outer_struct *k_invalid = (struct outer_struct *) unflatten_root_pointer_seq(flatten, 3);
    struct outer_struct *k_valid = (struct outer_struct *) unflatten_root_pointer_seq(flatten, 4);

    if (!support->smap_enabled)
        return KFLAT_TEST_UNSUPPORTED;

    ASSERT(u_valid != NULL);
    ASSERT(k_valid != NULL);
    ASSERT(u_invalid == NULL);
    ASSERT(k_invalid == NULL);

    ASSERT(u_valid->inner != NULL);
    ASSERT(k_valid->inner != NULL);

    ASSERT(u_valid->inner->tab != NULL);
    ASSERT(k_valid->inner->tab != NULL);

    for (int i = 0; i < 10; i++) {
        ASSERT(u_valid->inner->tab[i].l == i);
        ASSERT(k_valid->inner->tab[i].l == i);
    }

    ASSERT(u_valid->inner->str != NULL);
    ASSERT(k_valid->inner->str != NULL);

    ASSERT(strncmp(u_valid->inner->str, TEST_STRING, strlen(TEST_STRING)) == 0);
    ASSERT(strncmp(k_valid->inner->str, TEST_STRING, strlen(TEST_STRING)) == 0);

    return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("USERSPACE_FLATTENING", userspace_flattening_test, userspace_flattening_test_validate);

