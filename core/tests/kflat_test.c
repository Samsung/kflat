/**
 * @file kflat_test.c
 * @author Samsung R&D Poland - Mobile Security Group
 * @brief Collection of basic functions and recipes used for testing kflat
 * 
 */

#include "kflat.h"

#include <linux/init.h>
#include <linux/interval_tree_generic.h>
#include <linux/list_nulls.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>


#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

INTERVAL_TREE_DEFINE(struct flat_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST,static __used,interval_tree)

/*******************************************************
 * TEST CASE #1
 *******************************************************/
struct B {
	unsigned char T[4];
};
struct A {
	unsigned long X;
	struct B* pB;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(B);

FUNCTION_DEFINE_FLATTEN_STRUCT(A,
    AGGREGATE_FLATTEN_STRUCT(B,pB);
);

static int kflat_simple_test(struct kflat *kflat) {

	int err = 0;
	struct B b = { "ABC" };
	struct A a = { 0x0000404F, &b };
	struct A* pA = &a;
	struct A* vpA = (struct A*) 0xdeadbeefdabbad00;

	flatten_init(kflat);

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT(A, vpA);
		FLATTEN_STRUCT(A, pA);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;

}

/*******************************************************
 * TEST CASE #2
 *******************************************************/
struct my_list_head {
	struct my_list_head* prev;
	struct my_list_head* next;
};
struct intermediate {
	struct my_list_head* plh;
};
struct my_task_struct {
	int pid;
	struct intermediate* im;
	struct my_list_head u;
	float w;
};
/* RECURSIVE version */
FUNCTION_DEFINE_FLATTEN_STRUCT(my_list_head,
	AGGREGATE_FLATTEN_STRUCT(my_list_head,prev);
	AGGREGATE_FLATTEN_STRUCT(my_list_head,next);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(intermediate,
	AGGREGATE_FLATTEN_STRUCT(my_list_head,plh);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(my_task_struct,
	AGGREGATE_FLATTEN_STRUCT(intermediate,im);
	AGGREGATE_FLATTEN_STRUCT(my_list_head,u.prev);
	AGGREGATE_FLATTEN_STRUCT(my_list_head,u.next);
);

/* ITER version */
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(my_list_head);
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(intermediate);
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(my_task_struct);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(my_list_head,
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,prev);
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,next);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(intermediate,
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,plh);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(my_task_struct,
	AGGREGATE_FLATTEN_STRUCT_ITER(intermediate,im);
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,u.prev);
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,u.next);
);

static int kflat_overlaplist_test(struct kflat *kflat) {
	int err = 0;
	struct my_task_struct T;
	struct intermediate IM = {&T.u};

	T.pid = 123;
	T.im = &IM;
	T.u.prev = T.u.next = &T.u;
	T.w = 1.0;

	flatten_init(kflat);

	FOR_ROOT_POINTER(&T,
		FLATTEN_STRUCT(my_task_struct,&T);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

static int kflat_overlaplist_test_iter(struct kflat *kflat) {
	int err = 0;
	struct my_task_struct T;
	struct intermediate IM = {&T.u};

	T.pid = 123;
	T.im = &IM;
	T.u.prev = T.u.next = &T.u;
	T.w = 1.0;

	flatten_init(kflat);
	

	FOR_ROOT_POINTER(&T,
		UNDER_ITER_HARNESS(
			FLATTEN_STRUCT_ITER(my_task_struct,&T);
		);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

/*******************************************************
 * TEST CASE #3
 *******************************************************/
typedef struct struct_B {
	int i;
} my_B;
typedef struct struct_A {
	unsigned long ul;
	my_B* pB0;
	my_B* pB1;
	my_B* pB2;
	my_B* pB3;
	char* p;
} my_A;

/* RECURSIVE version */
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(my_B);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(my_A,
	STRUCT_ALIGN(64);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB0);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB1);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB2);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB3);
	AGGREGATE_FLATTEN_STRING(p);
);

/* ITER version */
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ITER(my_B);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ITER(my_A,
	STRUCT_ALIGN(120);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB0);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB1);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB2);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB3);
	AGGREGATE_FLATTEN_STRING(p);
);

static int kflat_overlapptr_test(struct kflat *kflat) {
	int err = 0;
	my_B arrB[4] = {{1},{2},{3},{4}};
	my_A T[3] = {{},{0,&arrB[0],&arrB[1],&arrB[2],&arrB[3],"p in struct A"},{}};
	unsigned char* p;

	flatten_init(kflat);
	

	flat_infos("sizeof(struct A): %zu\n",sizeof(my_A));
	flat_infos("sizeof(struct B): %zu\n",sizeof(my_B));

	p = (unsigned char*)&T[1]-8;
	FOR_ROOT_POINTER(p,
		FLATTEN_TYPE_ARRAY(unsigned char,p,sizeof(struct A)+16);
	);

	FOR_ROOT_POINTER(&T[1],
		FLATTEN_STRUCT_TYPE(my_A,&T[1]);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

static int kflat_overlapptr_test_iter(struct kflat *kflat) {
	int err = 0;
	my_B arrB[4] = {{1},{2},{3},{4}};
	my_A T[3] = {{},{0,&arrB[0],&arrB[1],&arrB[2],&arrB[3],"p in struct A"},{}};
	unsigned char* p;

	flatten_init(kflat);
	

	flat_infos("sizeof(struct A): %zu\n",sizeof(my_A));
	flat_infos("sizeof(struct B): %zu\n",sizeof(my_B));

	p = (unsigned char*)&T[1]-8;
	FOR_ROOT_POINTER(p,
		FLATTEN_TYPE_ARRAY(unsigned char,p,sizeof(struct A)+16);
	);

	FOR_ROOT_POINTER(&T[1],
		UNDER_ITER_HARNESS(
			FLATTEN_STRUCT_TYPE_ITER(my_A,&T[1]);
		);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}


/*******************************************************
 * TEST CASE #4
 *******************************************************/
struct myLongList {
	int k;
	struct list_head v;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongList,24,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongList,24,v.next,8,1,-8);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongList,24,v.prev,16,1,-8);
);

/*
 *    (head)
 * [myLongList]--|-> [myLongList] --> [myLongList] --> [myLongList] ...
 * 			   <-|-- [myLongList] <-- [myLongList] <-- [myLongList] ...
 */
static int kflat_list_test_iter(struct kflat *kflat, int debug_flag) {
	int i, err = 0;
	struct myLongList myhead = {-1};
	struct list_head* head;
	struct list_head *p;
	unsigned long count = 0;

	INIT_LIST_HEAD(&myhead.v);
	head = &myhead.v;
	for (i = 0; i < 10; ++i) {
		struct myLongList* item = kvzalloc(sizeof(struct myLongList),GFP_KERNEL);
		item->k = i+1;
		list_add(&item->v, head);
		head = &item->v;
	}

	list_for_each(p, &myhead.v) {
		struct myLongList *entry = list_entry(p, struct myLongList, v);
		(void)entry;
		count++;
	}

	flat_infos("List size: %zu\n",count);

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&myhead,
			FLATTEN_STRUCT_ARRAY_ITER(myLongList,&myhead,1);
		);
	);

	while(!list_empty(&myhead.v)) {
		struct myLongList *entry = list_entry(myhead.v.next, struct myLongList, v);
		list_del(myhead.v.next);
		kvfree(entry);
	}

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}


/*******************************************************
 * TEST CASE #5
 *******************************************************/
struct myLongHeadList {
	int k;
	struct list_head v;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,16);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(list_head,16,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,16,next,0,1);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,16,prev,8,1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHeadList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongHeadList,24,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,16,v.next,8,1);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,16,v.prev,16,1);
);

static int kflat_listhead_test_iter(struct kflat *kflat, int debug_flag) {
	int i, err = 0;
	struct list_head lhead;
	struct list_head* head = &lhead;
	struct list_head *p;
	unsigned long count = 0;

	INIT_LIST_HEAD(&lhead);
	for (i=0; i<10; ++i) {
		struct myLongHeadList* item = kvzalloc(sizeof(struct myLongHeadList),GFP_KERNEL);
		item->k = i+1;
		list_add(&item->v, head);
		head = &item->v;
	}

	list_for_each(p, &lhead) {
		struct myLongHeadList *entry = list_entry(p, struct myLongHeadList, v);
		(void)entry;
		count++;
	}

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&lhead,
			FLATTEN_STRUCT_ARRAY_ITER(list_head,&lhead,1);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&lhead,
			list_for_each(p, &lhead) {
				struct myLongHeadList *entry = list_entry(p, struct myLongHeadList, v);
				FLATTEN_STRUCT_ARRAY_ITER(myLongHeadList,entry,1);
			}
		);
	);

	while(!list_empty(&lhead)) {
		struct myLongHeadList *entry = list_entry(lhead.next, struct myLongHeadList, v);
		list_del(lhead.next);
		kvfree(entry);
	}

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

/*******************************************************
 * TEST CASE #6
 *******************************************************/
struct myList {
	long q;
	struct list_head v;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myList,sizeof(struct myList));

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myList,sizeof(struct myList),
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,sizeof(struct list_head),v.next,sizeof(long)+offsetof(struct list_head,next),1);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,sizeof(struct list_head),v.prev,sizeof(long)+offsetof(struct list_head,prev),1);
);

struct myListOwner {
	const char* name;
	long count;
	struct list_head list;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myListOwner,sizeof(struct myListOwner));

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myListOwner,sizeof(struct myListOwner),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(name,offsetof(struct myListOwner,name));
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,sizeof(struct list_head),v.next,
			offsetof(struct myListOwner,list)+offsetof(struct list_head,next),1);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(list_head,sizeof(struct list_head),v.prev,
			offsetof(struct myListOwner,list)+offsetof(struct list_head,prev),1);
	{
		struct myList* __entry;
		list_for_each_entry(__entry, &OFFATTR(struct list_head,offsetof(struct myListOwner,list)), v ) {
			FOR_POINTER(struct myList*,____entry,__entry,
					FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myList,sizeof(struct myList),____entry,1);
			);
		}
	}
);

/*
 *  (head)
 * [myList]--|-> [myList] --> [myList] --> [myList] ...
 * 		   <-|-- [myList] <-- [myList] <-- [myList] ...
 */
static int kflat_listmember_test_iter(struct kflat *kflat, int debug_flag) {
	int i, err = 0;
	struct myListOwner list = { "MyList",0 };
	INIT_LIST_HEAD(&list.list);
	unsigned long count = 0;
	struct list_head *p;

	for (i = 0; i < 10; ++i) {
		struct myList* item = kvzalloc(sizeof(struct myList),GFP_KERNEL);
		item->q = i+1;
		list_add_tail(&item->v, &list.list);
		list.count++;
	}

	list_for_each(p, &list.list) {
		count++;
	}
	flat_infos("List size: %zu\n",count);

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&list,
			FLATTEN_STRUCT_ARRAY_ITER(myListOwner,&list,1);
		);
	);

	while(!list_empty(&list.list)) {
		struct myList *entry = list_first_entry(&list.list, struct myList, v);
		list_del(&entry->v);
		kvfree(entry);
	}

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

/*******************************************************
 * TEST CASE #7
 *******************************************************/
struct paddingA {
	int i;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingA);

struct paddingB {
	char c;
} __attribute__(( aligned(sizeof(long)) ));

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingB,
	STRUCT_ALIGN(sizeof(long));
);

struct paddingC {
	char c;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingC);

struct paddingRoot {
	struct paddingA* a0;
	struct paddingB* b;
	struct paddingA* a1;
	struct paddingC* c;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingRoot,
	AGGREGATE_FLATTEN_STRUCT(paddingA,a0);
	AGGREGATE_FLATTEN_STRUCT(paddingB,b);
	AGGREGATE_FLATTEN_STRUCT(paddingA,a1);
	AGGREGATE_FLATTEN_STRUCT(paddingC,c);
);

static int kflat_padding_test(struct kflat *kflat) {

	int err = 0;
	struct paddingA a0 = {3};
	struct paddingB b = {'3'};
	struct paddingA a1 = {33};
	struct paddingC c = {'x'};

	struct paddingRoot r = {&a0,&b,&a1,&c};

	flatten_init(kflat);

	FOR_ROOT_POINTER(&r,
		FLATTEN_STRUCT(paddingRoot,&r);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

struct fptr_test_struct {
	int i;
	long l;
	char* s;
	int (*df)(const char *name, char **option);
	int (*sf)(struct kflat* kflat, uintptr_t addr);
	struct blstream* (*ef)(struct kflat* kflat, const void* data, size_t size);
	int (*gf)(struct kflat* kflat);
};

int binary_stream_calculate_index(struct kflat* kflat);
int fb_get_options(const char *name, char **option);

FUNCTION_DEFINE_FLATTEN_STRUCT(fptr_test_struct,
	AGGREGATE_FLATTEN_STRING(s);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(df);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(sf);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(ef);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(gf);
);
static int kflat_fpointer_test(struct kflat *kflat) {

	struct fptr_test_struct F = {
		0,1000,"this_string",
		fb_get_options,
		fixup_set_reserve_address,
		binary_stream_append,
		binary_stream_calculate_index
	};

	int err = 0;

	flatten_init(kflat);

	FOR_ROOT_POINTER(&F,
		FLATTEN_STRUCT(fptr_test_struct,&F);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

/*******************************************************
 * TEST CASE #8
 *******************************************************/
static int kflat_pointer_test(struct kflat *kflat) {
	int err = 0;
	double magic_number = 3.14159265359;
	double* pointer_to_it = &magic_number;
	double** pointer_to_pointer_to_it = &pointer_to_it;
	double*** ehhh = &pointer_to_pointer_to_it;

	flatten_init(kflat);

	FOR_ROOT_POINTER(ehhh,
		FLATTEN_TYPE_ARRAY(double**, &pointer_to_pointer_to_it, 1);
		FOREACH_POINTER(double**,p, &pointer_to_pointer_to_it, 1,
			FLATTEN_TYPE_ARRAY(double*, p, 1);
			FOREACH_POINTER(double*, q, p, 1,
				FLATTEN_TYPE_ARRAY(double, q, 1);
			);
		);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}


/*******************************************************
 * TEST CASE #9
 *******************************************************/
struct myLongHList {
	int k;
	struct hlist_node r;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node,16);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_node,16,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node,16,next,0,1);
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_node*,pprev,8,1);
	FOR_POINTER(struct hlist_node*,__pprev, OFFATTR(void**,8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node,16,__pprev,1);
	);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_head,8);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_head,8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_node,16,first,0,1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongHList,24,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongList,24,r.next,8,1,-8);
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_node*,pprev,8,1);
	FOR_POINTER(struct hlist_node*,__pprev, OFFATTR(void**,8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongList,24,__pprev,1);
	);
);

static int kflat_hlist_test_iter(struct kflat *kflat, int debug_flag) {

	int err = 0;
	struct hlist_head harr[5];
	int i,j;
	struct hlist_node *p;

	for (i=0; i<5; ++i) {
		struct hlist_node* node;
		INIT_HLIST_HEAD(&harr[i]);
		node = harr[i].first;
		for (j=0; j<10; ++j) {
			struct myLongHList* item = kvzalloc(sizeof(struct myLongHList),GFP_KERNEL);
			item->k = i*10+j+1;
			if (j==0) {
				hlist_add_head(&item->r, &harr[i]);
			}
			else {
				hlist_add_behind(&item->r,node);
			}
			node = &item->r;
		}
	}

	for (i=0; i<5; ++i) {
		unsigned long count = 0;
		hlist_for_each(p, &harr[i]) {
			struct myLongHList *entry = hlist_entry(p, struct myLongHList, r);
			(void)entry;
			count++;
		}
		flat_infos("myLongHList[%d] size: %lu\n",i,count);
	}

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(harr,
			FLATTEN_STRUCT_ARRAY_ITER(hlist_head,harr,5);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(harr,
			for (i=0; i<5; ++i) {
				hlist_for_each(p, &harr[i]) {
					struct myLongHList *entry = hlist_entry(p, struct myLongHList, r);
					FLATTEN_STRUCT_ARRAY_ITER(myLongHList,entry,1);
				}
			}
		);
	);

	for (i=0; i<5; ++i) {
		while(!hlist_empty(&harr[i])) {
			struct myLongHList *entry = hlist_entry(harr[i].first, struct myLongHList, r);
			hlist_del(harr[i].first);
			kvfree(entry);
		}
	}

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}



/*******************************************************
 * TEST CASE #10
 *******************************************************/
struct myLongHnullsList {
	int k;
	struct hlist_nulls_node n;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_nulls_node,16,
	if (!is_a_nulls(ATTR(next))) {
		AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16,next,0,1);
	}
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_nulls_node*,pprev,8,1);
	FOR_POINTER(struct hlist_nulls_node*,__pprev, OFFATTR(void**,8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16,__pprev,1);
	);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_head,8);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(hlist_nulls_head,8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(hlist_nulls_node,16,first,0,1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHnullsList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongHnullsList,24,
	if (!is_a_nulls(ATTR(n).next)) {
		AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongHnullsList,24,n.next,8,1,-8);
	}
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct hlist_nulls_node*,n.pprev,8,1);
	FOR_POINTER(struct hlist_nulls_node*,__pprev, OFFATTR(void**,8),
		FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongHnullsList,24,__pprev,1);
	);
);

static int kflat_hlist_nulls_test_iter(struct kflat *kflat, int debug_flag) {

	int err = 0;
	struct hlist_nulls_head hnarr[5];
	int i,j;
	struct hlist_nulls_node *p;

	for (i=0; i<5; ++i) {
		INIT_HLIST_NULLS_HEAD(&hnarr[i],0);
		for (j=0; j<10; ++j) {
			struct myLongHnullsList* item = kvzalloc(sizeof(struct myLongHnullsList),GFP_KERNEL);
			item->k = i*10+j+1;
			hlist_nulls_add_head(&item->n, &hnarr[i]);
		}
	}

	for (i=0; i<5; ++i) {
		unsigned long count = 0;
		struct myLongHnullsList *entry;
		hlist_nulls_for_each_entry(entry,p, &hnarr[i],n) {
			(void)entry;
			count++;
		}
		flat_infos("myLongHnullsList[%d] size: %lu\n",i,count);
	}

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(hnarr,
			FLATTEN_STRUCT_ARRAY_ITER(hlist_nulls_head,hnarr,5);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(hnarr,
			for (i=0; i<5; ++i) {
				struct myLongHnullsList *entry;
				hlist_nulls_for_each_entry(entry,p, &hnarr[i],n) {
					FLATTEN_STRUCT_ARRAY_ITER(myLongHnullsList,entry,1);
				}
			}
		);
	);

	for (i=0; i<5; ++i) {
		while(!hlist_nulls_empty(&hnarr[i])) {
			struct myLongHnullsList *entry = hlist_nulls_entry(hnarr[i].first, struct myLongHnullsList, n);
			hlist_nulls_del(hnarr[i].first);
			kvfree(entry);
		}
	}

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}


/*******************************************************
 * TEST CASE #11
 *******************************************************/
struct llist_node *__llist_del_first(struct llist_head *head)
{
	struct llist_node *entry, *old_entry, *next;

	entry = smp_load_acquire(&head->first);
	for (;;) {
		if (entry == NULL)
			return NULL;
		old_entry = entry;
		next = READ_ONCE(entry->next);
		entry = cmpxchg(&head->first, old_entry, next);
		if (entry == old_entry)
			break;
	}

	return entry;
}

struct myLongLList {
	int k;
	struct llist_node l;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_node,8);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(llist_node,8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_node,8,next,0,1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_head,8);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(llist_head,8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(llist_node,8,first,0,1);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongLList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongLList,16,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongLList,16,l.next,8,1,-8);
);

static int kflat_llist_test_iter(struct kflat *kflat, int debug_flag) {

	int err = 0;
	struct llist_head lhead;
	int i;
	struct llist_node *p;
	unsigned long count = 0;

	init_llist_head(&lhead);
	for (i=0; i<10; ++i) {
		struct myLongLList* item = kvzalloc(sizeof(struct myLongLList),GFP_KERNEL);
		item->k = i+1;
		llist_add(&item->l, &lhead);
	}

	llist_for_each(p, lhead.first) {
		struct myLongLList *entry = llist_entry(p, struct myLongLList, l);
		(void)entry;
		count++;
	}
	flat_infos("myLongLList size: %lu\n",count);

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&lhead,
			FLATTEN_STRUCT_ARRAY_ITER(llist_head,&lhead,1);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&lhead,
			llist_for_each(p, lhead.first) {
				struct myLongLList *entry = llist_entry(p, struct myLongLList, l);
				FLATTEN_STRUCT_ARRAY_ITER(myLongLList,entry,1);
			}
		);
	);

	while(!(llist_empty(&lhead))) {
		struct myLongLList *entry = llist_entry(lhead.first, struct myLongLList, l);
		__llist_del_first(&lhead);
		kvfree(entry);
	}

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

/*******************************************************
 * TEST CASE #12
 *******************************************************/
struct point {
    double x;
    double y;
    unsigned n;
    struct point** other;
};

struct figure {
    const char* name;
    unsigned n;
    struct point* points;
};


FUNCTION_DECLARE_FLATTEN_STRUCT(point);
FUNCTION_DECLARE_FLATTEN_STRUCT(figure);
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(point);
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(figure);

FUNCTION_DEFINE_FLATTEN_STRUCT(point,
    AGGREGATE_FLATTEN_TYPE_ARRAY(struct point*, other, ATTR(n));
    FOREACH_POINTER(struct point*, p, ATTR(other), ATTR(n),
            FLATTEN_STRUCT(point, p);
    );
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(point,
    AGGREGATE_FLATTEN_TYPE_ARRAY(struct point*, other, ATTR(n));
    FOREACH_POINTER(struct point*, p, ATTR(other), ATTR(n),
            FLATTEN_STRUCT_ITER(point, p);
    );
);

FUNCTION_DEFINE_FLATTEN_STRUCT(figure,
    AGGREGATE_FLATTEN_STRING(name);
    AGGREGATE_FLATTEN_STRUCT_ARRAY(point,points,ATTR(n));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(figure,
    AGGREGATE_FLATTEN_STRING(name);
    AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER(point,points,ATTR(n));
);

#define MAKE_POINT(p, i, N)   \
    p.x = (cosx[i]);	\
    p.y = (sinx[i]);	\
    p.n = (N);  \
    p.other = kvzalloc((N)*sizeof*p.other,GFP_KERNEL);


static int kflat_circle_test(struct kflat *kflat, size_t num_points, double* cosx, double* sinx) {

	struct figure circle = { "circle",num_points };
	unsigned i, j;
	int err = 0;

	flatten_init(kflat);
	
	
	circle.points = kvzalloc(circle.n*sizeof(struct point),GFP_KERNEL);
	for (i = 0; i < circle.n; ++i) {
		MAKE_POINT(circle.points[i], i, circle.n - 1);
	}
	for (i = 0; i < circle.n; ++i) {
		unsigned u = 0;
		for (j = 0; j < circle.n; ++j) {
			if (i == j)
				continue;
			circle.points[i].other[u++] = &circle.points[j];
		}
	}

	FOR_ROOT_POINTER(&circle,
		FLATTEN_STRUCT(figure, &circle);
	);

	for (i = 0; i < circle.n; ++i) {
		kvfree(circle.points[i].other);
	}
	kvfree(circle.points);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;

}

static int kflat_circle_test_iter(struct kflat *kflat, size_t num_points, double* cosx, double* sinx) {

	struct figure circle = { "circle",num_points };
	unsigned i, j;
	int err = 0;

	flatten_init(kflat);
	

	circle.points = kvzalloc(circle.n*sizeof(struct point),GFP_KERNEL);
    for (i = 0; i < circle.n; ++i) {
        MAKE_POINT(circle.points[i], i, circle.n - 1);
    }
    for (i = 0; i < circle.n; ++i) {
		unsigned u = 0;
		for (j = 0; j < circle.n; ++j) {
			if (i == j)
				continue;
			circle.points[i].other[u++] = &circle.points[j];
		}
	}

	FOR_ROOT_POINTER(&circle,
		UNDER_ITER_HARNESS(
			FLATTEN_STRUCT_ITER(figure, &circle);
		);
	);

	for (i = 0; i < circle.n; ++i) {
		kvfree(circle.points[i].other);
	}
	kvfree(circle.points);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;

}





struct string_node {
	struct rb_node node;
	char* s;
};

void (*flatten_global_variables_g)(struct kflat* kflat) = 0;
EXPORT_SYMBOL(flatten_global_variables_g);

static struct rb_root stringset_root = RB_ROOT;

static struct string_node* stringset_search(const char* s) __attribute__ ((unused));

static struct string_node* stringset_search(const char* s) {

	struct rb_node *node = stringset_root.rb_node;

	while (node) {
		struct string_node* data = container_of(node, struct string_node, node);

		if (strcmp(s,data->s)<0) {
			node = node->rb_left;
		}
		else if (strcmp(s,data->s)>0) {
			node = node->rb_right;
		}
		else
			return data;
	}

	return 0;
}

static int stringset_insert(const char* s) {

	struct string_node* data = kvzalloc(sizeof(struct string_node),GFP_KERNEL);
	struct rb_node **new, *parent = 0;
	data->s = kvzalloc(strlen(s)+1,GFP_KERNEL);
	strcpy(data->s,s);
	new = &(stringset_root.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct string_node* this = container_of(*new, struct string_node, node);

		parent = *new;
		if (strcmp(data->s,this->s)<0)
			new = &((*new)->rb_left);
		else if (strcmp(data->s,this->s)>0)
			new = &((*new)->rb_right);
		else {
		    kvfree((void*)data->s);
		    kvfree(data);
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &stringset_root);

	return 1;
}

static void stringset_destroy(struct rb_root* root) __attribute__ ((unused));

static void stringset_destroy(struct rb_root* root) {

    struct rb_node * p = rb_first(root);
    while(p) {
        struct string_node* data = (struct string_node*)p;
        rb_erase(p, root);
        p = rb_next(p);
        kvfree((void*)data->s);
        kvfree(data);
    }
}

static size_t stringset_count(const struct rb_root* root) {

	struct rb_node * p = rb_first(root);
	size_t count = 0;
	while(p) {
		count++;
		p = rb_next(p);
	}
	return count;
}





struct myTreeNode {
	int i;
	struct rb_node inode;
	struct K {
		char c;
		double d;
	} k;
	struct rb_node snode;
	char* s;
};

static inline void* rbnode_remove_color(const void* ptr) {
	return (void*)( (uintptr_t)ptr & ~3 );
}

static inline struct flatten_pointer* rbnode_add_color(struct flatten_pointer* fptr, const void* ptr) {
	fptr->offset |= (size_t)((uintptr_t)ptr & 3);
	return fptr;
}

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myTreeNode,80);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myTreeNode,80,
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode,80,inode.__rb_parent_color,8,
			rbnode_remove_color,rbnode_add_color,1,-8);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode,80,inode.rb_right,16,1,-8);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode,80,inode.rb_left,24,1,-8);
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode,80,snode.__rb_parent_color,48,
			rbnode_remove_color,rbnode_add_color,1,-48);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode,80,snode.rb_right,56,1,-48);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode,80,snode.rb_left,64,1,-48);
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(s,72);
);

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SPECIALIZE(myTreeNode,rb_root,8);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED_SPECIALIZE(myTreeNode,rb_root,8,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myTreeNode,80,rb_node,0,1,-8);
);

static struct myTreeNode* intset_search(struct rb_root* root, int i) __attribute__ ((unused));

static struct myTreeNode* intset_search(struct rb_root* root, int i) {

	struct rb_node *node = root->rb_node;

	while (node) {
		struct myTreeNode* data = container_of(node, struct myTreeNode, inode);

		if (i<data->i) {
			node = node->rb_left;
		}
		else if (i>data->i) {
			node = node->rb_right;
		}
		else
			return data;
	}

	return 0;
}

static int intset_insert(struct rb_root* root, struct myTreeNode* idata) {

	struct rb_node **new, *parent = 0;
	new = &(root->rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct myTreeNode* this = container_of(*new, struct myTreeNode, inode);

		parent = *new;
		if (idata->i<this->i)
			new = &((*new)->rb_left);
		else if (idata->i>this->i)
			new = &((*new)->rb_right);
		else {
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&idata->inode, parent, new);
	rb_insert_color(&idata->inode, root);

	return 1;
}

static void intset_destroy(struct rb_root* root) __attribute__ ((unused));

static void intset_destroy(struct rb_root* root) {

    struct rb_node * p = rb_first(root);
    while(p) {
        rb_erase(p, root);
        p = rb_next(p);
    }
}

static size_t intset_count(const struct rb_root* root) {

	struct rb_node * p = rb_first(root);
	size_t count = 0;
	while(p) {
		count++;
		p = rb_next(p);
	}
	return count;
}

static struct myTreeNode* strset_search(struct rb_root* root, const char* s) __attribute__ ((unused));

static struct myTreeNode* strset_search(struct rb_root* root, const char* s) {

	struct rb_node *node = root->rb_node;

	while (node) {
		struct myTreeNode* data = container_of(node, struct myTreeNode, snode);

		if (strcmp(s,data->s)<0) {
			node = node->rb_left;
		}
		else if (strcmp(s,data->s)>0) {
			node = node->rb_right;
		}
		else
			return data;
	}

	return 0;
}

static int strset_insert(struct rb_root* root, struct myTreeNode* sdata) {

	struct rb_node **new, *parent = 0;
	new = &(root->rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct myTreeNode* this = container_of(*new, struct myTreeNode, snode);

		parent = *new;
		if (strcmp(sdata->s,this->s)<0)
			new = &((*new)->rb_left);
		else if (strcmp(sdata->s,this->s)>0)
			new = &((*new)->rb_right);
		else {
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&sdata->snode, parent, new);
	rb_insert_color(&sdata->snode, root);

	return 1;
}

static void strset_destroy(struct rb_root* root) __attribute__ ((unused));

static void strset_destroy(struct rb_root* root) {

    struct rb_node * p = rb_first(root);
    while(p) {
    	struct myTreeNode* data = container_of(p,struct myTreeNode,snode);
    	rb_erase(p, root);
        p = rb_next(p);
        kvfree(data->s);
    }
}

static size_t strset_count(const struct rb_root* root) {

	struct rb_node * p = rb_first(root);
	size_t count = 0;
	while(p) {
		count++;
		p = rb_next(p);
	}
	return count;
}

static int kflat_rbnode_test_iter(struct kflat *kflat, int debug_flag) {

	int err=0;
	int i;

	struct rb_root iroot = RB_ROOT;
	struct rb_root sroot = RB_ROOT;

	struct myTreeNode tarr[15] = {};
	for (i=0; i<10; ++i) tarr[i].s = kvzalloc(4,GFP_KERNEL);
	strcpy(tarr[0].s,"AA0");
	strcpy(tarr[1].s,"AA5");
	strcpy(tarr[2].s,"AA9");
	strcpy(tarr[3].s,"AA4");
	strcpy(tarr[4].s,"AA2");
	strcpy(tarr[5].s,"AA6");
	strcpy(tarr[6].s,"AA7");
	strcpy(tarr[7].s,"AA1");
	strcpy(tarr[8].s,"AA8");
	strcpy(tarr[9].s,"AA3");
	for (i=5; i<15; ++i) tarr[i].i = i-5;

	for (i=0; i<10; ++i) {
		strset_insert(&sroot, &tarr[i]);
	}
	flat_infos("strset size: %lu\n",strset_count(&sroot));

	for (i=5; i<15; ++i) {
		intset_insert(&iroot, &tarr[i]);
	}
	flat_infos("intset size: %lu\n",intset_count(&iroot));

	for (i=0; i<15; ++i) {
		flat_infos("myTree[%d]: %016lx   (i)P[%016lx]L[%016lx]R[%016lx]  (s)P[%016lx]L[%016lx]R[%016lx]\n",
				i, (unsigned long) &tarr[i],
				(unsigned long) rbnode_remove_color((void*)tarr[i].inode.__rb_parent_color),
				(unsigned long) tarr[i].inode.rb_left, (unsigned long) tarr[i].inode.rb_right,
				(unsigned long) rbnode_remove_color((void*)tarr[i].snode.__rb_parent_color),
				(unsigned long) tarr[i].snode.rb_left, (unsigned long) tarr[i].snode.rb_right);
	}
	flat_infos("iroot: %016lx\n", (unsigned long) &iroot);
	flat_infos("sroot: %016lx\n", (unsigned long) &sroot);

	flat_infos("myTreeNode size: %zu\n",sizeof(struct myTreeNode));
	flat_infos("offsetof(myTreeNode.i): %zu\n",offsetof(struct myTreeNode,i));
	flat_infos("offsetof(myTreeNode.inode): %zu\n",offsetof(struct myTreeNode,inode));
	flat_infos("offsetof(myTreeNode.s): %zu\n",offsetof(struct myTreeNode,s));
	flat_infos("offsetof(myTreeNode.snode): %zu\n",offsetof(struct myTreeNode,snode));

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&iroot,
			FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE(myTreeNode,rb_root,&iroot,1);
		);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&sroot,
			FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE(myTreeNode,rb_root,&sroot,1);
		);
	);

	strset_destroy(&sroot);
	sroot.rb_node = 0;
	intset_destroy(&iroot);
	iroot.rb_node = 0;

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}



int iarr[10] = {0,1,2,3,4,5,6,7,8,9};
struct iptr {
	long l;
	int* p;
	struct iptr** pp;
};
FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(iptr,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(iptr,24,
    AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(int,p,8,OFFATTR(long,0));
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct iptr*,pp,16,1);
	FOR_POINTER(struct iptr*,__iptr_1,/*ATTR(pp)*/ OFFATTR(void**,16), /* not SAFE */
	  FLATTEN_STRUCT_ARRAY_ITER(iptr,__iptr_1,1);  /* not SAFE */
	);
);

int kflat_record_pointer_test(struct kflat *kflat) {

	struct iptr pv = {0,0,0};
	struct iptr* ppv = &pv;
	struct iptr pv2 = {10,iarr,&ppv};
	int err = 0;

	flatten_init(kflat);
	

	flat_infos("offsetof(struct iptr,l): [%ld] %zu\n",pv2.l,offsetof(struct iptr,l));
	flat_infos("offsetof(struct iptr,p): [%lx] %zu\n",(unsigned long)pv2.p,offsetof(struct iptr,p));
	flat_infos("offsetof(struct iptr,pp): [%lx] %zu\n",(unsigned long)pv2.pp,offsetof(struct iptr,pp));
	flat_infos("&pv: %lx\n",(unsigned long)&pv);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&pv2,
			FLATTEN_STRUCT_ARRAY_ITER(iptr,&pv2,1);
		);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;

}

FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(task_struct);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(task_struct,
		AGGREGATE_FLATTEN_STRUCT_ITER(task_struct,last_wakee);
		AGGREGATE_FLATTEN_STRUCT_ITER(task_struct,real_parent);
		AGGREGATE_FLATTEN_STRUCT_ITER(task_struct,parent);
		AGGREGATE_FLATTEN_STRUCT_ITER(task_struct,group_leader);
		AGGREGATE_FLATTEN_STRUCT_ITER(task_struct,pi_top_task);
		AGGREGATE_FLATTEN_STRUCT_ITER(task_struct,oom_reaper_list);
);

FUNCTION_DECLARE_FLATTEN_STRUCT(task_struct);

FUNCTION_DEFINE_FLATTEN_STRUCT(task_struct,
		AGGREGATE_FLATTEN_STRUCT(task_struct,last_wakee);
		AGGREGATE_FLATTEN_STRUCT(task_struct,real_parent);
		AGGREGATE_FLATTEN_STRUCT(task_struct,parent);
		AGGREGATE_FLATTEN_STRUCT(task_struct,group_leader);
		AGGREGATE_FLATTEN_STRUCT(task_struct,pi_top_task);
		AGGREGATE_FLATTEN_STRUCT(task_struct,oom_reaper_list);
);

void print_struct_task_offsets(struct task_struct* t) {
	flat_infos("task_struct.PID: %d\n",t->pid);
	flat_infos("task_struct.last_wakee: %zu\n",offsetof(struct task_struct,last_wakee));
	flat_infos("task_struct.real_parent: %zu\n",offsetof(struct task_struct,real_parent));
	flat_infos("task_struct.parent: %zu\n",offsetof(struct task_struct,parent));
	flat_infos("task_struct.group_leader: %zu\n",offsetof(struct task_struct,group_leader));
	flat_infos("task_struct.pi_top_task: %zu\n",offsetof(struct task_struct,pi_top_task));
	flat_infos("task_struct.oom_reaper_list: %zu\n",offsetof(struct task_struct,oom_reaper_list));
	flat_infos("task_struct.pid: %zu\n",offsetof(struct task_struct,pid));
	flat_infos("task_struct.tgid: %zu\n",offsetof(struct task_struct,tgid));
	flat_infos("task_struct.prio: %zu\n",offsetof(struct task_struct,prio));
	flat_infos("task_struct size: %zu\n",sizeof(struct task_struct));
}

static int kflat_currenttask_test(struct kflat *kflat) {

	int err = 0;
	struct task_struct* t;

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = 1;
	

	t = current;
	print_struct_task_offsets(t);

	FOR_ROOT_POINTER(t,
		FLATTEN_STRUCT(task_struct, t);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;

}

static int kflat_currenttask_test_iter(struct kflat *kflat) {

	int err = 0;
	struct task_struct* t;

	flatten_init(kflat);
	

	t = current;
	print_struct_task_offsets(t);

	FOR_ROOT_POINTER(t,
		UNDER_ITER_HARNESS(
			FLATTEN_STRUCT_ITER(task_struct, t);
		);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;

}

static inline const struct string_node* ptr_remove_color(const struct string_node* ptr) {
	return (const struct string_node*)( (uintptr_t)ptr & ~3 );
}

static inline struct flatten_pointer* fptr_add_color(struct flatten_pointer* fptr, const struct string_node* ptr) {
	fptr->offset |= (size_t)((uintptr_t)ptr & 3);
	return fptr;
}

FUNCTION_DECLARE_FLATTEN_STRUCT(string_node);
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(string_node);

FUNCTION_DEFINE_FLATTEN_STRUCT(string_node,
	STRUCT_ALIGN(4);
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER(string_node,node.__rb_parent_color,ptr_remove_color,fptr_add_color);
	AGGREGATE_FLATTEN_STRUCT(string_node,node.rb_right);
	AGGREGATE_FLATTEN_STRUCT(string_node,node.rb_left);
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(string_node,
	STRUCT_ALIGN(4);
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER(string_node,node.__rb_parent_color,ptr_remove_color,fptr_add_color);
	AGGREGATE_FLATTEN_STRUCT_ITER(string_node,node.rb_right);
	AGGREGATE_FLATTEN_STRUCT_ITER(string_node,node.rb_left);
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(rb_root,
	AGGREGATE_FLATTEN_STRUCT(string_node,rb_node);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(rb_root,
	AGGREGATE_FLATTEN_STRUCT_ITER(string_node,rb_node);
);

void print_string_node_tree(struct rb_node* node, int depth) {

	const char* s = "          ";
	const char* ps = &s[10];
	struct string_node* this = container_of(node, struct string_node, node);

	flat_infos("%s(%lx)[C:%lx][L:%lx][R:%lx]: %s\n",
			ps-2*depth,(uintptr_t)node,node->__rb_parent_color,(uintptr_t)node->rb_left,(uintptr_t)node->rb_right,this->s);
	if (node->rb_left) {
		print_string_node_tree(node->rb_left,depth+1);
	}
	if (node->rb_right) {
		print_string_node_tree(node->rb_right,depth+1);
	}
}

static int kflat_stringset_test(struct kflat *kflat, size_t num_strings) {

	static const char chars[] = "ABCDEFGHIJ";
	unsigned i,j;
	int err = 0;

	for (j=0; j<num_strings; ++j) {
		char* s = kvzalloc(sizeof chars,GFP_KERNEL);
		for (i=0; i<sizeof chars - 1; ++i) {
			unsigned char u;
			get_random_bytes(&u,1);
			s[i] = chars[u%(sizeof chars - 1)];
		}
		stringset_insert(s);
		kvfree(s);
	}

	flat_infos("String set size: %zu\n",stringset_count(&stringset_root));

	flatten_init(kflat);
	flatten_set_option(kflat, 1);
	

	FOR_ROOT_POINTER(&stringset_root,
		FLATTEN_STRUCT(rb_root,&stringset_root);
	);

	stringset_destroy(&stringset_root);
	stringset_root.rb_node = 0;

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

static int kflat_stringset_test_iter(struct kflat *kflat, size_t num_strings) {

	static const char chars[] = "ABCDEFGHIJ";
	unsigned i,j;
	int err = 0;

	for (j=0; j<num_strings; ++j) {
		char* s = kvzalloc(sizeof chars,GFP_KERNEL);
		for (i=0; i<sizeof chars - 1; ++i) {
			unsigned char u;
			get_random_bytes(&u,1);
			s[i] = chars[u%(sizeof chars - 1)];
		}
		stringset_insert(s);
		kvfree(s);
	}

	flat_infos("String set size: %zu\n",stringset_count(&stringset_root));

	flatten_init(kflat);
	

	FOR_ROOT_POINTER(&stringset_root,
		UNDER_ITER_HARNESS(
			FLATTEN_STRUCT_ITER(rb_root,&stringset_root);
		);
	);

	stringset_destroy(&stringset_root);
	stringset_root.rb_node = 0;

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

struct CC {
	int i;
};

struct BB {
	long s;
	long n;
	int* pi;
	struct CC* pC;
};

struct MM {
	const char* s;
	struct BB arrB[4];
	long* Lx;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(CC,
);

FUNCTION_DEFINE_FLATTEN_STRUCT(BB,
		AGGREGATE_FLATTEN_TYPE_ARRAY(int,pi,ATTR(n));
		AGGREGATE_FLATTEN_STRUCT(CC,pC);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(MM,
	AGGREGATE_FLATTEN_STRING(s);
	for (int __i=0; __i<4; ++__i) {
		const struct BB* p = ATTR(arrB)+__i;
		AGGREGATE_FLATTEN_STRUCT_STORAGE(BB,p);
	}
	AGGREGATE_FLATTEN_TYPE_ARRAY(long,Lx,0);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(CC,
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(BB,
		AGGREGATE_FLATTEN_TYPE_ARRAY(int,pi,ATTR(n));
		AGGREGATE_FLATTEN_STRUCT_ITER(CC,pC);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(MM,
	AGGREGATE_FLATTEN_STRING(s);
	for (int __i=0; __i<4; ++__i) {
		const struct BB* p = ATTR(arrB)+__i;
		AGGREGATE_FLATTEN_STRUCT_STORAGE_ITER(BB,p);
	}
	AGGREGATE_FLATTEN_TYPE_ARRAY(long,Lx,0);
);

static int kflat_structarray_test(struct kflat *kflat) {

	struct CC c0 = {}, c1 = {1000}, c2 = {1000000};
	int T[60] = {};
	struct MM obM = {
			"This is a M object here",
			{
					{0,3,&T[3],&c0},
					{10,20,&T[10],&c1},
					{15,40,&T[15],&c2},
			},
	};
	unsigned char* p = (unsigned char*)&obM;
	unsigned char* q = (unsigned char*)&obM.arrB[3].n;
	size_t q_offset = q-p;
	int err = 0;

	for (int i=0; i<60; ++i) {
		T[i] = i;
	}

	flatten_init(kflat);

	FOR_ROOT_POINTER(p,
			FLATTEN_TYPE_ARRAY(unsigned char,p,q_offset);
	);
	FOR_ROOT_POINTER(q,
			FLATTEN_TYPE_ARRAY(unsigned char,p,sizeof(struct MM)-q_offset);
	);

	FOR_ROOT_POINTER(&obM,
		FLATTEN_STRUCT(MM,&obM);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

static int kflat_structarray_test_iter(struct kflat *kflat) {

	struct CC c0 = {}, c1 = {1000}, c2 = {1000000};
	int T[60] = {};
	struct MM obM = {
			"This is a M object here",
			{
					{0,3,&T[3],&c0},
					{10,20,&T[10],&c1},
					{15,40,&T[15],&c2},
			},
	};
	unsigned char* p = (unsigned char*)&obM;
	unsigned char* q = (unsigned char*)&obM.arrB[3].n;
	size_t q_offset = q-p;
	int err = 0;

	for (int i=0; i<60; ++i) {
		T[i] = i;
	}

	flatten_init(kflat);

	FOR_ROOT_POINTER(p,
			FLATTEN_TYPE_ARRAY(unsigned char,p,q_offset);
	);
	FOR_ROOT_POINTER(q,
			FLATTEN_TYPE_ARRAY(unsigned char,p,sizeof(struct MM)-q_offset);
	);

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&obM,
			FLATTEN_STRUCT_ITER(MM,&obM);
		);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

static int kflat_info_test(struct kflat *kflat) {

	int err = 0;

	flat_infos("ADDR_VALID(0): %zu\n", ADDR_VALID(0));
	err = (ADDR_VALID(0) != 0);

	return err;
}

#include "kflat_test_data.h"


/*******************************************************
 * TEST SUITE ENTRY POINT
 *******************************************************/
int kflat_ioctl_test(struct kflat *kflat, unsigned int cmd, unsigned long arg) {

	int err = 0;
	int flags = KFLAT_ARG_TO_FLAG(arg);
	int debug_flag = flags & KFLAT_DEBUG_FLAG;
	int iter_flag = flags & KFLAT_TEST_ITER;
	int test_code = KFLAT_ARG_TO_CODE(arg);

	kflat->debug_flag = debug_flag;

	switch(test_code) {
		case INFO:
			err = kflat_info_test(kflat);
			break;

		case SIMPLE:
			err = kflat_simple_test(kflat);
			break;

		case CIRCLE:
			if(iter_flag)
				err = kflat_circle_test_iter(kflat, 750, cosxi, sinxi);
			else
				err = kflat_circle_test(kflat, 30, cosx, sinx);
			break;

		case STRINGSET:
			if(iter_flag)
				err = kflat_stringset_test_iter(kflat, 50000);
			else
				err = kflat_stringset_test(kflat, 50);
			break;
		
		case POINTER:
			err = kflat_pointer_test(kflat);
			break;
		
		case RPOINTER:
			err = kflat_record_pointer_test(kflat);
			break;

		case CURRENTTASK:
			if(iter_flag)
				err = kflat_currenttask_test_iter(kflat);
			else
				err = kflat_currenttask_test(kflat);
			break;

		case OVERLAPLIST:
			if(iter_flag)
				err = kflat_overlaplist_test_iter(kflat);
			else
				err = kflat_overlaplist_test(kflat);
			break;
		
		case OVERLAPPTR:
			if(iter_flag)
				err = kflat_overlapptr_test_iter(kflat);
			else
				err = kflat_overlapptr_test(kflat);
			break;
		
		case PADDING:
			err = kflat_padding_test(kflat);
			break;

		case STRUCTARRAY:
			if(iter_flag)
				err = kflat_structarray_test_iter(kflat);
			else
				err = kflat_structarray_test(kflat);
			break;
		
		case FPOINTER:
			err = kflat_fpointer_test(kflat);
			break;

		case GETOBJECTCHECK: {
#ifdef KFLAT_GET_OBJ_SUPPORT
				bool ret;
				void* start = NULL; void* end = NULL;
				void* buffer = kmalloc(256, GFP_KERNEL);

				ret = flatten_get_object(buffer + 10, &start, &end);
				if(!ret) {
					flat_errs("%s: flatten_get_object failed to locate heap object", __func__);
					err = -EFAULT;
				} else if(start != buffer || end != buffer + 256) {
					flat_errs("%s: flatten_get_object incorrectly located object 0x%llx:0x%llx (should be: 0x%llx:0x%llx)",
								 __func__, (uint64_t)start, (uint64_t)end, (uint64_t)buffer, (uint64_t)buffer + 256);
					err = -EFAULT;
				}
				kfree(buffer);

				ret = flatten_get_object(&ret, NULL, NULL);
				if(ret) {
					flat_errs("%s: flatten_get_object accepted object from stack", __func__);
					err = -EFAULT;
				}

				ret = flatten_get_object(iarr, NULL, NULL);
				if(ret) {
					flat_errs("%s: flatten_get_object accepted global object", __func__);
					err = -EFAULT;
				}

				ret = flatten_get_object(kflat_ioctl_test, NULL, NULL);
				if(ret) {
					flat_errs("%s: flatten_get_object accepted pointer to code section", __func__);
					err = -EFAULT;
				}
#else
				pr_warn("%s: KFLAT hasn't been compiled with KFLAT_GET_OBJ_SUPPORT option enabled", __func__);
				pr_warn("%s: Ignoring test GETOBJECTCHECK...", __func__);
#endif

			}
			break;

		case LIST:
			err = kflat_list_test_iter(kflat, debug_flag);
			break;
		
		case LISTHEAD:
			err = kflat_listhead_test_iter(kflat, debug_flag);
			break;
		
		case LISTMEMBER:
			err = kflat_listmember_test_iter(kflat, debug_flag);
			break;

		case HLIST:
			err = kflat_hlist_test_iter(kflat, debug_flag);
			break;

		case HNULLSLIST:
			err = kflat_hlist_nulls_test_iter(kflat, debug_flag);
			break;

		case LLIST:
			err = kflat_llist_test_iter(kflat, debug_flag);
			break;

		case RBNODE:
			err = kflat_rbnode_test_iter(kflat, debug_flag);
			break;

		default:
			flat_errs("%s: invalid test code provided(%d)", __func__, test_code);
			err = -EINVAL;
	}

	// On success, return the size of flattened memory
	if(err < 0)
		return err;
	
	if(kflat->area != NULL)
		return *(size_t*)kflat->area + sizeof(size_t);
	
	return 0;
}
