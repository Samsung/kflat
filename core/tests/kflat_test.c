#include "kflat.h"

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/interval_tree_generic.h>
#include <linux/list_nulls.h>

/* Global variables for flatten test */

int kflat_global_int;

enum kflat_global_enum {
	kflat_global_enum_val0,
	kflat_global_enum_val1,
};

enum kflat_global_enum kflat_global_enum_named;
enum kflat_global_enum kflat_global_enum_named_array[5];

enum { kflat_global_enum_n_val0, kflat_global_enum_n_val1 } kflat_global_enum_nonamed;

typedef enum kflat_global_enum kflat_global_enum_t;
kflat_global_enum_t kflat_global_enum_typedef;
kflat_global_enum_t* kflat_global_enum_typedef_pointer;

struct kflat_global_struct {
	int i;
};

union kflat_global_union {
	int i;
	long l;
};

struct kflat_global_struct kflat_global_struct;
union kflat_global_union kflat_global_union;

struct { int i; } kflat_global_struct_nonamed;

int kflat_global_int_array[20];
struct kflat_global_struct kflat_global_struct_array[5];

struct { int i; } kflat_global_struct_nonamed_array[2];

int* kflat_global_int_p = &kflat_global_int;
int** kflat_global_int_pp = &kflat_global_int_p;

struct kflat_global_struct* kflat_global_struct_p = &kflat_global_struct;
struct kflat_global_struct* kflat_global_struct_pa = kflat_global_struct_array;
struct kflat_global_struct** kflat_global_struct_pp = &kflat_global_struct_p;
enum kflat_global_enum* kflat_global_enum_named_p = &kflat_global_enum_named;

struct kflat_global_struct** kflat_global_struct_pp_array[9];

char* kflat_global_string = "kflat";
void* kfalt_global_void = "kflat";

void (*kflat_global_fun)(int);
void (*kflat_global_fun_array[12])(int);

typedef void (*kflat_global_fun_t)(int);
kflat_global_fun_t kflat_global_function_pointer_array_typedef[3];

int* kflat_global_pointer_array[8];
const char* kflat_global_string_array[4];
struct kflat_global_struct* kflat_global_struct_pointer_array[4];

typedef int myInt;
typedef myInt myIntInt;
typedef myIntInt myIntIntInt;

myIntIntInt kflat_global_typedef_int;

typedef struct kflat_global_struct my_global_struct_t;
my_global_struct_t kflat_global_struct_typedef;

typedef struct kflat_global_struct my_global_struct_array_t[2];
my_global_struct_array_t kflat_global_struct_typedef_array;

my_global_struct_t* kflat_global_struct_pointer_typedef;

struct kflat_struct_forward;
struct kflat_struct_forward* kflat_global_struct_forward;

myIntInt kflat_global_typedef_int_array[20];
my_global_struct_t global_typedef_struct_array[5];

/* done */

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

INTERVAL_TREE_DEFINE(struct flat_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST,static __used,interval_tree)

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

	struct string_node* data = libflat_zalloc(1,sizeof(struct string_node));
	struct rb_node **new, *parent = 0;
	data->s = libflat_zalloc(1,strlen(s)+1);
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
		    libflat_free((void*)data->s);
		    libflat_free(data);
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
        libflat_free((void*)data->s);
        libflat_free(data);
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

struct B {
	unsigned char T[4];
};

struct A {
	unsigned long X;
	struct B* pB;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(B,
);

FUNCTION_DEFINE_FLATTEN_STRUCT(A,
    AGGREGATE_FLATTEN_STRUCT(B,pB);
);

static int kflat_simple_test(struct kflat *kflat) {

	struct B b = { "ABC" };
	struct A a = { 0x0000404F, &b/*0xffffdddddddddddd*/ };
	struct A* pA = &a;
	struct A* vpA = (struct A*) 0xdeadbeefdabbad00;
	int err = 0;

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

struct my_list_head;
struct intermediate;
struct my_task_struct;

FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(my_list_head);
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(intermediate);
FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(my_task_struct);

struct my_list_head {
	struct my_list_head* prev;
	struct my_list_head* next;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(my_list_head,
	AGGREGATE_FLATTEN_STRUCT(my_list_head,prev);
	AGGREGATE_FLATTEN_STRUCT(my_list_head,next);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(my_list_head,
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,prev);
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,next);
);

struct intermediate {
	struct my_list_head* plh;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(intermediate,
	AGGREGATE_FLATTEN_STRUCT(my_list_head,plh);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(intermediate,
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,plh);
);

struct my_task_struct {
	int pid;
	struct intermediate* im;
	struct my_list_head u;
	float w;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(my_task_struct,
	AGGREGATE_FLATTEN_STRUCT(intermediate,im);
	AGGREGATE_FLATTEN_STRUCT(my_list_head,u.prev);
	AGGREGATE_FLATTEN_STRUCT(my_list_head,u.next);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(my_task_struct,
	AGGREGATE_FLATTEN_STRUCT_ITER(intermediate,im);
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,u.prev);
	AGGREGATE_FLATTEN_STRUCT_ITER(my_list_head,u.next);
);

static int kflat_overlaplist_test(struct kflat *kflat) {

	struct my_task_struct T;
	struct intermediate IM = {&T.u};
	int err = 0;

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

	struct my_task_struct T;
	struct intermediate IM = {&T.u};
	int err = 0;

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

typedef struct struct_B {
	int i;
} my_B;

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(my_B,
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ITER(my_B,
);

typedef struct struct_A {
	unsigned long ul;
	my_B* pB0;
	my_B* pB1;
	my_B* pB2;
	my_B* pB3;
	char* p;
} /*__attribute__((aligned(64)))*/ my_A;

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(my_A,
	STRUCT_ALIGN(64);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB0);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB1);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB2);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B,pB3);
	AGGREGATE_FLATTEN_STRING(p);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ITER(my_A,
	STRUCT_ALIGN(120);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB0);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB1);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB2);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(my_B,pB3);
	AGGREGATE_FLATTEN_STRING(p);
);

static int kflat_overlapptr_test(struct kflat *kflat) {

	my_B arrB[4] = {{1},{2},{3},{4}};
	my_A T[3] = {{},{0,&arrB[0],&arrB[1],&arrB[2],&arrB[3],"p in struct A"},{}};
	int err = 0;
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

	my_B arrB[4] = {{1},{2},{3},{4}};
	my_A T[3] = {{},{0,&arrB[0],&arrB[1],&arrB[2],&arrB[3],"p in struct A"},{}};
	int err = 0;
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

struct myLongList {
	int k;
	struct list_head v;
};

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(myLongList,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(myLongList,24,
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongList,24,v.next,8,1,-8);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(myLongList,24,v.prev,16,1,-8);
);

static int kflat_list_test_iter(struct kflat *kflat, int debug_flag) {

	struct myLongList myhead = {-1};
	int i;
	struct list_head* head;
	struct list_head *p;
	unsigned long count = 0;
	int err = 0;

	INIT_LIST_HEAD(&myhead.v);
	head = &myhead.v;
	for (i=0; i<10; ++i) {
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
	flat_infos("myLongList size: %lu\n",count);
	flat_infos("sizeof(struct myLongList): %zu\n",sizeof(struct myLongList));
	flat_infos("offsetof(struct myLongList,k): %zu\n",offsetof(struct myLongList,k));
	flat_infos("offsetof(struct myLongList,v): %zu\n",offsetof(struct myLongList,v));

	flatten_init(kflat);
	kflat->FLCTRL.debug_flag = debug_flag;

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&myhead,
			FLATTEN_STRUCT_ARRAY_ITER(myLongList,&myhead,1);
		);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

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

	struct list_head lhead;

	int i;
	struct list_head* head = &lhead;
	struct list_head *p;
	unsigned long count = 0;
	int err = 0;

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
	flat_infos("myLongList size: %lu\n",count);
	flat_infos("sizeof(struct myLongList): %zu\n",sizeof(struct myLongList));
	flat_infos("offsetof(struct myLongList,k): %zu\n",offsetof(struct myLongList,k));
	flat_infos("offsetof(struct myLongList,v): %zu\n",offsetof(struct myLongList,v));

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

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

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

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

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

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
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

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
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
	rb_insert_color(&sdata->snode, &stringset_root);

	return 1;
}

static void strset_destroy(struct rb_root* root) __attribute__ ((unused));

static void strset_destroy(struct rb_root* root) {

    struct rb_node * p = rb_first(root);
    while(p) {
        rb_erase(p, root);
        p = rb_next(p);
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
	for (i=0; i<10; ++i) tarr[i].s = libflat_zalloc(1,4);
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
		flat_infos("myTree[%d]: %016lx   (i)P[%016lx]L[%016lx]R[%016lx]  (s)P[%016lx]L[%016lx]R[%016lx]\n",i,&tarr[i],
				rbnode_remove_color((void*)tarr[i].inode.__rb_parent_color),tarr[i].inode.rb_left,tarr[i].inode.rb_right,
				rbnode_remove_color((void*)tarr[i].snode.__rb_parent_color),tarr[i].snode.rb_left,tarr[i].snode.rb_right);
	}
	flat_infos("iroot: %016lx\n",&iroot);
	flat_infos("sroot: %016lx\n",&sroot);

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

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

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

static int kflat_circle_test_arg_iter(struct kflat *kflat, size_t num_points, double* cosx, double* sinx) {

	struct figure circle = { "circle",num_points };
	unsigned i, j;
	int err = 0;

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

    FLATTEN_FUNCTION_VARIABLE(flatten_circle_arg_iter,circle,&circle);

	for (i = 0; i < circle.n; ++i) {
		kvfree(circle.points[i].other);
	}
	kvfree(circle.points);

	return err;

}

static int kflat_pointer_test(struct kflat *kflat) {

	double magic_number = 3.14159265359;
	double* pointer_to_it = &magic_number;
	double** pointer_to_pointer_to_it = &pointer_to_it;
	double*** ehhh = &pointer_to_pointer_to_it;
	int err = 0;

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

int iarr[10] = {0,1,2,3,4,5,6,7,8,9};
struct iptr {
	long l;
	int* p;
	struct iptr** pp;
};

#define SELF_CONTAINED
#ifdef SELF_CONTAINED

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(iptr,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(iptr,24,
    AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(int,p,8,OFFATTR(long,0));
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct iptr*,pp,16,1);
	FOR_POINTER(struct iptr*,__iptr_1,/*ATTR(pp)*/ OFFATTR(void**,16), /* not SAFE */
	  FLATTEN_STRUCT_ARRAY_ITER(iptr,__iptr_1,1);  /* not SAFE */
	);
);

#else

FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(iptr);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(iptr,
    AGGREGATE_FLATTEN_TYPE_ARRAY(int,p,ATTR(l));
	AGGREGATE_FLATTEN_TYPE_ARRAY(struct iptr*,pp,1);
	FOR_POINTER(struct iptr*,__iptr_1,ATTR(pp) /*OFFATTR(void**,2048)*/, /* not SAFE */
	  FLATTEN_STRUCT_ARRAY_ITER(iptr,__iptr_1,1);  /* not SAFE */
	);
);

#endif

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
		char* s = libflat_zalloc(1,sizeof chars);
		for (i=0; i<sizeof chars - 1; ++i) {
			unsigned char u;
			get_random_bytes(&u,1);
			s[i] = chars[u%(sizeof chars - 1)];
		}
		stringset_insert(s);
		libflat_free(s);
	}

	flat_infos("String set size: %zu\n",stringset_count(&stringset_root));

	flatten_init(kflat);
	flatten_set_option(kflat, 1);
	

	FOR_ROOT_POINTER(&stringset_root,
		FLATTEN_STRUCT(rb_root,&stringset_root);
	);

	stringset_destroy(&stringset_root);

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
		char* s = libflat_zalloc(1,sizeof chars);
		for (i=0; i<sizeof chars - 1; ++i) {
			unsigned char u;
			get_random_bytes(&u,1);
			s[i] = chars[u%(sizeof chars - 1)];
		}
		stringset_insert(s);
		libflat_free(s);
	}

	flat_infos("String set size: %zu\n",stringset_count(&stringset_root));

	flatten_init(kflat);
	

	FOR_ROOT_POINTER(&stringset_root,
		UNDER_ITER_HARNESS(
			FLATTEN_STRUCT_ITER(rb_root,&stringset_root);
		);
	);

	stringset_destroy(&stringset_root);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;
}

struct paddingA {
	int i;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingA,
);

struct paddingB {
	char c;
} __attribute__((aligned(sizeof(long))));;

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingB,
	STRUCT_ALIGN(sizeof(long));
);

struct paddingC {
	char c;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingC,
);

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

	flat_infos("a0: %lx [%zu]\n",&a0,sizeof(struct paddingA));
	flat_infos("b: %lx [%zu]\n",&b,sizeof(struct paddingB));
	flat_infos("a1: %lx [%zu]\n",&a1,sizeof(struct paddingA));
	flat_infos("c: %lx [%zu]\n",&c,sizeof(struct paddingC));

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

	flatten_set_option(kflat, debug_flag);

	switch(test_code) {
		case SIMPLE:
			err = kflat_simple_test(kflat);
			if(err) return err;
			break;

		case CIRCLE:
			if(iter_flag)
				err = kflat_circle_test_iter(kflat, 750, cosxi, sinxi);
			else
				err = kflat_circle_test(kflat, 30, cosx, sinx);
			break;
		
		case CIRCLEARG:
			err = kflat_circle_test_arg_iter(kflat, 750, cosxi, sinxi);
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
		
		case GLOBALCHECK: {
				// struct class *wakeup_class;
				// static unsigned long stringset_root_base_address = 0xffffffff8330a668;
				// static unsigned long wakeup_class_base_address = 0xffffffff833451c0;
				// long global_offset = GLOBAL_ADDR_OFFSET(&stringset_root,stringset_root_base_address);
				// wakeup_class = *((struct class**)(wakeup_class_base_address + global_offset));
				// flat_infos("wakeup_class:name: %s\n",wakeup_class->name);
			}
			break;

		case GETOBJECTCHECK: {
				bool ret;
				void* start = NULL; void* end = NULL;
				void* buffer = kmalloc(256, GFP_KERNEL);

				ret = flatten_get_object(buffer + 10, &start, &end);
				if(!ret) {
					flat_errs("%s: flatten_get_object failed to locate heap object", __func__);
					err = -EFAULT;
				}
				if(start != buffer || end != buffer + 256) {
					flat_errs("%s: flatten_get_object incorrectly located object 0x%llx:0x%llx (should be: 0x%llx:0x%llx)",
								 __func__, (uint64_t)start, (uint64_t)end, (uint64_t)buffer, (uint64_t)buffer + 256);
					err = -EFAULT;
				}

			}
			break;

		case LIST:
			err = kflat_list_test_iter(kflat, debug_flag);
			break;
		
		case LISTHEAD:
			err = kflat_listhead_test_iter(kflat, debug_flag);
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

	return err;
}
