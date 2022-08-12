/**
 * @file imginfo.cpp
 * @author Pawel Wieczorek (p.wieczorek@samsung.com)
 * @brief App presenting results of tests embedded into kflat kernel module
 * 
 * @copyright Copyright (c) 2022 Samsung R&D Poland
 * 
 */

#include <cassert>
#include <cmath>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstddef>

#include <set>
#include <string>

#include "../lib/unflatten.hpp"

extern "C" {
#include <rbtree.h>
}

#define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

/* Structures used in kflat tests */
struct task_struct {
	unsigned char padding0[64];
	unsigned int cpu;
	unsigned char padding1[12];
	struct task_struct* last_wakee;
	unsigned char padding2[12];
	int prio;
	unsigned char padding3[1312];
	int pid;
	int tgid;
	unsigned char padding4[8];
	struct task_struct* real_parent;
	struct task_struct* parent;
	unsigned char padding5[32];
	struct task_struct* group_leader;
	unsigned char padding6[664];
	struct task_struct* pi_top_task;
	unsigned char padding7[600];
	struct task_struct* oom_reaper_list;
	unsigned char padding8[5232];
} __attribute__((packed));

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

struct B {
	unsigned char T[4];
};

struct A {
	unsigned long X;
	struct B* pB;
};

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
} /*__attribute__((aligned(64)))*/ my_A;


/* Collection of functions displaying results of kflat tests */

void print_struct_task_offsets(struct task_struct* t) {
	printf("task_struct.last_wakee: %zu\n",offsetof(struct task_struct,last_wakee));
	printf("task_struct.real_parent: %zu\n",offsetof(struct task_struct,real_parent));
	printf("task_struct.parent: %zu\n",offsetof(struct task_struct,parent));
	printf("task_struct.group_leader: %zu\n",offsetof(struct task_struct,group_leader));
	printf("task_struct.pi_top_task: %zu\n",offsetof(struct task_struct,pi_top_task));
	printf("task_struct.oom_reaper_list: %zu\n",offsetof(struct task_struct,oom_reaper_list));
	printf("task_struct.pid: %zu\n",offsetof(struct task_struct,pid));
	printf("task_struct.tgid: %zu\n",offsetof(struct task_struct,tgid));
	printf("task_struct.prio: %zu\n",offsetof(struct task_struct,prio));
	printf("task_struct.cpu: %zu\n",offsetof(struct task_struct,cpu));
	printf("task_struct size: %zu\n",sizeof(struct task_struct));
}

void walk_print_task_struct(struct task_struct* T,std::set<struct task_struct*>& visited) {
	visited.insert(T);
	printf("T[%d:%d], cpu %u, prio %d\n",T->pid,T->tgid,T->cpu,T->prio);
	if ((T->last_wakee!=0)&&(visited.find(T->last_wakee)==visited.end())) {
		walk_print_task_struct(T->last_wakee,visited);
	}
	if ((T->real_parent!=0)&&(visited.find(T->real_parent)==visited.end())) {
		walk_print_task_struct(T->real_parent,visited);
	}
	if ((T->parent!=0)&&(visited.find(T->parent)==visited.end())) {
		walk_print_task_struct(T->parent,visited);
	}
	if ((T->group_leader!=0)&&(visited.find(T->group_leader)==visited.end())) {
		walk_print_task_struct(T->group_leader,visited);
	}
	if ((T->pi_top_task!=0)&&(visited.find(T->pi_top_task)==visited.end())) {
		walk_print_task_struct(T->pi_top_task,visited);
	}
	if ((T->oom_reaper_list!=0)&&(visited.find(T->oom_reaper_list)==visited.end())) {
		walk_print_task_struct(T->oom_reaper_list,visited);
	}
}

struct string_node {
	struct rb_node node;
	const char* s;
};

static void stringset_nprint(const struct rb_root* root, size_t n) {

	struct rb_node * p = rb_first(root);
	printf("[\n");
	size_t i=0;
	while(p) {
		struct string_node* data = (struct string_node*)p;
		printf("  %s\n",data->s);
		p = rb_next(p);
		if (p && (i>=n-1)) {
			printf("  ...\n");
			break;
		}
		++i;
	}
	printf("]\n");
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

struct fptr_test_struct {
	int i;
	long l;
	char* s;
	int (*sf)(struct kflat *kflat, size_t num_strings, int debug_flag);
	struct blstream* (*ef)(struct kflat* kflat, const void* data, size_t size);
	int (*gf)(struct kflat* kflat);
};

int kflat_stringset_module_test(struct kflat *kflat, size_t num_strings, int debug_flag) {
	printf("HOST::kflat_stringset_module_test()\n");
	return 0;
}

int binary_stream_append(struct kflat* kflat, const void* data, size_t size) {
	printf("HOST::binary_stream_append()\n");
	return 0;
}

int binary_stream_calculate_index(struct kflat* kflat) {
	printf("HOST::binary_stream_calculate_index()\n");
	return 0;
}

bool endswith (std::string const &s, std::string const &what) {
    if (s.length() >= what.length()) {
        return (0 == s.compare (s.length() - what.length(), what.length(), what));
    } else {
        return false;
    }
}

uintptr_t get_fpointer_test_function_address(const char* fsym) {
	std::string sf(fsym);
	if (endswith(sf,"kflat_stringset_module_test")) {
		return (uintptr_t)&kflat_stringset_module_test;
	}
	else if (endswith(sf,"binary_stream_append")) {
		return (uintptr_t)&binary_stream_append;
	}
	else if (endswith(sf,"binary_stream_calculate_index")) {
		return (uintptr_t)&binary_stream_calculate_index;
	}

	return 0;
}

uintptr_t print_function_address(const char* fsym) {
	printf("HOST: %s\n",fsym);
	return 0;
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

void print_struct_BB(const struct BB* pB) {
	printf("%ld:%ld",pB->s,pB->n);
	if (pB->pi) {
		printf(" [ ");
		for (long i=0; i<pB->n; ++i) {
			printf("%d ",pB->pi[i]);
		}
		printf("]");
	}
	printf("\n");
	if (pB->pC) {
		printf("C: %d\n",pB->pC->i);
	}
}

struct iptr {
	long l;
	int* p;
	struct iptr** pp;
};

struct paddingA {
	int i;
};

struct paddingB {
	char c;
} __attribute__((aligned(sizeof(long))));;

struct paddingC {
	char c;
};

struct paddingRoot {
	struct paddingA* a0;
	struct paddingB* b;
	struct paddingA* a1;
	struct paddingC* c;
};

struct list_head {
	struct list_head *next, *prev;
};

struct myLongList {
	int k;
	struct list_head v;
};

struct myLongHeadList {
	int k;
	struct list_head v;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct myLongHList {
	int k;
	struct hlist_node r;
};

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};

struct hlist_nulls_node {
	struct hlist_nulls_node *next, **pprev;
};

struct myLongHnullsList {
	int k;
	struct hlist_nulls_node n;
};

struct llist_node {
	struct llist_node *next;
};

struct llist_head {
	struct llist_node *first;
};

struct myLongLList {
	int k;
	struct llist_node l;
};

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

static inline int is_a_nulls(const struct hlist_nulls_node *ptr)
{
	return ((unsigned long)ptr & 1);
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

static size_t intset_count(const struct rb_root* root) {

	struct rb_node * p = rb_first(root);
	size_t count = 0;
	while(p) {
		count++;
		p = rb_next(p);
	}
	return count;
}

int main(int argc, char* argv[]) {
	int ret;

	if(argc < 3) {
		printf("Usage: %s <kflat_image> <test_name>\n", argv[0]);
		return 1;
	}

	FILE* in = fopen(argv[1], "r");
	assert(in != NULL);

	get_function_address_t handler = print_function_address;
	if (!strcmp(argv[2], "FPOINTER"))
		handler = get_fpointer_test_function_address;

	Flatten flatten;
	if (!strcmp(argv[2], "INFO")) {
		if (argc>=4) {
			ret = flatten.info(in,argv[3]);
		}
		else {
			ret = flatten.info(in);
		}
		return ret;
	}
	ret = flatten.load(in, handler);
	assert(ret == 0);

	if (!strcmp(argv[2],"SIMPLE")) {
		printf("sizeof(struct A): %zu\n", sizeof(struct A));
		printf("sizeof(struct B): %zu\n", sizeof(struct B));
		
		const struct A* pA = (const struct A*) flatten.get_next_root();
		printf("pA->X: %016lx\n" ,pA->X);
		printf("pA->pB->T: [%02x%02x%02x%02x]\n", 
					pA->pB->T[0], pA->pB->T[1], 
					pA->pB->T[2], pA->pB->T[3]);
		return 0;
	} else if (!strcmp(argv[2],"CIRCLE")) {
		const struct figure* circle = (const struct figure*) flatten.get_next_root();
		double length = 0, circumference = 0;
		unsigned edge_number = 0;
		for (unsigned int i = 0; i < circle->n - 1; ++i) {
			for (unsigned int j = i; j < circle->n - 1; ++j) {
				if (circle->points[i].other[j]) {

					double path_len = sqrt(  pow(circle->points[i].x-circle->points[i].other[j]->x,2) +
							pow(circle->points[i].y-circle->points[i].other[j]->y,2) );
					length += path_len;

					if (j == i)
						circumference += path_len;
					if ((i == 0) && (j == circle->n - 2))
						circumference += path_len;

					unsigned u;
					for (u = 0; u < circle->n - 1; ++u) {
						if (circle->points[i].other[j]->other[u] == &circle->points[i]) {
							circle->points[i].other[j]->other[u] = 0;
						}
					}
					edge_number++;
				}
			}
		}

		printf("Number of edges/diagonals: %u\n", edge_number);
		printf("Sum of lengths of edges/diagonals: %.17f\n", length);
		printf("Half of the circumference: %.17f\n", circumference / 2);
		return 0;
	}
	else if ((!strcmp(argv[2],"CURRENTTASK")) || (!strcmp(argv[2],"CURRENTTASKM"))) {
		struct task_struct *T = (struct task_struct *) flatten.get_next_root();
		print_struct_task_offsets(T);
		printf("\n");
		printf("# root PID: %d\n",T->pid);
		
		std::set<struct task_struct*> visited;
		walk_print_task_struct(T,visited);
		return 0;
	}
	else if (!strcmp(argv[2],"OVERLAPLIST")) {
		struct my_task_struct *T = (struct my_task_struct *) flatten.get_next_root();
		printf("pid: %d\n", T->pid);
		printf("T: %lx\n", (uintptr_t)T);
		printf("T->im->plh: %lx\n", (uintptr_t)T->im->plh);
		printf("T->u.prev: %lx\n", (uintptr_t)T->u.prev);
		printf("T->u.next: %lx\n", (uintptr_t)T->u.next);
		printf("w: %f\n", T->w);
		return 0;
	}
	else if (!strcmp(argv[2],"OVERLAPPTR")) {
		my_A* pA = (my_A*) flatten.get_seq_root(1);

		printf("%d %d %d %d\n", 
					pA->pB0->i, pA->pB1->i, 
					pA->pB2->i, pA->pB3->i);
		printf("%lx\n", (uintptr_t)pA->p);
		printf("%s\n", pA->p);
		return 0;
	}
	else if ((!strcmp(argv[2],"STRINGSET"))||(!strcmp(argv[2],"STRINGSETM"))) {
		const struct rb_root* root = (struct rb_root*)flatten.get_next_root();
		printf("stringset size: %zu\n",stringset_count(root));
		stringset_nprint(root,10);
		return 0;
	}
	else if (!strcmp(argv[2],"POINTER")) {
		double*** ehhh = (double***) flatten.get_next_root();
		printf("The magic answer to the ultimate question of life?: %f\n", ***ehhh);
		return 0;
	}
	else if (!strcmp(argv[2],"RPOINTER")) {
		struct iptr* p = (struct iptr*) flatten.get_next_root();
		printf("iptr->l: %ld\n", p->l);
		printf("[ ");
		for (int i = 0; i < 10; ++i)
			printf("%d ", p->p[i]);
		printf("]\n");
		printf("**iptr->l: %ld\n", (*(p->pp))->l);
		printf("%p\n", (*p->pp)->p);
		return 0;
	}
	else if (!strcmp(argv[2],"FPOINTER")) {
		const struct fptr_test_struct* p = (const struct fptr_test_struct*) flatten.get_next_root();
		printf("%d\n", p->i);
		printf("%ld\n", p->l);
		printf("%s\n", p->s);
		p->sf(0,0,0);
		p->ef(0,0,0);
		p->gf(0);
		return 0;
	}
	else if (!strcmp(argv[2],"STRUCTARRAY")) {
		const struct MM* pM = (const struct MM*) flatten.get_seq_root(2);
		printf("\n");
		printf("pM->s: %s\n", pM->s);
		for (int i = 0; i < 4; ++i)
			print_struct_BB(&pM->arrB[i]);
		printf("pM->Lx: %p\n", pM->Lx);
		return 0;
	}
	else if (!strcmp(argv[2],"PADDING")) {
		const struct paddingRoot* pr = (const struct paddingRoot*) flatten.get_next_root();
		printf("a0: %d\n", pr->a0->i);
		printf("b: %c \n", pr->b->c);
		printf("a1: %d\n", pr->a1->i);
		printf("c: %c \n", pr->c->c);
		return 0;
	}
	else if (!strcmp(argv[2],"LIST")) {
		struct list_head *p;
		size_t list_size = 0;
		struct myLongList* myhead = (struct myLongList*)flatten.get_next_root();
		printf("[ ");
		for (p = (&myhead->v)->next; p != (&myhead->v); p = p->next) {
			struct myLongList *entry = container_of(p, struct myLongList, v);
			printf("%d ",entry->k);
			list_size++;
		}
		printf("]\n");
		printf("List size: %zu\n",list_size);
		return 0;
	}
	else if (!strcmp(argv[2],"LISTHEAD")) {
		struct list_head* lhead = (struct list_head*)flatten.get_seq_root(0);
		struct list_head *p;
		size_t list_size = 0;
		printf("[ ");
		for (p = lhead->next; p != lhead; p = p->next) {
			struct myLongHeadList *entry = container_of(p, struct myLongHeadList, v);
			printf("%d ",entry->k);
			list_size++;
		}
		printf("]\n");
		printf("List size: %zu\n",list_size);
		return 0;
	}
	else if (!strcmp(argv[2],"HLIST")) {
		struct hlist_head* harr = (struct hlist_head*)flatten.get_seq_root(0);
		struct hlist_node *p;
		for (int i=0; i<5; ++i) {
			unsigned long list_size = 0;
			printf("h%d: [ ",i);
			for (p = (&harr[i])->first; p ; p = p->next) {
				struct myLongHList *entry = container_of(p, struct myLongHList, r);
				printf("%d ",entry->k);
				list_size++;
			}
			printf("]: size %lu\n",list_size);
		}
		return 0;
	}
	else if (!strcmp(argv[2],"HNULLSLIST")) {
		struct hlist_nulls_head* hnarr = (struct hlist_nulls_head*)flatten.get_seq_root(0);
		struct hlist_nulls_node *p;
		for (int i=0; i<5; ++i) {
			unsigned long list_size = 0;
			printf("hn%d: [ ",i);
			struct myLongHnullsList *entry;
			for (p = (&hnarr[i])->first;
			     (!is_a_nulls(p)) &&
				({ entry = container_of(p, typeof(*entry), n); 1;});
			     p = p->next) {
				printf("%d ",entry->k);
				list_size++;
			}
			printf("]: size %lu\n",list_size);
		}
		return 0;
	}
	else if (!strcmp(argv[2],"LLIST")) {
		struct llist_head* lhead = (struct llist_head*)flatten.get_seq_root(0);
		struct llist_node *p;
		size_t list_size = 0;
		printf("[ ");
		for ((p) = (lhead->first); p; (p) = (p)->next) {
			struct myLongLList *entry = container_of(p, struct myLongLList, l);
			list_size++;
			printf("%d ",entry->k);
		}
		printf("]: size %lu\n",list_size);
		return 0;
	}
	else if (!strcmp(argv[2],"RBNODE")) {
		struct rb_root* iroot = (struct rb_root*)flatten.get_seq_root(0);
		struct rb_root* sroot = (struct rb_root*)flatten.get_seq_root(1);
		printf("strset size: %lu\n",strset_count(sroot));
		struct rb_node * sf = rb_first(sroot);
		struct myTreeNode *sfentry = container_of(sf, struct myTreeNode, snode);
		printf("%s\n",sfentry->s);
		struct rb_node * sl = rb_last(sroot);
		struct myTreeNode *slentry = container_of(sl, struct myTreeNode, snode);
		printf("%s\n",slentry->s);
		printf("intset size: %lu\n",intset_count(iroot));
		struct rb_node * intf = rb_first(iroot);
		struct myTreeNode *ifentry = container_of(intf, struct myTreeNode, inode);
		printf("%d\n",ifentry->i);
		struct rb_node * intl = rb_last(iroot);
		struct myTreeNode *ilentry = container_of(intl, struct myTreeNode, inode);
		printf("%d\n",ilentry->i);
		return 0;
	}

	flatten.unload();
	fclose(in);

	printf("ERROR: Unknown test name %s\n", argv[2]);
    return 1;
}
