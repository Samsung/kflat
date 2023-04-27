/**
 * @file kflat_impl.c
 * @author Samsung R&D Poland - Mobile Security Group
 * @brief Main implementation of kflat fast serialization
 * 
 */

#include "kflat.h"

#include <linux/interval_tree_generic.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/vmalloc.h>


#ifdef KFLAT_GET_OBJ_SUPPORT
/* Nasty include, but we need some of the macros that for whatever
 *  reasons are stored in header files located outside of include/ dir */
#include "../../mm/slab.h"
#endif /* KFLAT_GET_OBJ_SUPPORT */

#ifndef __nocfi
#define __nocfi
#endif


#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)
INTERVAL_TREE_DEFINE(struct flat_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST,static,interval_tree);

/*******************************************************
 * BINARY STREAM
 *  List based implementation of expandable vector 
 ******************************************************/
static struct blstream* create_binary_stream_element(struct kflat* kflat, size_t size) {
	struct blstream* n;
	void* m;
	n = kflat_zalloc(kflat, sizeof(struct blstream), 1);
	if (!n)
		return 0;
	m = kflat_zalloc(kflat, size, 1);
	if (!m) {
		kflat_free(n);
		return 0;
	}
	n->data = m;
	n->size = size;
	INIT_LIST_HEAD(&n->head);
	return n;
}

struct blstream* binary_stream_append(struct kflat* kflat, const void* data, size_t size) {
	struct blstream* v = create_binary_stream_element(kflat, size);
	if (!v)
		return 0;
	memcpy(v->data,data,size);
	list_add_tail(&v->head, &kflat->FLCTRL.head);
	return v;
}
EXPORT_SYMBOL_GPL(binary_stream_append);

static struct blstream* binary_stream_insert_front(struct kflat* kflat, const void* data, size_t size, struct blstream* where) {
	struct blstream* v = create_binary_stream_element(kflat, size);
	if (!v)
		return 0;
	memcpy(v->data, data, size);
	list_add_tail(&v->head, &where->head);
	return v;
}


static struct blstream* binary_stream_insert_back(struct kflat* kflat, const void* data, size_t size, struct blstream* where) {
	struct blstream* v = create_binary_stream_element(kflat, size);
	if (!v)
		return 0;
	memcpy(v->data,data,size);
	list_add(&v->head, &where->head);
	return v;
}


static int binary_stream_calculate_index(struct kflat* kflat) {
	struct blstream *ptr = NULL;
	size_t index = 0;

	list_for_each_entry(ptr, &kflat->FLCTRL.head, head) {
		size_t align = 0;
		if (ptr->alignment) {
			struct blstream* v;
			unsigned char* padding = kflat_zalloc(kflat, ptr->alignment, 1);
			if (!padding) {
				return ENOMEM;
			}
			if (index==0) {
				align = ptr->alignment;
			}
			else if (index % ptr->alignment) {
				align = ptr->alignment - (index % ptr->alignment);
			}
			v = binary_stream_insert_front(kflat, padding, align, ptr);
			if (!v)
				return ENOMEM;
			kflat_free(padding);
			v->index = index;
			index += v->size;
		}

		ptr->index = index;
		index += ptr->size;
	}

	return 0;
}

static void binary_stream_destroy(struct kflat* kflat) {
	struct blstream *entry = NULL;
	struct blstream *temp = NULL;

	list_for_each_entry_safe(entry, temp, &kflat->FLCTRL.head, head) {
		list_del(&entry->head);
		kflat_free(entry->data);
		kflat_free(entry);
	}
}

static int binary_stream_element_write(struct kflat* kflat, struct blstream* p, size_t* wcounter_p) {

	FLATTEN_WRITE_ONCE((unsigned char*)(p->data),p->size,wcounter_p);
	return 0;
}

static void binary_stream_print(struct kflat* kflat) {
	struct blstream* cp = NULL;
	size_t total_size = 0;

	kflat_dbg_printf("# Binary stream\n");
	list_for_each_entry(cp, &kflat->FLCTRL.head, head) {
		kflat_dbg_printf("(%zu)(%zu)[%zu]{%lx}[...]\n",cp->index,cp->alignment,cp->size,(unsigned long)cp);
		total_size+=cp->size;
	}

	kflat_dbg_printf("Total size: %zu\n\n",total_size);
}

static size_t binary_stream_write(struct kflat* kflat, size_t* wcounter_p) {
	int err;
	struct blstream* cp = NULL;
	list_for_each_entry(cp, &kflat->FLCTRL.head, head) {
		if ((err = binary_stream_element_write(kflat,cp,wcounter_p))!=0) {
			return err;
		}
	}
	return 0;
}

static size_t binary_stream_size(struct kflat* kflat) {
	struct blstream* cp = NULL;
	size_t total_size = 0;
	list_for_each_entry(cp, &kflat->FLCTRL.head, head) {
		total_size += cp->size;
	}
	return total_size;
}

static void binary_stream_update_pointers(struct kflat* kflat) {
	int count = 0;
	size_t size_to_cpy, __ptr_offset;
	struct blstream* __storage;
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);

	kflat_dbg_printf("# Pointer update\n");
	while(p) {
    	struct fixup_set_node* node = (struct fixup_set_node*)p;
    	if ((node->ptr)&&(!(((unsigned long)node->ptr)&1))) {
			void* newptr = (unsigned char*)node->ptr->node->storage->index+node->ptr->offset;
			DBGS("@ ptr update at ((%lx)%lx:%zu) : %lx => %lx\n",(unsigned long)node->inode,(unsigned long)node->inode->start,node->offset,
					(unsigned long)newptr,(unsigned long)(((unsigned char*)node->inode->storage->data)+node->offset));
			size_to_cpy = sizeof(void*);
			__storage = node->inode->storage;
			__ptr_offset = node->offset;
			while(size_to_cpy>0) {
				size_t cpy_size = (size_to_cpy>(__storage->size-__ptr_offset))?(__storage->size-__ptr_offset):(size_to_cpy);
				memcpy(&((unsigned char*)__storage->data)[__ptr_offset],(unsigned char*)&newptr+(sizeof(void*)-size_to_cpy),cpy_size);
				size_to_cpy-=cpy_size;
				if (size_to_cpy>0) {
					__storage = list_next_entry(__storage, head);
					__ptr_offset = 0;
				}
			}
			count++;
    	}
    	p = rb_next(p);
    }
    kflat_dbg_printf("Updated %d pointers\n\n",count);
}


/*******************************************************
 * B-QUEUE
 *  List based implementation of two-way queue
 ******************************************************/
int bqueue_init(struct kflat* kflat, struct bqueue* q, size_t block_size) {

    q->block_size = block_size;
    q->size = 0;
    q->front_block = kflat_bqueue_zalloc(kflat,block_size+sizeof(struct queue_block*),1);
    if (!q->front_block) {
    	return ENOMEM;
    }
    q->front_block->next = 0;
    q->back_block = q->front_block;
    q->front_index=0;
    q->back_index=0;
    return 0;
}
EXPORT_SYMBOL_GPL(bqueue_init);

void bqueue_destroy(struct bqueue* q) {

    struct queue_block* back = q->back_block;
    while(back) {
        struct queue_block* tmp = back;
        back = back->next;
        kflat_bqueue_free(tmp);
    }
}
EXPORT_SYMBOL_GPL(bqueue_destroy);

static int bqueue_empty(struct bqueue* q) { return q->size == 0; }

static size_t bqueue_size(struct bqueue* q) { return q->size; }

static unsigned long bqueue_el_count(struct bqueue* q) { return q->el_count; }

int bqueue_push_back(struct kflat* kflat, struct bqueue* q, const void* m, size_t s) {

    size_t copied = 0;
    while(s>0) {
        size_t avail_size = q->block_size-q->front_index;
        size_t copy_size = (s>avail_size)?(avail_size):(s);
        memcpy(q->front_block->data+q->front_index,m+copied,copy_size);
        copied+=copy_size;
        if (unlikely(s>=avail_size)) {
        	struct queue_block* new_block;
            s=s-avail_size;
            new_block = kflat_bqueue_zalloc(kflat,q->block_size+sizeof(struct queue_block*),1);
            if (!new_block) {
            	return ENOMEM;
            }
            new_block->next = 0;
            q->front_block->next = new_block;
            q->front_block = new_block;
        }
        else s=0;
        q->front_index = (q->front_index+copy_size)%q->block_size;
    }
    q->size+=copied;
    q->el_count++;
    return 0;
}
EXPORT_SYMBOL_GPL(bqueue_push_back);

static int bqueue_pop_front(struct bqueue* q, void* m, size_t s) {

	size_t copied = 0;

	if (q->size<s) {
    	flat_errs("bqueue underflow");
    	return EFAULT;
    }

    while(s>0) {
        size_t avail_size = q->block_size-q->back_index;
        size_t copy_size = (s>avail_size)?(avail_size):(s);
        memcpy(m+copied,q->back_block->data+q->back_index,copy_size);
        copied+=copy_size;
        if (s>=avail_size) {
        	struct queue_block* tmp;
        	s=s-avail_size;
            tmp = q->back_block;
            q->back_block = q->back_block->next;
            kflat_bqueue_free(tmp);
        }
        else s=0;
        q->back_index = (q->back_index+copy_size)%q->block_size;
    }
    q->size-=copied;
    q->el_count--;

    return 0;
}


/*******************************************************
 * FIXUP set
 ******************************************************/
#define ADDR_KEY(p)	((((p)->inode)?((p)->inode->start):0) + (p)->offset)

static struct fixup_set_node* create_fixup_set_node_element(struct kflat* kflat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {
	struct fixup_set_node* n = kflat_zalloc(kflat,sizeof(struct fixup_set_node),1);
	if (n==0) return 0;
	n->inode = node;
	n->offset = offset;
	n->ptr = ptr;
	return n;
}

struct fixup_set_node *fixup_set_search(struct kflat* kflat, uintptr_t v) {
	struct rb_node *node = kflat->FLCTRL.fixup_set_root.rb_root.rb_node;

	while (node) {
		struct fixup_set_node *data = container_of(node, struct fixup_set_node, node);

		if (v < ADDR_KEY(data)) {
			node = node->rb_left;
		}
		else if (v > ADDR_KEY(data)) {
			node = node->rb_right;
		}
		else {
			DBGS("fixup_set_search(%lx): (%lx:%zu,%lx)\n",v,(unsigned long)data->inode,data->offset,(unsigned long)data->ptr);
			return data;
		}
	}

	DBGS("fixup_set_search(%lx): 0\n",v);
	return 0;
}
EXPORT_SYMBOL_GPL(fixup_set_search);

int fixup_set_reserve_address(struct kflat* kflat, uintptr_t addr) {

	struct fixup_set_node *data;
	struct rb_node **new, *parent;
	struct fixup_set_node* inode;

	DBGS("fixup_set_reserve_address(%lx)\n",addr);

	inode = fixup_set_search(kflat,addr);

	if (inode) {
		return EEXIST;
	}

	new = &(kflat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	data = create_fixup_set_node_element(kflat,0,addr,0);
	if (!data) {
		return ENOMEM;
	}

	/* Figure out where to put new node */
	while (*new) {
		struct fixup_set_node *this = container_of(*new, struct fixup_set_node, node);

		parent = *new;
		if (data->offset < ADDR_KEY(this))
			new = &((*new)->rb_left);
		else if (data->offset > ADDR_KEY(this))
			new = &((*new)->rb_right);
		else
			return EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}
EXPORT_SYMBOL_GPL(fixup_set_reserve_address);

int fixup_set_reserve(struct kflat* kflat, struct flat_node* node, size_t offset) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new, *parent;

	DBGS("fixup_set_reserve(%lx,%zu)\n",(uintptr_t)node,offset);

	if (node==0) {
		return EINVAL;
	}

	inode = fixup_set_search(kflat,node->start+offset);

	if (inode) {
		return EEXIST;
	}

	data = create_fixup_set_node_element(kflat,node,offset,0);
	if (!data) {
		return ENOMEM;
	}

	new = &(kflat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new) {
		struct fixup_set_node *this = container_of(*new, struct fixup_set_node, node);

		parent = *new;
		if (ADDR_KEY(data) < ADDR_KEY(this))
			new = &((*new)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this))
			new = &((*new)->rb_right);
		else
			return EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}

int fixup_set_update(struct kflat* kflat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {

	struct fixup_set_node* inode;

	DBGS("fixup_set_update(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,(uintptr_t)ptr);

	if (node==0) {
		kflat_free(ptr);
		return EINVAL;
	}

	inode = fixup_set_search(kflat,node->start+offset);

	if (!inode) {
		return ENOKEY;
	}

	if (!inode->inode) {
		if ((node->start + offset)!=inode->offset) {
			flat_errs("node address not matching reserved offset");
			return EFAULT;
		}
		rb_erase(&inode->node, &kflat->FLCTRL.fixup_set_root.rb_root);
		return fixup_set_insert(kflat,node,offset,ptr);
	}

	inode->ptr = ptr;

	return 0;
}

int fixup_set_insert(struct kflat* kflat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new, *parent;

	DBGS("fixup_set_insert(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,(uintptr_t)ptr);

	if (!ptr) {
		DBGS("fixup_set_insert(...): ptr - EINVAL\n");
		return EINVAL;
	}

	if (node==0) {
		kflat_free(ptr);
		DBGS("fixup_set_insert(...): node - EINVAL\n");
		return EINVAL;
	}

	inode = fixup_set_search(kflat,node->start+offset);

	if (inode && inode->inode) {
		uintptr_t inode_ptr;
		if (((unsigned long)inode->ptr)&1) {
			inode_ptr = ((unsigned long)inode->ptr)&(~1);
		}
		else {
			inode_ptr = inode->ptr->node->start + inode->ptr->offset;
		}
		if (inode_ptr!=ptr->node->start+ptr->offset) {
			flat_errs("fixup_set_insert(...): multiple pointer mismatch for the same storage [%ld]: (%lx vs %lx)\n",
					((unsigned long)inode->ptr)&1,inode_ptr,ptr->node->start+ptr->offset);
			kflat_free(ptr);
			DBGS("fixup_set_insert(...): EFAULT\n");
			return EFAULT;
		}
		kflat_free(ptr);
		DBGS("fixup_set_insert(...): node - EEXIST\n");
		return EEXIST;
	}

	if (inode) {
		return fixup_set_update(kflat,node, offset, ptr);
	}

	data = create_fixup_set_node_element(kflat,node,offset,ptr);
	if (!data) {
		kflat_free(ptr);
		return ENOMEM;
	}
	new = &(kflat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new) {
		struct fixup_set_node *this = container_of(*new, struct fixup_set_node, node);

		parent = *new;
		if (ADDR_KEY(data) < ADDR_KEY(this))
			new = &((*new)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this))
			new = &((*new)->rb_right);
		else {
			DBGS("fixup_set_insert(...): EEXIST\n");
			return EEXIST;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->FLCTRL.fixup_set_root.rb_root);

	DBGS("fixup_set_insert(...): 0\n");

	return 0;
}

int fixup_set_insert_force_update(struct kflat* kflat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new, *parent;

	DBGS("fixup_set_insert_force_update(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,(uintptr_t)ptr);

	if (!ptr) {
		DBGS("fixup_set_insert_force_update(...): ptr - EINVAL\n");
		return EINVAL;
	}

	if (node==0) {
		kflat_free(ptr);
		DBGS("fixup_set_insert_force_update(...): node - EINVAL\n");
		return EINVAL;
	}

	inode = fixup_set_search(kflat,node->start+offset);

	if (inode && inode->inode) {
		uintptr_t inode_ptr;
		if (((unsigned long)inode->ptr)&1) {
			inode_ptr = ((unsigned long)inode->ptr)&(~1);
		}
		else {
			inode_ptr = inode->ptr->node->start + inode->ptr->offset;
		}
		if (inode_ptr!=ptr->node->start+ptr->offset) {
			flat_errs("fixup_set_insert_force_update(...): multiple pointer mismatch for the same storage [%ld]: (%lx vs %lx)\n",
					((unsigned long)inode->ptr)&1,inode_ptr,ptr->node->start+ptr->offset);
		}
		else {
			kflat_free(ptr);
			DBGS("fixup_set_insert_force_update(...): node - EEXIST\n");
			return EEXIST;
		}
	}

	if (inode && !inode->inode) {
		return fixup_set_update(kflat,node, offset, ptr);
	}

	data = create_fixup_set_node_element(kflat,node,offset,ptr);
	if (!data) {
		kflat_free(ptr);
		return ENOMEM;
	}
	new = &(kflat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new) {
		struct fixup_set_node *this = container_of(*new, struct fixup_set_node, node);

		parent = *new;
		if (ADDR_KEY(data) < ADDR_KEY(this))
			new = &((*new)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this))
			new = &((*new)->rb_right);
		else {
			kflat_free((void*)(((uintptr_t)data->ptr)&(~1)));
			data->ptr = ptr;
			return EAGAIN;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->FLCTRL.fixup_set_root.rb_root);

	DBGS("fixup_set_insert_force_update(...): 0\n");

	return 0;
}
EXPORT_SYMBOL_GPL(fixup_set_insert_force_update);

int fixup_set_insert_fptr(struct kflat* kflat, struct flat_node* node, size_t offset, unsigned long fptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new, *parent;

	DBGS("fixup_set_insert_fptr(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,fptr);

	if (!fptr) {
		return EINVAL;
	}

	if (node==0) {
		return EINVAL;
	}

	inode = fixup_set_search(kflat,node->start+offset);

	if (inode && inode->inode) {
		if ((((unsigned long)inode->ptr)&(~1))!=fptr) {
			flat_errs("fixup_set_insert_fptr(...): multiple pointer mismatch for the same storage: (%lx vs %lx)\n",
					(((unsigned long)inode->ptr)&(~1)),fptr);
			return EFAULT;
		}
		return EEXIST;
	}

	if (inode) {
		return fixup_set_update(kflat,node, offset, (struct flatten_pointer*)(fptr|1));
	}

	data = create_fixup_set_node_element(kflat,node,offset,(struct flatten_pointer*)(fptr|1));
	if (!data) {
		return ENOMEM;
	}
	new = &(kflat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new) {
		struct fixup_set_node *this = container_of(*new, struct fixup_set_node, node);

		parent = *new;
		if (ADDR_KEY(data) < ADDR_KEY(this))
			new = &((*new)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this))
			new = &((*new)->rb_right);
		else
			return EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}

int fixup_set_insert_fptr_force_update(struct kflat* kflat, struct flat_node* node, size_t offset, unsigned long fptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new, *parent;

	DBGS("fixup_set_insert_fptr_force_update(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,fptr);

	if (!fptr) {
		return EINVAL;
	}

	if (node==0) {
		return EINVAL;
	}

	inode = fixup_set_search(kflat,node->start+offset);

	if (inode && inode->inode) {
		if ((((unsigned long)inode->ptr)&(~1))!=fptr) {
			flat_errs("fixup_set_insert_fptr_force_update(...): multiple pointer mismatch for the same storage: (%lx vs %lx)\n",
					(((unsigned long)inode->ptr)&(~1)),fptr);
		}
		return EEXIST;
	}

	if (inode && !inode->inode) {
		return fixup_set_update(kflat,node, offset, (struct flatten_pointer*)(fptr|1));
	}

	data = create_fixup_set_node_element(kflat,node,offset,(struct flatten_pointer*)(fptr|1));
	if (!data) {
		return ENOMEM;
	}
	new = &(kflat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new) {
		struct fixup_set_node *this = container_of(*new, struct fixup_set_node, node);

		parent = *new;
		if (ADDR_KEY(data) < ADDR_KEY(this))
			new = &((*new)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this))
			new = &((*new)->rb_right);
		else {
			kflat_free((void*)(((uintptr_t)data->ptr)&(~1)));
			data->ptr = (struct flatten_pointer*)(fptr|1);
			return EAGAIN;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}
EXPORT_SYMBOL_GPL(fixup_set_insert_fptr_force_update);

static void fixup_set_print(struct kflat* kflat) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	kflat_dbg_printf("# Fixup set\n");
	kflat_dbg_printf("[\n");
	while(p) {
    	struct fixup_set_node* node = (struct fixup_set_node*)p;
    	if (node->ptr) {
			if (((unsigned long)node->ptr)&1) {
				uintptr_t newptr = ((unsigned long)node->ptr)&(~1);
				uintptr_t origptr = node->inode->storage->index+node->offset;
				kflat_dbg_printf(" %zu: (%lx:%zu)->(F) | %zu -> %zu\n",
					node->inode->storage->index,
					(unsigned long)node->inode,node->offset,
					origptr,newptr);
			}
			else {
				uintptr_t newptr = node->ptr->node->storage->index+node->ptr->offset;
				uintptr_t origptr = node->inode->storage->index+node->offset;
				kflat_dbg_printf(" %zu: (%lx:%zu)->(%lx:%zu) | %zu -> %zu\n",
						node->inode->storage->index,
						(unsigned long)node->inode,node->offset,
						(unsigned long)node->ptr->node,node->ptr->offset,
						origptr,newptr);
			}
    	}
    	else if (node->inode) {
    		/* Reserved node but never filled */
    		uintptr_t origptr = node->inode->storage->index+node->offset;
    		kflat_dbg_printf(" %zu: (%lx:%zu)-> 0 | %zu\n",
					node->inode->storage->index,
					(unsigned long)node->inode,node->offset,
					origptr);
    	}
    	else {
    		/* Reserved for dummy pointer */
    		kflat_dbg_printf(" (%lx)-> 0 | \n",(unsigned long)node->offset);
    	}
    	p = rb_next(p);
    }
	kflat_dbg_printf("]\n\n");
}

static int fixup_set_write(struct kflat* kflat, size_t* wcounter_p) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
    	struct fixup_set_node* node = (struct fixup_set_node*)p;
    	if ((node->ptr)&&(!(((unsigned long)node->ptr)&1))) {
			size_t origptr = node->inode->storage->index+node->offset;
			FLATTEN_WRITE_ONCE(&origptr,sizeof(size_t),wcounter_p);
    	}
    	p = rb_next(p);
    }
    return 0;
}

static int fixup_set_fptr_write(struct kflat* kflat, size_t* wcounter_p) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
    	struct fixup_set_node* node = (struct fixup_set_node*)p;
    	if ((((unsigned long)node->ptr)&1)) {
			size_t origptr = node->inode->storage->index+node->offset;
			FLATTEN_WRITE_ONCE(&origptr,sizeof(size_t),wcounter_p);
    	}
    	p = rb_next(p);
    }
    return 0;
}

static size_t fixup_fptr_info_count(struct kflat* kflat) {
	char func_symbol[128];
	size_t symbol_len, func_ptr, count = sizeof(size_t);

	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		if (((unsigned long)node->ptr) & 1) {
			func_ptr = ((unsigned long)node->ptr) & ~(1ULL);
			symbol_len = scnprintf(func_symbol, sizeof(func_symbol), "%ps", (void*) func_ptr);

			count += 2 * sizeof(size_t) + symbol_len;
		}
		p = rb_next(p);
	}
	return count;
}

static int fixup_set_fptr_info_write(struct kflat* kflat, size_t* wcounter_p) {
	char func_symbol[128];
	size_t symbol_len, func_ptr, orig_ptr;
	struct rb_node* p;

	FLATTEN_WRITE_ONCE(&kflat->FLCTRL.HDR.fptr_count, sizeof(size_t), wcounter_p);

	p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		if (((unsigned long)node->ptr) & 1) {
			func_ptr = ((unsigned long)node->ptr) & ~(1ULL);
			orig_ptr = node->inode->storage->index+node->offset;
			symbol_len = scnprintf(func_symbol, sizeof(func_symbol), "%ps", (void*) func_ptr);

			FLATTEN_WRITE_ONCE(&orig_ptr, sizeof(size_t), wcounter_p);
			FLATTEN_WRITE_ONCE(&symbol_len, sizeof(size_t), wcounter_p);
			FLATTEN_WRITE_ONCE(func_symbol, symbol_len, wcounter_p);
		}
		p = rb_next(p);
	}
	return 0;
}

static size_t mem_fragment_index_count(struct kflat* kflat) {

	struct rb_node * p = rb_first(&kflat->FLCTRL.imap_root.rb_root);
	size_t mcount = 0;
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		p = rb_next(p);
		if ((!p)||(node->last+1!=((struct flat_node*)p)->start)) {
			mcount++;
		}
	};

	return mcount;
}

static int mem_fragment_index_write(struct kflat* kflat, size_t* wcounter_p) {

	struct rb_node * p = rb_first(&kflat->FLCTRL.imap_root.rb_root);
	size_t index = 0;
	size_t fragment_size = 0;
	size_t mcount = 0;
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		fragment_size += node->storage->size;
		p = rb_next(p);
		if ((!p)||(node->last+1!=((struct flat_node*)p)->start)) {
			if (p) {
				size_t nindex = ((struct flat_node*)p)->storage->index;
				size_t wrnfo;
				FLATTEN_WRITE_ONCE(&index,sizeof(size_t),wcounter_p);
				wrnfo = nindex-index;
				FLATTEN_WRITE_ONCE(&wrnfo,sizeof(size_t),wcounter_p);
				index = nindex;
			}
			else {
				FLATTEN_WRITE_ONCE(&index,sizeof(size_t),wcounter_p);
				FLATTEN_WRITE_ONCE(&fragment_size,sizeof(size_t),wcounter_p);
			}
			fragment_size = 0;
			mcount++;
		}
	};

	return 0;
}

static int mem_fragment_index_debug_print(struct kflat* kflat) {

	struct rb_node * p = rb_first(&kflat->FLCTRL.imap_root.rb_root);
	size_t index = 0;
	size_t fragment_size = 0;
	size_t mcount = 0;
	kflat_dbg_printf("# Fragment list\n");
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		fragment_size += node->storage->size;
		p = rb_next(p);
		if ((!p)||(node->last+1!=((struct flat_node*)p)->start)) {
			if (p) {
				size_t nindex = ((struct flat_node*)p)->storage->index;
				kflat_dbg_printf("%08zu [%zu]\n",index,nindex-index);
				index = nindex;
			}
			else {
				kflat_dbg_printf("%08zu [%zu]\n",index,fragment_size);
			}
			fragment_size = 0;
			mcount++;
		}
	};

	return 0;
}

static size_t fixup_set_count(struct kflat* kflat) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	size_t count=0;
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		if ((node->ptr)&&(!(((unsigned long)node->ptr)&1))) {
			count++;
		}
    	p = rb_next(p);
    }
    return count;
}

static size_t fixup_set_fptr_count(struct kflat* kflat) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	size_t count=0;
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		if ((((unsigned long)node->ptr)&1)) {
			count++;
		}
    	p = rb_next(p);
    }
    return count;
}

static void fixup_set_destroy(struct kflat* kflat) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		rb_erase(p, &kflat->FLCTRL.fixup_set_root.rb_root);
		p = rb_next(p);
		if (!(((unsigned long)node->ptr)&1)) {
			kflat_free(node->ptr);
		}
		kflat_free(node);
	};
}

/*******************************************************
 * Root Addr set
 ******************************************************/
static struct root_addr_set_node* root_addr_set_search(struct kflat* kflat, const char* name) {

	struct rb_node *node = kflat->root_addr_set.rb_node;

	while (node) {
		struct root_addr_set_node* data = container_of(node, struct root_addr_set_node, node);

		if (strcmp(name,data->name)<0) {
			node = node->rb_left;
		}
		else if (strcmp(name,data->name)>0) {
			node = node->rb_right;
		}
		else
			return data;
	}

	return 0;
}

static int root_addr_set_insert(struct kflat* kflat, const char* name, uintptr_t v) {

	struct root_addr_set_node* data = kflat_zalloc(kflat, 1, sizeof(struct root_addr_set_node));
	struct rb_node **new, *parent = 0;
	data->name = kflat_zalloc(kflat, 1, strlen(name)+1);
	strcpy(data->name,name);
	data->root_addr = v;
	new = &(kflat->root_addr_set.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct root_addr_set_node* this = container_of(*new, struct root_addr_set_node, node);

		parent = *new;
		if (strcmp(data->name,this->name)<0)
			new = &((*new)->rb_left);
		else if (strcmp(data->name,this->name)>0)
			new = &((*new)->rb_right);
		else {
			kflat_free((void*)data->name);
		    kflat_free(data);
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->root_addr_set);

	return 1;
}

int root_addr_append(struct kflat* kflat, uintptr_t root_addr) {
    struct root_addrnode* v = kflat_zalloc(kflat,sizeof(struct root_addrnode),1);
    if (!v) {
    	return ENOMEM;
    }
    v->root_addr = root_addr;
    if (!kflat->FLCTRL.rhead) {
    	kflat->FLCTRL.rhead = v;
    	kflat->FLCTRL.rtail = v;
    }
    else {
    	kflat->FLCTRL.rtail->next = v;
    	kflat->FLCTRL.rtail = kflat->FLCTRL.rtail->next;
    }
    kflat->FLCTRL.root_addr_count++;
    return 0;
}
EXPORT_SYMBOL_GPL(root_addr_append);

int root_addr_append_extended(struct kflat* kflat, size_t root_addr, const char* name, size_t size) {

	struct root_addr_set_node* root_addr_node = root_addr_set_search(kflat, name);
	struct root_addrnode* v;

	if (root_addr_node) {
		return EEXIST;
	}

	v = kflat_zalloc(kflat,sizeof(struct root_addrnode),1);
    if (!v) {
    	return ENOMEM;
    }
    v->root_addr = root_addr;
    v->name = name;
    v->index = kflat->FLCTRL.root_addr_count;
    v->size = size;
    if (!kflat->FLCTRL.rhead) {
    	kflat->FLCTRL.rhead = v;
    	kflat->FLCTRL.rtail = v;
    }
    else {
    	kflat->FLCTRL.rtail->next = v;
    	kflat->FLCTRL.rtail = kflat->FLCTRL.rtail->next;
    }
    kflat->FLCTRL.root_addr_count++;
    root_addr_set_insert(kflat, name, root_addr);
    return 0;
}
EXPORT_SYMBOL_GPL(root_addr_append_extended);

static size_t root_addr_count(struct kflat* kflat) {
	struct root_addrnode* p = kflat->FLCTRL.rhead;
	size_t count = 0;
    while(p) {
    	count++;
    	p = p->next;
    }
    return count;
}

size_t root_addr_extended_count(struct kflat* kflat) {
	struct root_addrnode* p = kflat->FLCTRL.rhead;
	size_t count = 0;
    while(p) {
    	if (p->name) {
    		count++;
    	}
    	p = p->next;
    }
    return count;
}

size_t root_addr_extended_size(struct kflat* kflat) {
	struct root_addrnode* p = kflat->FLCTRL.rhead;
	size_t size = 0;
    while(p) {
    	if (p->name) {
    		size+=3*sizeof(size_t)+strlen(p->name);
    	}
    	p = p->next;
    }
    return size;
}

static void root_addr_set_destroy(struct kflat* kflat) {

	struct rb_root* root = &kflat->root_addr_set;
	struct rb_node * p = rb_first(root);
    while(p) {
        struct root_addr_set_node* data = (struct root_addr_set_node*)p;
        rb_erase(p, root);
        p = rb_next(p);
        kflat_free((void*)data->name);
        kflat_free(data);
    }
}

void interval_tree_print(struct rb_root *root) {

	struct rb_node * p;
	size_t total_size = 0;

	kflat_dbg_printf("# Interval tree\n");
	p = rb_first(root);
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		kflat_dbg_printf("(%lx)[%lx:%lx](%zu){%lx}\n",(unsigned long)node,(unsigned long)node->start,(unsigned long)node->last,
				node->last-node->start+1,(unsigned long)node->storage);
		total_size+=node->last-node->start+1;
		p = rb_next(p);
	};
	kflat_dbg_printf("Total size: %zu\n\n",total_size);
}

int interval_tree_destroy(struct kflat* kflat, struct rb_root *root) {
	struct interval_nodelist *h = 0, *i = 0;
	struct rb_node * p = rb_first(root);
	int rv = 0;
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		struct interval_nodelist* v;
		v = kflat_zalloc(kflat,sizeof(struct interval_nodelist),1);
		if (!v) {
			rv = ENOMEM;
			break;
		}
		interval_tree_remove(node,&kflat->FLCTRL.imap_root);
	    v->node = node;
	    if (!h) {
	        h = v;
	        i = v;
	    }
	    else {
	        i->next = v;
	        i = i->next;
	    }
		p = rb_next(p);
	};
	while(h) {
    	struct interval_nodelist* p = h;
    	h = h->next;
    	kflat_free(p->node);
    	kflat_free(p);
    }
	return rv;
}

int kflat_linear_memory_realloc(struct kflat* kflat, size_t nsize) {
	void* nmem = 0;
	if (nsize==kflat->msize) return 0;
	if (kflat->mptrindex>0) return EFAULT;
	if (kflat->bqueue_mptrindex>0) return EFAULT;
	nmem = kvzalloc(nsize,GFP_KERNEL);
	if (!nmem) {
		flat_errs("Failed to reallocate kflat memory pool for new size %zu\n",nsize);
		return ENOMEM;
	}
	kflat->msize = nsize;
	kvfree(kflat->mpool);
	kflat->mpool = nmem;
	nmem = kvzalloc(nsize,GFP_KERNEL);
	if (!nmem) {
		flat_errs("Failed to reallocate kflat bqueue memory pool for new size %zu\n",nsize);
		return ENOMEM;
	}
	kflat->bqueue_msize = nsize;
	kvfree(kflat->bqueue_mpool);
	kflat->bqueue_mpool = nmem;
	return 0;
}


/*******************************************************
 * FLATTEN engine
 ******************************************************/
void flatten_init(struct kflat* kflat) {
	memset(&kflat->FLCTRL,0,sizeof(struct FLCONTROL));
	INIT_LIST_HEAD(&kflat->FLCTRL.head);
	kflat->FLCTRL.debug_flag = kflat->debug_flag;
	kflat->FLCTRL.fixup_set_root = RB_ROOT_CACHED;
	kflat->FLCTRL.imap_root = RB_ROOT_CACHED;
	kflat->root_addr_set.rb_node = 0;
	kflat->mptrindex = 0;
	kflat->msize = 0;
	kflat->bqueue_mptrindex = 0;
	kflat->bqueue_msize = 0;
#if LINEAR_MEMORY_ALLOCATOR>0
	kflat->msize = KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE;
	kflat->mpool = kvzalloc(KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE,GFP_KERNEL);
	if (!kflat->mpool) {
		flat_errs("Failed to allocate initial kflat memory pool of size %lluu\n",KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE);
		kflat->errno = ENOMEM;
	}
	kflat->bqueue_msize = KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE;
	kflat->bqueue_mpool = kvzalloc(KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE,GFP_KERNEL);
	if (!kflat->bqueue_mpool) {
		flat_errs("Failed to allocate initial kflat bqueue memory pool of size %lluu\n",KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE);
		kflat->errno = ENOMEM;
	}
#else
	kflat->mpool = 0;
	kflat->bqueue_mpool = 0;
#endif

	kflat_dbg_buf_clear();
}

static void flatten_debug_info(struct kflat* kflat) {
	binary_stream_print(kflat);
    interval_tree_print(&kflat->FLCTRL.imap_root.rb_root);
    fixup_set_print(kflat);
    mem_fragment_index_debug_print(kflat);
}

volatile int vi;
int flatten_base_function_address(void) {
	return vi;
}

static int flatten_write_internal(struct kflat* kflat, size_t* wcounter_p) {

	int err = 0;
	struct root_addrnode* p;
	binary_stream_calculate_index(kflat);
    binary_stream_update_pointers(kflat);
    if (kflat->FLCTRL.debug_flag) {
    	flatten_debug_info(kflat);
    }
    kflat->FLCTRL.HDR.memory_size = binary_stream_size(kflat);
    kflat->FLCTRL.HDR.ptr_count = fixup_set_count(kflat);
    kflat->FLCTRL.HDR.fptr_count = fixup_set_fptr_count(kflat);
    kflat->FLCTRL.HDR.root_addr_count = root_addr_count(kflat);
    kflat->FLCTRL.HDR.root_addr_extended_count = root_addr_extended_count(kflat);
    kflat->FLCTRL.HDR.root_addr_extended_size = root_addr_extended_size(kflat);
    kflat->FLCTRL.HDR.this_addr = (uintptr_t)&flatten_base_function_address;
    kflat->FLCTRL.HDR.mcount = mem_fragment_index_count(kflat);
    kflat->FLCTRL.HDR.magic = FLATTEN_MAGIC;
    kflat->FLCTRL.HDR.fptrmapsz = fixup_fptr_info_count(kflat);
    FLATTEN_WRITE_ONCE(&kflat->FLCTRL.HDR,sizeof(struct flatten_header),wcounter_p);
    p = kflat->FLCTRL.rhead;
	while(p) {
		size_t root_addr_offset;
		if (p->root_addr) {
			struct flat_node *node = PTRNODE(p->root_addr);
			if (!node) {
				/* Actually nothing has been flattened under this root address */
				root_addr_offset = (size_t)-1;
			} else 
				root_addr_offset = node->storage->index + (p->root_addr-node->start);
		}
		else {
			root_addr_offset = (size_t)-1;
		}
		FLATTEN_WRITE_ONCE(&root_addr_offset,sizeof(size_t),wcounter_p);
		p = p->next;
	}
	p = kflat->FLCTRL.rhead;
	while(p) {
		if (p->name) {
			size_t name_size = strlen(p->name);
			FLATTEN_WRITE_ONCE(&name_size,sizeof(size_t),wcounter_p);
			FLATTEN_WRITE_ONCE(p->name,name_size,wcounter_p);
			FLATTEN_WRITE_ONCE(&p->index,sizeof(size_t),wcounter_p);
			FLATTEN_WRITE_ONCE(&p->size,sizeof(size_t),wcounter_p);
		}
		p = p->next;
	}
	if ((err = fixup_set_write(kflat,wcounter_p))!=0) {
		return err;
	}
	if ((err = fixup_set_fptr_write(kflat,wcounter_p))!=0) {
		return err;
	}
	if ((err = mem_fragment_index_write(kflat,wcounter_p))!=0) {
		return err;
	}
	if ((err = binary_stream_write(kflat,wcounter_p))!=0) {
		return err;
	}
	if ((err = fixup_set_fptr_info_write(kflat, wcounter_p)) != 0) {
		return err;
	}
    return 0;
}

int flatten_write(struct kflat* kflat) {

	size_t written = sizeof(size_t);
	int err;

	if ((err=flatten_write_internal(kflat,&written))==0) {
		flat_infos("OK. Flatten size: %lu, %lu pointers, %zu root pointers, %lu function pointers, %lu continuous memory fragments, "
				"%zu bytes written, memory used: %zu, memory avail: %zu\n",
			kflat->FLCTRL.HDR.memory_size,kflat->FLCTRL.HDR.ptr_count,kflat->FLCTRL.HDR.root_addr_count,kflat->FLCTRL.HDR.fptr_count,
			kflat->FLCTRL.HDR.mcount,written-sizeof(size_t),kflat->mptrindex,kflat->msize);
	}
	else {
		flat_errs("ERROR %d: Could not write flatten image. Flatten size: %lu, %lu pointers, %zu root pointers, %lu function pointers,"
				"%lu continuous memory fragments, %zu bytes written\n",kflat->errno,kflat->FLCTRL.HDR.memory_size,
				kflat->FLCTRL.HDR.ptr_count,kflat->FLCTRL.HDR.root_addr_count,kflat->FLCTRL.HDR.fptr_count,kflat->FLCTRL.HDR.mcount,written-sizeof(size_t));
	}

	*((size_t*)(kflat->area)) = written-sizeof(size_t);

	return err;
}

int flatten_fini(struct kflat* kflat) {
	binary_stream_destroy(kflat);
    fixup_set_destroy(kflat);
    kflat->FLCTRL.rtail = kflat->FLCTRL.rhead;
    while(kflat->FLCTRL.rtail) {
    	struct root_addrnode* p = kflat->FLCTRL.rtail;
    	kflat->FLCTRL.rtail = kflat->FLCTRL.rtail->next;
    	kflat_free(p);
    }
    interval_tree_destroy(kflat,&kflat->FLCTRL.imap_root.rb_root);
	root_addr_set_destroy(kflat);
#if LINEAR_MEMORY_ALLOCATOR
    kvfree(kflat->mpool);
    kflat->mptrindex = 0;
    kflat->msize = 0;
    kvfree(kflat->bqueue_mpool);
    kflat->bqueue_mptrindex = 0;
    kflat->bqueue_msize = 0;
#endif
    return 0;
}

struct flat_node* flatten_acquire_node_for_ptr(struct kflat* kflat, const void* _ptr, size_t size) {
	struct flat_node *node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr + size - 1);
	struct flat_node* head_node = 0;
	if (node) {
		uintptr_t p = (uintptr_t)_ptr;
    	struct flat_node *prev;
    	while(node) {
			if (node->start>p) {
				struct flat_node* nn;
				if (node->storage == 0) {
					kflat->errno = EFAULT;
					DBGS("%s(%lx): EFAULT (node(%lx)->storage==0)\n", __func__, (uintptr_t)_ptr, node);
					return 0;
				}
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);
				if (nn == 0) {
					kflat->errno = ENOMEM;
					DBGS("%s(%lx): ENOMEM\n",__func__, (uintptr_t)_ptr);
					return 0;
				}
				nn->start = p;
				nn->last = node->start-1;
				nn->storage = binary_stream_insert_front(kflat, (void*)p, node->start-p, node->storage);
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);
				if (head_node==0) {
					head_node = node;
				}
			}
			else {
				if (head_node==0) {
					head_node = node;
				}
			}
			p = node->last + 1;
			prev = node;
			node = interval_tree_iter_next(node, (uintptr_t)_ptr, (uintptr_t)_ptr+ size-1);
		}

		if ((uintptr_t)_ptr+ size > p) {
			struct flat_node* nn;
			if (prev->storage == NULL) {
				kflat->errno = EFAULT;
				DBGS("%s(%lx): EFAULT (prev(%llx)->storage==0)\n", __func__, (uintptr_t)_ptr, (uint64_t)prev);
				return 0;
			}
			nn = kflat_zalloc(kflat, sizeof(struct flat_node), 1);
			if (nn == NULL) {
				kflat->errno = ENOMEM;
				DBGS("%s(%lx): ENOMEM\n",__func__, (uintptr_t)_ptr);
				return 0;
			}
			nn->start = p;
			nn->last = (uintptr_t)_ptr + size - 1;
			nn->storage = binary_stream_insert_back(kflat, (void*)p, (uintptr_t)_ptr + size - p, prev->storage);
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);
		}
	} else {
    	struct blstream* storage;
    	struct rb_node* rb;
    	struct rb_node* prev;
    	node = kflat_zalloc(kflat, sizeof(struct flat_node), 1);
    	if (!node) {
	    	kflat->errno = ENOMEM;
    		DBGS("%s(%lx): ENOMEM\n", __func__, (uintptr_t)_ptr);
			return 0;
		}
		node->start = (uint64_t)_ptr;
        node->last = (uint64_t)_ptr +  size - 1;
        interval_tree_insert(node, &kflat->FLCTRL.imap_root);
        rb = &node->rb;
        prev = rb_prev(rb);
        if (prev) {
           	storage = binary_stream_insert_back(kflat,_ptr, size,((struct flat_node*)prev)->storage);
        } else {
			struct rb_node* next = rb_next(rb);
			if (next)
				storage = binary_stream_insert_front(kflat,_ptr, size,((struct flat_node*)next)->storage);
			else
				storage = binary_stream_append(kflat,_ptr, size);
		}
		if (!storage) {
			kflat->errno = ENOMEM;
			DBGS("%s(%lx): ENOMEM\n",__func__, (uintptr_t)_ptr);
			return 0;
		}
		node->storage = storage;
		if (head_node==0) {
			head_node = node;
		}
	}

	return head_node;
}
EXPORT_SYMBOL_GPL(flatten_acquire_node_for_ptr);

void flatten_generic(struct kflat* kflat, void* q, struct flatten_pointer* fptr, const void* p, size_t el_size, size_t count, uintptr_t custom_val, flatten_struct_t func_ptr, unsigned long shift) {
	int err;
	size_t i;
	struct flatten_pointer* __shifted;
	struct flat_node* __ptr_node;
	const void* _fp = (const void*)(p+shift);

	DBGS("flatten_generic: ADDR(%lx)\n", (uintptr_t) _fp);

	if(kflat->errno || !ADDR_RANGE_VALID(_fp, count * el_size)) {
		DBGS("flatten_generic: errno(%d), ADDR(0x%lx)", kflat->errno, (uintptr_t) _fp);
		return;
	}

	__shifted = flatten_plain_type(kflat, _fp, count * el_size);
	if(__shifted == NULL) {
		DBGS("flatten_generic: flatten_plain_type() == NULL");
		kflat->errno = EFAULT;
		return;
	}

	if (shift != 0) {
		__ptr_node = interval_tree_iter_first(
				&kflat->FLCTRL.imap_root, 
				(uintptr_t)_fp - shift,
				(uintptr_t)_fp - shift + 1);
		__shifted->node = __ptr_node;
		__shifted->offset = (uintptr_t)_fp - shift - __ptr_node->start;
	}

	err = fixup_set_insert_force_update(kflat, fptr->node, fptr->offset, __shifted);
	if (err && err != EINVAL && err != EEXIST && err != EAGAIN) {
		DBGS("flatten_generic: fixup_set_insert_force_update(): err(%d)", err);
		kflat->errno = err;
	} else if (err != EEXIST) {
		struct fixup_set_node* struct_inode;
		err = 0;

		for (i = 0; i < count; ++i) {
			const void* target = _fp + i * el_size;
			struct_inode = fixup_set_search(kflat, (uint64_t)target);
			if (!struct_inode) {
				struct flatten_job job = {0, };
				
				int err = fixup_set_reserve_address(kflat, (uint64_t)target);
				if(err)
					break;

				job.size = 1;
				job.custom_val = custom_val;
				job.index = i;
				job.ptr = (struct flatten_base*)target;
				job.fun = func_ptr;
				err = bqueue_push_back(kflat, q, &job, sizeof(struct flatten_job));
				if (err) 
					break;
			}
		}

		if (err && err != EEXIST)
			kflat->errno = err;
	}
}
EXPORT_SYMBOL_GPL(flatten_generic);

void flatten_aggregate_generic(struct kflat* kflat, void* q, const void* _ptr, 
		size_t el_size, size_t count, uintptr_t custom_val, ssize_t _off, ssize_t _shift,
		flatten_struct_t func_ptr, flatten_struct_embedded_extract_t pre_f, flatten_struct_embedded_convert_t post_f) {
	int err;
	struct flat_node* __ptr_node, *__node;
	void* _p;
	const void* _fp = 0;
	struct flatten_pointer* __shifted;
	struct fixup_set_node* __struct_inode;
	size_t _i;
	
	_p = (void*)OFFATTR(const void*,_off);
	if (pre_f)
		_p = pre_f(_p);
	if (_p)
		_fp = (const void*) ( _p+_shift);
	DBGTNFOMF(AGGREGATE_FLATTEN_GENERIC,"", el_size,f,"%lx:%zu",_fp,(size_t)_off,pre_f,post_f);

	if (kflat->errno || !ADDR_RANGE_VALID(_fp, el_size * count)) {
		DBGS("AGGREGATE_FLATTEN_GENERIC: errno(%d), ADDR(%lx)\n", kflat->errno, (uintptr_t)OFFATTR(void**,_off));
		return;
	}
	__node = interval_tree_iter_first(
			&kflat->FLCTRL.imap_root, 
			(uint64_t)_ptr + _off,
			(uint64_t)_ptr + _off + sizeof(void*) - 1);
	if (__node == NULL) {
		kflat->errno = EFAULT;
		return;
	}

	__shifted = flatten_plain_type(kflat, _fp, el_size * count);
	if(__shifted == NULL) {
		DBGS("AGGREGATE_FLATTEN_GENERIC:flatten_plain_type(): NULL");
		kflat->errno = EFAULT;
		return;
	}
	if (_shift != 0) {
		__ptr_node = interval_tree_iter_first(
				&kflat->FLCTRL.imap_root, 
				(uintptr_t)_fp - _shift,
				(uintptr_t)_fp - _shift + 1);
		__shifted->node = __ptr_node;
		__shifted->offset = (uintptr_t)_fp - _shift - __ptr_node->start;
	}

	if (post_f)
		__shifted = post_f(__shifted, OFFATTR(const struct flatten_base*, _off));

	err = fixup_set_insert_force_update(kflat, __node, (uint64_t)_ptr - __node->start + _off, __shifted);
	if (err && err != EEXIST && err != EAGAIN) {
		DBGS("AGGREGATE_FLATTEN_GENERIC:fixup_set_insert_force_update(): err(%d)\n",err);
		kflat->errno = err;
		return;
	}
	if(err == EEXIST) return;

	err = 0;
	for (_i = 0; _i < count; ++_i) {
		struct flat_node *__struct_node = interval_tree_iter_first(
				&kflat->FLCTRL.imap_root,
				(uint64_t)((void*)_fp + _i * el_size),
				(uint64_t)((void*)_fp + (_i + 1) * el_size - 1));
		if (__struct_node == NULL) {
			err = EFAULT;
			break;
		}

		__struct_inode = fixup_set_search(kflat,(uint64_t)((void*)_fp + _i * el_size));
		if (!__struct_inode) {
			struct flatten_job __job;
			int err = fixup_set_reserve_address(kflat,(uint64_t)((void*)_fp + _i * el_size));
			if (err) break;
			__job.node = 0;
			__job.offset = 0;
			__job.size = 1;
			__job.custom_val = (uintptr_t)custom_val;
			__job.index = _i;
			__job.ptr = (struct flatten_base*)((void*)_fp + _i * el_size);
			__job.fun = func_ptr;
			__job.fp = 0;
			__job.convert = 0;
			err = bqueue_push_back(kflat, q, &__job, sizeof(struct flatten_job));
			if (err) break;
		}
	}
	if (err && (err != EEXIST))
		kflat->errno = err;
}
EXPORT_SYMBOL_GPL(flatten_aggregate_generic);

struct flatten_pointer* flatten_plain_type(struct kflat* kflat, const void* _ptr, size_t _sz) {

	struct flat_node* node;
	struct flatten_pointer* flat_ptr;

	if (!_sz) {
		flat_errs("flatten_plain_type - zero size memory");
		return 0;
	}

	node = flatten_acquire_node_for_ptr(kflat, _ptr, _sz);

	if (!node) {
		flat_errs("failed to acquire flatten node");
		return 0;
	}

	flat_ptr = make_flatten_pointer(kflat,node,(uintptr_t)_ptr-node->start);
	if (!flat_ptr) {
		return 0;
	}

	return flat_ptr;
}
EXPORT_SYMBOL_GPL(flatten_plain_type);

void flatten_run_iter_harness(struct kflat* kflat, struct bqueue* bq) {
	size_t n = 0;
	ktime_t init_time, now;
	s64 total_time = 0;
	void* fp;
	struct flatten_job job;

	init_time = ktime_get();
	while((!kflat->errno) && (!bqueue_empty(bq))) {
		int err;

		DBGS("%s: queue iteration, size: %zu el_count: %ld\n",__func__, bqueue_size(bq),bqueue_el_count(bq));

		err = bqueue_pop_front(bq, &job, sizeof(struct flatten_job));
		if (err) {
			kflat->errno = err;
			break;
		}

		fp = job.fun(kflat, job.ptr, job.size, job.custom_val, job.index, bq);
		if (job.convert != NULL)
			fp = job.convert(fp, job.ptr);

		if (job.node != NULL) {
			err = fixup_set_insert_force_update(kflat, job.node, job.offset, fp);
			if (err && err != EINVAL && err != EEXIST && err != EAGAIN) {
				kflat->errno = err;
				break;
			}
		} else {
			if (!fp) 
				break;
			kflat_free(fp);
		}

		n++;
		now = ktime_get();
		DBGS("UNDER_ITER_HARNESS: recipes done: %lu, elapsed: %lld\n", n, now - init_time);

		if (now - init_time > KFLAT_PING_TIME_NS) {
			total_time += now - init_time;
			if (total_time > KFLAT_MAX_TIME_NS) {
				flat_errs("Timeout! Total time %lld [ms] exceeds maximum allowed %ld [ms]\n", 
							total_time / NSEC_PER_MSEC, KFLAT_MAX_TIME_NS / NSEC_PER_MSEC);
				kflat->errno = EAGAIN;
				break;
			}
			flat_infos("Still working! done %lu recipes in total time %lld [ms], memory used: %zu, memory avail: %zu \n",
				n, total_time / NSEC_PER_MSEC, kflat->mptrindex, kflat->msize);
			init_time = ktime_get();
		}
	}
	total_time += ktime_get() - init_time;
	flat_infos("Done working with %lu recipes in total time %lld [ms], memory used: %zu, memory avail: %zu \n",
		n, total_time / NSEC_PER_MSEC, kflat->mptrindex, kflat->msize);
	bqueue_destroy(bq);
	bqueue_release_memory(kflat);
}
EXPORT_SYMBOL_GPL(flatten_run_iter_harness);

/*******************************************************
 * GLOBAL VARIABLES SUPPORT
 *******************************************************/
unsigned long (*kflat_lookup_kallsyms_name)(const char* name);

__nocfi void* flatten_global_address_by_name(const char* name) {
	void* addr;

	if(kflat_lookup_kallsyms_name == NULL) {
		pr_warn("failed to obtain an address of global variable '%s' - kallsyms is not initialized", name);
		return NULL;
	}
	
	addr = (void*) kflat_lookup_kallsyms_name(name);
	
	if(addr == NULL)
		pr_warn("failed to obtain an address of global variable '%s'", name);
	return addr;
}
EXPORT_SYMBOL_GPL(flatten_global_address_by_name);


/*******************************************************
 * DYNAMIC OBJECTS RESOLUTION
 *******************************************************/
#ifdef KFLAT_GET_OBJ_SUPPORT
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 0, 0)
static void* kasan_reset_tag(void* addr) { 
	return addr;
}
#endif

bool check_kfence_address(void* ptr, void** start, void** end) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	// KFENCE support has been added in Linux kernel 5.12.0
	return false;
#else
	if(!is_kfence_address(ptr))
		return false;
	
	// KFENCE always allocates full kernel page
	*start = (void*) ((uint64_t)ptr & PAGE_MASK);
	*end = (void*)((uint64_t) *start + PAGE_SIZE);
	return true;
#endif
}

/*
 * Original implementation of kmem_cache_debug_flags can be 
 * 	found in mm/slab.h
 */
static inline bool _kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t flags) {
#ifdef CONFIG_SLUB_DEBUG_ON
		return s->flags & flags;
#else
	return false;
#endif
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,16,0)
/* Based on __check_heap_object@mm/slub.c */
static bool _flatten_get_heap_obj(struct page* page, void* ptr, void** start, void** end) {
	off_t offset;
	size_t object_size;
	struct kmem_cache* cache;

	cache = page->slab_cache;
	ptr = kasan_reset_tag(ptr);
	if(ptr < page_address(page))
		return false;

	if(check_kfence_address(ptr, start, end))
		return true;

	/*
	* Calculate the offset between ptr and the start of the object.
	* Each object on kmem_cache heap has constant size - use modulo
	* to determine offset of pointer
	*/
	offset = (ptr - page_address(page)) % cache->size;

	/*
	* When SLAB_RED_ZONE is enabled, the first few bytes of an
	*  object is in fact allocator private data.
	*/
	if(_kmem_cache_debug_flags(cache, SLAB_RED_ZONE))
		offset -= cache->red_left_pad;

	if((ptr - offset) < page_address(page))
		return false;

	object_size = slab_ksize(cache);
	if(object_size <= offset)
		return false;

	if(offset < cache->useroffset || cache->useroffset + cache->usersize < offset)
		return false;

	printk(KERN_INFO "KFLAT DEBUG: ptr(%llx) offset(%llx) cache->useroffset(%llx) cache->usersize(%llx)",
		ptr, offset, cache->useroffset, cache->usersize);
	printk(KERN_INFO "KFLAT DEBUG: object_size(%llx)", object_size);

	if(start)
		*start = ptr - offset + cache->useroffset;
	if(end)
		*end = ptr - offset + cache->useroffset + cache->usersize;
	return true;
}

static void* flatten_find_heap_object(void* ptr) {
	struct page* page;

	page = compound_head(kmap_to_page(ptr));
	if(page == NULL)
		return NULL;

	if(PageSlab(page))
		return page;
	return NULL;
}

#else
/* Based on __check_heap_object@mm/slub.c */
static bool _flatten_get_heap_obj(struct slab* slab, void* ptr, 
									void** start, void** end) {
	off_t offset;
	size_t object_size;
	struct kmem_cache* cache;

	cache = slab->slab_cache;
	ptr = kasan_reset_tag(ptr);
	if(ptr < slab_address(slab))
		return false;

	if(check_kfence_address(ptr, start, end))
		return true;

	/*
	 * Calculate the offset between ptr and the start of the object.
	 * Each object on kmem_cache heap has constant size - use modulo
	 * to determine offset of pointer
	 */
	offset = (ptr - slab_address(slab)) % cache->size;

	/*
	 * When SLAB_RED_ZONE is enabled, the first few bytes of an
	 *  object is in fact allocator private data.
	 */
	if(_kmem_cache_debug_flags(cache, SLAB_RED_ZONE))
		offset -= cache->red_left_pad;
	if((ptr - offset) < slab_address(slab))
		return false;

	object_size = slab_ksize(cache);
	if(object_size <= offset)
		return false;

	if(start)
		*start = ptr - offset + cache->useroffset;
	if(end)
		*end = ptr - offset + cache->useroffset + cache->usersize;
	return true;
}

static void* flatten_find_heap_object(void* ptr) {
	struct folio* folio;
	
	folio = virt_to_folio(ptr);

	if(folio == NULL)
		return NULL;

	if(folio_test_slab(folio))
		return folio_slab(folio);
	return NULL;
}

#endif

/*
 * flatten_get_object - check whether `ptr` points to the heap or vmalloc
 *		object and if so retrieve its start and end address
 *  For instance, if there's an array `char tab[32]` allocated on heap,
 *   invoking this func with &tab[10] will set `start` to &tab[0] and
 *   `end` to &tab[31].
 *  Returns false, when pointer does not point to valid heap memory location
 */
bool flatten_get_object(void* ptr, void** start, void** end) {
	void* obj;

	if(!is_vmalloc_addr(ptr) && virt_addr_valid(ptr)) {
		obj = flatten_find_heap_object(ptr);
		if(obj != NULL)
			return _flatten_get_heap_obj(obj, ptr, start, end);
	} 
	/* xxx this could be an extension of this function that supports 
	       vmalloc as well. However, the problem is that kernel allocates
		   stack with vmalloc, so we cannot distinguish between stack memory
		   and intentionally allocated additional data 
	else if (is_vmalloc_addr(ptr)) {
		size_t size = kdump_test_address(ptr, INT_MAX);
		if(size == 0)
			    return false;
		if(end)
			   *end = ptr + size;
		
		// Search for the start of memory
		if(start) {
			unsigned long long p = (unsigned long long) ptr;
			p &= PAGE_MASK;
			do {
				p -= PAGE_SIZE;
				size = kdump_test_address((void*)p, PAGE_SIZE);
			} while(size);
			*start = (void*)p + PAGE_SIZE;
		}
		return true;
	}*/
	
	return false;
}
#else /* KFLAT_GET_OBJ_SUPPORT */
bool flatten_get_object(void* ptr, void** start, void** end) {
	return false;
}
#endif /* KFLAT_GET_OBJ_SUPPORT */

EXPORT_SYMBOL_GPL(flatten_get_object);

/*******************************************************
 * KFLAT RECIPES REGISTRY
 *******************************************************/
LIST_HEAD(kflat_recipes_registry);
DEFINE_MUTEX(kflat_recipes_registry_lock);

int kflat_recipe_register(struct kflat_recipe* recipe) {
    int ret = 0;
    struct kflat_recipe* entry = NULL;

    if(!recipe || !recipe->owner || !recipe->symbol || !recipe->handler) {
        pr_err("cannot register incomplete recipe");
        return -EINVAL;
    }

    mutex_lock(&kflat_recipes_registry_lock);

    // Check for name duplicates
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(!strcasecmp(entry->symbol, recipe->symbol)) {
            pr_err("cannot register the same recipe twice");
            ret = -EBUSY;
            goto exit;
        }
    }
    list_add(&recipe->list, &kflat_recipes_registry);

exit:
    mutex_unlock(&kflat_recipes_registry_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(kflat_recipe_register);


int kflat_recipe_unregister(struct kflat_recipe* recipe) {
    int ret = -EINVAL;
    struct kflat_recipe* entry;
    
    mutex_lock(&kflat_recipes_registry_lock);
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(entry == recipe) {
            list_del(&entry->list);
            goto exit;
        }
    }

exit:
    mutex_unlock(&kflat_recipes_registry_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(kflat_recipe_unregister);


struct kflat_recipe* kflat_recipe_get(char* name) {
    struct kflat_recipe* entry, *ret = NULL;
    
    mutex_lock(&kflat_recipes_registry_lock);
    list_for_each_entry(entry, &kflat_recipes_registry, list) {
        if(!strcasecmp(entry->symbol, name)) {
            ret = entry;
            break;
        }
    }
    mutex_unlock(&kflat_recipes_registry_lock);

    if(ret)
        try_module_get(ret->owner); // TODO: Error handling
    return ret;
}

void kflat_recipe_put(struct kflat_recipe* recipe) {
    if(recipe == NULL)
        return;
    module_put(recipe->owner);
}
