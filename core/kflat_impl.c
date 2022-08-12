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


/* Nasty include, but we need some of the macros that for whatever
 *  reasons are stored in header files located outside of include/ dir */
#include "../../mm/slab.h"


#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)
INTERVAL_TREE_DEFINE(struct flat_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST,static,interval_tree)

/*******************************************************
 * BINARY STREAM
 *  List based implementation of expandable vector 
 ******************************************************/
static struct blstream* create_binary_stream_element(struct kflat* kflat, size_t size) {
	struct blstream* n;
	void* m;
	n = kflat_zalloc(kflat,sizeof(struct blstream),1);
	if (n==0) return 0;
	m = kflat_zalloc(kflat,size,1);
	if (m==0) {
		kflat_free(n);
		return 0;
	}
	n->data = m;
	n->size = size;
	return n;
}

struct blstream* binary_stream_append(struct kflat* kflat, const void* data, size_t size) {
	struct blstream* v = create_binary_stream_element(kflat,size);
	if (v==0) return 0;
	memcpy(v->data,data,size);
    if (!kflat->FLCTRL.bhead) {
    	kflat->FLCTRL.bhead = v;
    	kflat->FLCTRL.btail = v;
    }
    else {
        v->prev = kflat->FLCTRL.btail;
        kflat->FLCTRL.btail->next = v;
        kflat->FLCTRL.btail = kflat->FLCTRL.btail->next;
    }
    return v;
}
EXPORT_SYMBOL_GPL(binary_stream_append);


struct blstream* binary_stream_append_reserve(struct kflat* kflat, size_t size) {
	struct blstream* v = kflat_zalloc(kflat,sizeof(struct blstream),1);
	if (v==0) return 0;
	v->data = 0;
	v->size = size;
	if (!kflat->FLCTRL.bhead) {
		kflat->FLCTRL.bhead = v;
		kflat->FLCTRL.btail = v;
    }
    else {
        v->prev = kflat->FLCTRL.btail;
        kflat->FLCTRL.btail->next = v;
        kflat->FLCTRL.btail = kflat->FLCTRL.btail->next;
    }
    return v;
}

struct blstream* binary_stream_update(struct kflat* kflat, const void* data, size_t size, struct blstream* where) {
	void* m = kflat_zalloc(kflat,size,1);
	if (m==0) return 0;
	where->data = m;
	memcpy(where->data,data,size);
	return where;
}


struct blstream* binary_stream_insert_front(struct kflat* kflat, const void* data, size_t size, struct blstream* where) {
	struct blstream* v = create_binary_stream_element(kflat,size);
	if (v==0) return 0;
	memcpy(v->data,data,size);
	v->next = where;
	v->prev = where->prev;
	if (where->prev) {
		where->prev->next = v;
	}
	else {
		kflat->FLCTRL.bhead = v;
	}
	where->prev = v;
	return v;
}
EXPORT_SYMBOL_GPL(binary_stream_insert_front);

struct blstream* binary_stream_insert_front_reserve(struct kflat* kflat, size_t size, struct blstream* where) {
	struct blstream* v = kflat_zalloc(kflat,sizeof(struct blstream),1);
	if (v==0) return 0;
	v->data = 0;
	v->size = size;
	v->next = where;
	v->prev = where->prev;
	if (where->prev) {
		where->prev->next = v;
	}
	else {
		kflat->FLCTRL.bhead = v;
	}
	where->prev = v;
	return v;
}

struct blstream* binary_stream_insert_back(struct kflat* kflat, const void* data, size_t size, struct blstream* where) {
	struct blstream* v = create_binary_stream_element(kflat,size);
	if (v==0) return 0;
	memcpy(v->data,data,size);
	v->next = where->next;
	v->prev = where;
	if (where->next) {
		where->next->prev = v;
	}
	else {
		kflat->FLCTRL.btail = v;
	}
	where->next = v;
	return v;
}
EXPORT_SYMBOL_GPL(binary_stream_insert_back);

struct blstream* binary_stream_insert_back_reserve(struct kflat* kflat, size_t size, struct blstream* where) {
	struct blstream* v = kflat_zalloc(kflat,sizeof(struct blstream),1);
	if (v==0) return 0;
	v->data = 0;
	v->size = size;
	v->next = where->next;
	v->prev = where;
	if (where->next) {
		where->next->prev = v;
	}
	else {
		kflat->FLCTRL.btail = v;
	}
	where->next = v;
	return v;
}

int binary_stream_calculate_index(struct kflat* kflat) {
	struct blstream* p = kflat->FLCTRL.bhead;
	size_t index=0;
    while(p) {
    	struct blstream* cp = p;
    	size_t align=0;
    	p = p->next;
    	if (cp->alignment) {
    		struct blstream* v;
    		unsigned char* padding = kflat_zalloc(kflat,cp->alignment,1);
    		if (!padding) {
    			return ENOMEM;
    		}
    		if (index==0) {
    			align=cp->alignment;
    		}
    		else if (index%cp->alignment) {
    			align=cp->alignment-(index%cp->alignment);
    		}
    		v = binary_stream_insert_front(kflat,padding,align,cp);
    		if (v==0) return ENOMEM;
    		kflat_free(padding);
    		v->index = index;
    		index+=v->size;
    	}

    	cp->index = index;
    	index+=cp->size;
    }
    return 0;
}

void binary_stream_destroy(struct kflat* kflat) {
	kflat->FLCTRL.btail = kflat->FLCTRL.bhead;
    while(kflat->FLCTRL.btail) {
    	struct blstream* p = kflat->FLCTRL.btail;
    	kflat->FLCTRL.btail = kflat->FLCTRL.btail->next;
    	kflat_free(p->data);
    	kflat_free(p);
    }
}

static void binary_stream_element_print(struct blstream* p) {
	flat_infos("(%zu)(%zu)[%zu]{%lx}[...]\n",p->index,p->alignment,p->size,(unsigned long)p);
}

void binary_stream_element_print_data(struct blstream* p) {
	size_t i;
	flat_infos("(%zu)(%zu)[%zu]{%lx}[ ",p->index,p->alignment,p->size,(unsigned long)p);
	for (i=0; i<p->size; ++i) {
		flat_infos("%02x ",((unsigned char*)(p->data))[i]);
	}
	flat_infos("]\n");
}

static int binary_stream_element_write(struct kflat* kflat, struct blstream* p, size_t* wcounter_p) {

	FLATTEN_WRITE_ONCE((unsigned char*)(p->data),p->size,wcounter_p);
	return 0;
}

void binary_stream_print(struct kflat* kflat) {

	struct blstream* cp = kflat->FLCTRL.bhead;
	size_t total_size = 0;
    while(cp) {
    	struct blstream* p = cp;
    	cp = cp->next;
    	binary_stream_element_print(p);
    	total_size+=p->size;
    }
    flat_infos("@ Total size: %zu\n",total_size);
}

size_t binary_stream_write(struct kflat* kflat, size_t* wcounter_p) {
	int err;
	struct blstream* cp = kflat->FLCTRL.bhead;
    while(cp) {
    	struct blstream* p = cp;
    	cp = cp->next;
    	if ((err = binary_stream_element_write(kflat,p,wcounter_p))!=0) {
    		return err;
    	}
    }
    return 0;
}

size_t binary_stream_size(struct kflat* kflat) {

	struct blstream* cp = kflat->FLCTRL.bhead;
	size_t total_size = 0;
    while(cp) {
    	struct blstream* p = cp;
    	cp = cp->next;
    	total_size+=p->size;
    }
    return total_size;
}

void binary_stream_update_pointers(struct kflat* kflat) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	int count=0;
	while(p) {
    	struct fixup_set_node* node = (struct fixup_set_node*)p;
    	if ((node->ptr)&&(!(((unsigned long)node->ptr)&1))) {
			void* newptr = (unsigned char*)node->ptr->node->storage->index+node->ptr->offset;
			DBGS("@ ptr update at ((%lx)%lx:%zu) : %lx => %lx\n",(unsigned long)node->inode,(unsigned long)node->inode->start,node->offset,
					(unsigned long)newptr,(unsigned long)(((unsigned char*)node->inode->storage->data)+node->offset));
			memcpy(&((unsigned char*)node->inode->storage->data)[node->offset],&newptr,sizeof(void*));
    	}
    	p = rb_next(p);
    	count++;
    }
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

int bqueue_empty(struct bqueue* q) {

    return q->size == 0;
}
EXPORT_SYMBOL_GPL(bqueue_empty);

size_t bqueue_size(struct bqueue* q) {

    return q->size;
}
EXPORT_SYMBOL_GPL(bqueue_size);


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
    return 0;
}
EXPORT_SYMBOL_GPL(bqueue_push_back);

int bqueue_pop_front(struct bqueue* q, void* m, size_t s) {

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

    return 0;
}
EXPORT_SYMBOL_GPL(bqueue_pop_front);

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
EXPORT_SYMBOL_GPL(fixup_set_insert);

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
EXPORT_SYMBOL_GPL(fixup_set_insert_fptr);

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

void fixup_set_print(struct kflat* kflat) {
	struct rb_node * p = rb_first(&kflat->FLCTRL.fixup_set_root.rb_root);
	flat_infos("[\n");
	while(p) {
    	struct fixup_set_node* node = (struct fixup_set_node*)p;
    	if (node->ptr) {
			if (((unsigned long)node->ptr)&1) {
				uintptr_t newptr = ((unsigned long)node->ptr)&(~1);
				uintptr_t origptr = node->inode->storage->index+node->offset;
				flat_infos(" %zu: (%lx:%zu)->(F) | %zu <- %zu\n",
					node->inode->storage->index,
					(unsigned long)node->inode,node->offset,
					origptr,newptr);
			}
			else {
				uintptr_t newptr = node->ptr->node->storage->index+node->ptr->offset;
				uintptr_t origptr = node->inode->storage->index+node->offset;
				flat_infos(" %zu: (%lx:%zu)->(%lx:%zu) | %zu <- %zu\n",
						node->inode->storage->index,
						(unsigned long)node->inode,node->offset,
						(unsigned long)node->ptr->node,node->ptr->offset,
						origptr,newptr);
			}
    	}
    	else if (node->inode) {
    		/* Reserved node but never filled */
    		uintptr_t origptr = node->inode->storage->index+node->offset;
    		flat_infos(" %zu: (%lx:%zu)-> 0 | %zu\n",
					node->inode->storage->index,
					(unsigned long)node->inode,node->offset,
					origptr);
    	}
    	else {
    		/* Reserved for dummy pointer */
    		flat_infos(" (%lx)-> 0 | \n",(unsigned long)node->offset);
    	}
    	p = rb_next(p);
    }
	flat_infos("]\n");
}

int fixup_set_write(struct kflat* kflat, size_t* wcounter_p) {
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

int fixup_set_fptr_write(struct kflat* kflat, size_t* wcounter_p) {
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

size_t mem_fragment_index_count(struct kflat* kflat) {

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

int mem_fragment_index_write(struct kflat* kflat, size_t* wcounter_p) {

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

int mem_fragment_index_debug_print(struct kflat* kflat) {

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
				flat_infos("MEM: %08zu [%zu]\n",index,nindex-index);
				index = nindex;
			}
			else {
				flat_infos("MEM: %08zu [%zu]\n",index,fragment_size);
			}
			fragment_size = 0;
			mcount++;
		}
	};

	return 0;
}

size_t fixup_set_count(struct kflat* kflat) {
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

size_t fixup_set_fptr_count(struct kflat* kflat) {
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

void fixup_set_destroy(struct kflat* kflat) {
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

size_t root_addr_count(struct kflat* kflat) {
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

struct root_addr_set_node* root_addr_set_search(struct kflat* kflat, const char* name) {

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
EXPORT_SYMBOL_GPL(root_addr_set_search);

int root_addr_set_insert(struct kflat* kflat, const char* name, uintptr_t v) {

	struct root_addr_set_node* data = libflat_zalloc(1,sizeof(struct root_addr_set_node));
	struct rb_node **new, *parent = 0;
	data->name = libflat_zalloc(1,strlen(name)+1);
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
			libflat_free((void*)data->name);
		    libflat_free(data);
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &kflat->root_addr_set);

	return 1;
}
EXPORT_SYMBOL_GPL(root_addr_set_insert);

int root_addr_set_delete(struct kflat* kflat, const char* name) {

	struct root_addr_set_node* node = root_addr_set_search(kflat,name);
	if (node) {
		rb_erase(&node->node, &kflat->root_addr_set);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(root_addr_set_delete);

void root_addr_set_destroy(struct kflat* kflat) {

	struct rb_root* root = &kflat->root_addr_set;
	struct rb_node * p = rb_first(root);
    while(p) {
        struct root_addr_set_node* data = (struct root_addr_set_node*)p;
        rb_erase(p, root);
        p = rb_next(p);
        libflat_free((void*)data->name);
        libflat_free(data);
    }
}
EXPORT_SYMBOL_GPL(root_addr_set_destroy);

size_t root_addr_set_count(struct kflat* kflat) {

	struct rb_root* root = &kflat->root_addr_set;
	struct rb_node * p = rb_first(root);
	size_t count = 0;
	while(p) {
		count++;
		p = rb_next(p);
	}
	return count;
}
EXPORT_SYMBOL_GPL(root_addr_set_count);

void interval_tree_print(struct rb_root *root) {
	struct rb_node * p = rb_first(root);
	size_t total_size=0;
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		flat_infos("(%lx)[%lx:%lx](%zu){%lx}\n",(unsigned long)node,(unsigned long)node->start,(unsigned long)node->last,
				node->last-node->start+1,(unsigned long)node->storage);
		total_size+=node->last-node->start+1;
		p = rb_next(p);
	};
	flat_infos("@ Total size: %zu\n",total_size);
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

struct flatten_pointer* flatten_plain_type(struct kflat* kflat, const void* _ptr, size_t _sz) {

	struct flat_node *node;
	struct flatten_pointer* r = 0;
	if (!_sz) {
		return 0;
	}
	node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)_ptr, (uintptr_t)_ptr+_sz-1);
	if (node) {
		uintptr_t p = (uintptr_t)_ptr;
		struct flat_node *prev;
		while(node) {
			if (node->start>p) {
				struct flat_node* nn;
				if (!node->storage) {
					flat_errs("flat_node missing storage");
					return 0;
				}
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);
				if (nn==0) return 0;
				nn->start = p;
				nn->last = node->start-1;
				nn->storage = binary_stream_insert_front(kflat,(void*)p,node->start-p,node->storage);
				if (!nn->storage) {
					kflat_free(nn);
					return 0;
				}
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);
				if (r==0) {
					r = make_flatten_pointer(kflat,nn,0);
					if (!r) {
						return 0;
					}
				}
			}
			else {
				if (r==0) {
					r = make_flatten_pointer(kflat,node,p-node->start);
					if (!r) {
						return 0;
					}
				}
			}
			p = node->last+1;
			prev = node;
			node = interval_tree_iter_next(node, (uintptr_t)_ptr, (uintptr_t)_ptr+_sz-1);
		}
		if ((uintptr_t)_ptr+_sz>p) {
			struct flat_node* nn;
			if (!prev->storage) {
				kflat_free(r);
				return 0;
			}
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);
			if (!nn) {
				kflat_free(r);
				return 0;
			}
			nn->start = p;
			nn->last = (uintptr_t)_ptr+_sz-1;
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+_sz-p,prev->storage);
			if (!nn->storage) {
				kflat_free(nn);
				kflat_free(r);
				return 0;
			}
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);
		}
		return r;
	}
	else {
		struct blstream* storage;
		struct rb_node* rb;
		struct rb_node* prev;
		node = kflat_zalloc(kflat,sizeof(struct flat_node),1);
		if (!node) {
			return 0;
		}
		node->start = (uintptr_t)_ptr;
		node->last = (uintptr_t)_ptr + _sz-1;
		interval_tree_insert(node, &kflat->FLCTRL.imap_root);
		rb = &node->rb;
		prev = rb_prev(rb);
		if (prev) {
			storage = binary_stream_insert_back(kflat,_ptr,_sz,((struct flat_node*)prev)->storage);
		}
		else {
			struct rb_node* next = rb_next(rb);
			if (next) {
				storage = binary_stream_insert_front(kflat,_ptr,_sz,((struct flat_node*)next)->storage);
			}
			else {
				storage = binary_stream_append(kflat,_ptr,_sz);
			}
		}
		if (!storage) {
			return 0;
		}
		node->storage = storage;
		r = make_flatten_pointer(kflat,node,0);
		if (!r) {
			return 0;
		}
		return r;
	}
}
EXPORT_SYMBOL_GPL(flatten_plain_type);

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

void flatten_init(struct kflat* kflat) {
	memset(&kflat->FLCTRL,0,sizeof(struct FLCONTROL));
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
		flat_errs("Failed to allocate initial kflat memory pool of size %zu\n",KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE);
		kflat->errno = ENOMEM;
	}
	kflat->bqueue_msize = KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE;
	kflat->bqueue_mpool = kvzalloc(KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE,GFP_KERNEL);
	if (!kflat->bqueue_mpool) {
		flat_errs("Failed to allocate initial kflat bqueue memory pool of size %zu\n",KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE);
		kflat->errno = ENOMEM;
	}
#else
	kflat->mpool = 0;
	kflat->bqueue_mpool = 0;
#endif
}
EXPORT_SYMBOL_GPL(flatten_init);

void flatten_debug_info(struct kflat* kflat) {
	binary_stream_print(kflat);
    interval_tree_print(&kflat->FLCTRL.imap_root.rb_root);
    fixup_set_print(kflat);
    mem_fragment_index_debug_print(kflat);
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
EXPORT_SYMBOL_GPL(flatten_write);

volatile int vi;
int flatten_base_function_address(void) {
	return vi;
}
EXPORT_SYMBOL_GPL(flatten_base_function_address);

int flatten_base_global_address;
EXPORT_SYMBOL_GPL(flatten_base_global_address);

int flatten_write_internal(struct kflat* kflat, size_t* wcounter_p) {

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
    FLATTEN_WRITE_ONCE(&kflat->FLCTRL.HDR,sizeof(struct flatten_header),wcounter_p);
    p = kflat->FLCTRL.rhead;
	while(p) {
		size_t root_addr_offset;
		if (p->root_addr) {
			struct flat_node *node = PTRNODE(p->root_addr);
			if (!node) {
				/* Actually nothing has been flattened under this root address */
				p = p->next;
				continue;
			}
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
    return 0;
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
#if LINEAR_MEMORY_ALLOCATOR
    kvfree(kflat->mpool);
    kflat->mptrindex = 0;
    kflat->msize = 0;
    kvfree(kflat->bqueue_mpool);
    kflat->bqueue_mptrindex = 0;
    kflat->bqueue_msize = 0;
#endif
    root_addr_set_destroy(kflat);
    return 0;
}
EXPORT_SYMBOL_GPL(flatten_fini);

void flatten_set_option(struct kflat* kflat, int option) {
	kflat->FLCTRL.option |= option;
}
EXPORT_SYMBOL_GPL(flatten_set_option);

void flatten_clear_option(struct kflat* kflat, int option) {
	kflat->FLCTRL.option &= ~option;
}
EXPORT_SYMBOL_GPL(flatten_clear_option);


/*******************************************************
 * DYNAMIC OBJECTS RESOLUTION
 *******************************************************/
/*
 * Original implementation of kmem_cache_debug_flags can be found in mm/slab.h
 *  We need to redeclare it here, because __slub_debug_enabled is not exported
 *  to modules.
 */
static inline bool _kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t flags) {
#ifdef CONFIG_SLUB_DEBUG_ON
		return s->flags & flags;
#else
	return false;
#endif
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,16,0)
static bool _flatten_get_heap_obj(struct page* page, void* ptr, void** start, void** end) {
	off_t offset;
	size_t object_size;
	struct kmem_cache* cache;

	cache = page->slab_cache;
	ptr = kasan_reset_tag(ptr);
	if(ptr < page_address(page))
		return false;

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

	/*
	 * Finally, kindly ask allocator to provide us the size of 
	 *  an object
	 */
	object_size = slab_ksize(cache);
	if(object_size <= offset)
		return false;

	if(start)
		*start = ptr - offset;
	if(end)
		*end = ptr - offset + object_size;
	return true;
}

/*
 * flatten_get_object - check whether `ptr` points to the heap object and
 *		if so retrieve its start and end address
 *  For instance, if there's an array `char tab[32]` allocated on heap,
 *   invoking this func with &tab[10] will set `start` to &tab[0] and
 *   `end` to &tab[31].
 *  Returns false, when pointer does not point to valid heap location
 */
bool flatten_get_object(void* ptr, void** start, void** end) {
	struct page* page;

	if(!virt_addr_valid(ptr))
		return false;

	page = compound_head(kmap_to_page(ptr));
	if(page == NULL)
		return false;

	if(PageSlab(page)) {
		// This is heap (SLAB) object
		return _flatten_get_heap_obj(page, ptr, start, end);
	} else {
		// This is vmalloc area
		//  xxx TODO: Add support for this bastard
		return false;
	}
}
#else
static bool _flatten_get_heap_obj(struct slab* slab, void* ptr, 
									void** start, void** end) {
	off_t offset;
	size_t object_size;
	struct kmem_cache* cache;

	cache = slab->slab_cache;
	ptr = kasan_reset_tag(ptr);
	if(ptr < slab_address(slab))
		return false;

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

	/*
	 * Finally, kindly ask allocator to provide us the size of 
	 *  an object
	 */
	object_size = slab_ksize(cache);
	if(object_size <= offset)
		return false;

	if(start)
		*start = ptr - offset;
	if(end)
		*end = ptr - offset + object_size;
	return true;
}

bool flatten_get_object(void* ptr, void** start, void** end) {
	struct folio* folio;

	if(!virt_addr_valid(ptr))
		return false;

	folio = page_folio(kmap_to_page(ptr));
	if(folio == NULL)
		return false;

	if(folio_test_slab(folio))
		// This is heap (SLAB) object
		return _flatten_get_heap_obj(folio_slab(folio), ptr, start, end);
	else
		return false;
}
#endif

EXPORT_SYMBOL_GPL(flatten_get_object);

/*******************************************************
 * GLOBAL VARIABLES SUPPORT
 *******************************************************/
struct _flatten_module_priv {
	const char* name;
	uint64_t offset;
	uint64_t result;
};

static int _find_module_offset(const char* name, void* base_addr, void* priv) {
	struct module* module = NULL;
	void* globals_address;
	struct _flatten_module_priv* module_priv = (struct _flatten_module_priv*) priv;

	if(!strcmp(name, module_priv->name)) {
		// Access full content of module structure and lookup the start of globals
		module = container_of((void*) name, struct module, name);
		globals_address = module->core_layout.base + module->core_layout.ro_size + 0xc00;

		module_priv->result = module_priv->offset + (uint64_t) globals_address;
		return 1;
	}
	return 0;
}

/*
 * flatten_global_address - get VA of kernel global variable beloning to
 *		`module` and located at `offset` from base address
 *	`module` can be set to NULL or 'vmlinux', to access globals from kernel image
 */
#ifdef CONFIG_ANDROID_DEBUG_SYMBOLS 
#include <linux/android_debug_symbols.h>
void* flatten_global_address(const char* module, uint64_t offset) {
	struct _flatten_module_priv priv;

	if(module == NULL || !strcmp(module, "vmlinux")) {
		WARN_ONCE(1, "Accessing global variables from vmlinux is not currently supported");
		return NULL;
		//return KERNEL_START + offset;
	}
	
	priv.name = module;
	priv.offset = offset;
	priv.result = 0;
	android_debug_for_each_module(_find_module_offset, &priv);

	return (void*) priv.result;
}
#else
#warning "Support for globals variable is currently supported only on Android kernel"

void* flatten_global_address(const char* module, uint64_t offset) {
	(void)_find_module_offset;
	return NULL;
}
#endif
EXPORT_SYMBOL_GPL(flatten_global_address);


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
