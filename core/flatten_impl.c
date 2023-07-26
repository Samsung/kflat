/**
 * @file flatten_impl.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Main implementation of C fast serialization
 * 
 */

#include "flatten.h"
#include "flatten_impl.h"


/*******************************************************
 * LINEAR MEMORY ALLOCATOR
 *  Flatten engine performs a lot of memory allocations
 *  that are not freed till the end of serialization process
 *  To speed up, (K)Flat can use linear buffer as simple
 *  memory allocator.
 *  It's also useful in kernel, as it supports atomic context
 ******************************************************/
void* flat_zalloc(struct flat* flat, size_t size, size_t n) {
#if LINEAR_MEMORY_ALLOCATOR > 0
    void* ptr = NULL;
    static int diag_issued;
	size_t alloc_size = ALIGN(size * n, __alignof__(unsigned long long));

	if (unlikely(flat->mptrindex + alloc_size > flat->msize)) {
		if (!diag_issued) {
			flat_errs("Maximum capacity of flatten linear memory allocator (%zu) has been reached at %zu\n",
					flat->msize, flat->mptrindex);
			diag_issued = 1;
		}
		return NULL;
	}

	ptr = (unsigned char*)flat->mpool + flat->mptrindex;
	flat->mptrindex += alloc_size;
	return ptr;
#else
	return FLATTEN_BSP_ZALLOC(size * n);
#endif
}
EXPORT_FUNC(flat_zalloc);

void flat_free(void* p) {
#if LINEAR_MEMORY_ALLOCATOR > 0
#else
	FLATTEN_BSP_FREE(p);
#endif
}
EXPORT_FUNC(flat_free);

/*******************************************************
 * BINARY STREAM
 *  List based implementation of expandable vector 
 ******************************************************/
static struct blstream* create_binary_stream_element(struct flat* flat, size_t size) {
	struct blstream* n;
	void* m;
	n = (struct blstream*) flat_zalloc(flat, sizeof(struct blstream), 1);
	if (!n)
		return 0;
	m = flat_zalloc(flat, size, 1);
	if (!m) {
		flat_free(n);
		return 0;
	}
	n->data = m;
	n->size = size;
	INIT_LIST_HEAD(&n->head);
	return n;
}

struct blstream* binary_stream_append(struct flat* flat, const void* data, size_t size) {
	struct blstream* v = create_binary_stream_element(flat, size);
	if (!v)
		return 0;
	memcpy(v->data,data,size);
	list_add_tail(&v->head, &flat->FLCTRL.storage_head);
	return v;
}
EXPORT_FUNC(binary_stream_append);

static struct blstream* binary_stream_insert_front(struct flat* flat, const void* data, size_t size, struct blstream* where) {
	struct blstream* v = create_binary_stream_element(flat, size);
	if (!v)
		return 0;
	memcpy(v->data, data, size);
	list_add_tail(&v->head, &where->head);
	return v;
}


static struct blstream* binary_stream_insert_back(struct flat* flat, const void* data, size_t size, struct blstream* where) {
	struct blstream* v = create_binary_stream_element(flat, size);
	if (!v)
		return 0;
	memcpy(v->data,data,size);
	list_add(&v->head, &where->head);
	return v;
}


int binary_stream_calculate_index(struct flat* flat) {
	struct blstream *ptr = NULL, *v;
	size_t index = 0;
	unsigned char padding[128] = {0};

	list_for_each_entry(ptr, &flat->FLCTRL.storage_head, head) {
		size_t align = 0;
		if (ptr->alignment && index != 0) {
			if(ptr->alignment > 128) {
				flat_errs("Invalid ptr->alignment(%zu) in blstream node", ptr->alignment);
				return EINVAL;
			}

			align = -index & (ptr->alignment - 1);
			if (align != 0) {
				v = binary_stream_insert_front(flat, padding, align, ptr);
				if (!v)
					return ENOMEM;
				v->index = index;
				index += v->size;
			}
		}

		ptr->index = index;
		index += ptr->size;
	}

	return 0;
}

static void binary_stream_destroy(struct flat* flat) {
	struct blstream *entry = NULL;
	struct blstream *temp = NULL;

	list_for_each_entry_safe(entry, temp, &flat->FLCTRL.storage_head, head) {
		list_del(&entry->head);
		flat_free(entry->data);
		flat_free(entry);
	}
}

static int binary_stream_element_write(struct flat* flat, struct blstream* p, size_t* wcounter_p) {
	FLATTEN_WRITE_ONCE((unsigned char*)(p->data), p->size, wcounter_p);
	return 0;
}

static void binary_stream_print(struct flat* flat) {
	struct blstream* cp = NULL;
	size_t total_size = 0;

	FLATTEN_LOG_DEBUG("# Binary stream\n");
	list_for_each_entry(cp, &flat->FLCTRL.storage_head, head) {
		FLATTEN_LOG_DEBUG("(%zu)(%zu)[%zu]{%lx}[...]\n", cp->index, cp->alignment, cp->size, (unsigned long)cp);
		total_size+=cp->size;
	}

	FLATTEN_LOG_DEBUG("Total size: %zu\n\n",total_size);
}

static size_t binary_stream_write(struct flat* flat, size_t* wcounter_p) {
	int err;
	struct blstream* cp = NULL;
	list_for_each_entry(cp, &flat->FLCTRL.storage_head, head) {
		if ((err = binary_stream_element_write(flat, cp, wcounter_p))!=0) {
			return err;
		}
	}
	return 0;
}

static size_t binary_stream_size(struct flat* flat) {
	struct blstream* cp = NULL;
	size_t total_size = 0;
	list_for_each_entry(cp, &flat->FLCTRL.storage_head, head) {
		total_size += cp->size;
	}
	return total_size;
}

static void binary_stream_update_pointers(struct flat* flat) {
	int count = 0;
	size_t size_to_cpy, __ptr_offset;
	struct blstream* __storage;
	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);

	FLATTEN_LOG_DEBUG("# Pointer update\n");
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
    FLATTEN_LOG_DEBUG("Updated %d pointers\n\n",count);
}


/*******************************************************
 * B-QUEUE
 *  List based implementation of two-way queue
 ******************************************************/
int bqueue_init(struct flat* flat, struct bqueue* q, size_t block_size) {
	struct queue_block *new_block = NULL;

	memset(q, 0, sizeof(struct bqueue));

	new_block = (struct queue_block *) flat_zalloc(flat, block_size + sizeof(struct queue_block), 1);
	if (!new_block)
		return ENOMEM;

	q->block_size = block_size;
	INIT_LIST_HEAD(&q->head);
	list_add(&new_block->head, &q->head);
	return 0;
}
EXPORT_FUNC(bqueue_init);

void bqueue_destroy(struct bqueue* q) {
	struct queue_block *cur = NULL;
	struct queue_block *tmp = NULL;
	list_for_each_entry_safe(cur, tmp, &q->head, head) {
		list_del(&cur->head);
		flat_free(cur);
	}
}
EXPORT_FUNC(bqueue_destroy);

static int bqueue_empty(struct bqueue* q) { return q->size == 0; }

static size_t bqueue_size(struct bqueue* q) { return q->size; }

static unsigned long bqueue_el_count(struct bqueue* q) { return q->el_count; }

int bqueue_push_back(struct flat* flat, struct bqueue* q, const void* m, size_t s) {
	size_t copied = 0;
	struct queue_block *front = NULL;
	struct queue_block* new_block = NULL;

	if (list_empty(&q->head)) {
		new_block = (struct queue_block *) flat_zalloc(flat, q->block_size + sizeof(struct queue_block), 1);
		if (!new_block)
			return ENOMEM;

		list_add(&new_block->head, &q->head);
	}

	while (s > 0) {
		size_t avail_size = q->block_size - q->front_index;
		size_t copy_size = (s > avail_size) ? (avail_size) : (s);
		front = list_first_entry(&q->head, struct queue_block, head);
		memcpy(front->data + q->front_index, (char*)m + copied, copy_size);
		copied += copy_size;
		if (unlikely(s >= avail_size)) {
			s = s - avail_size;
			new_block = (struct queue_block*) flat_zalloc(flat, q->block_size + sizeof(struct queue_block), 1);
			if (!new_block)
				return ENOMEM;

			list_add(&new_block->head, &q->head);
		}
		else
			s = 0;
		q->front_index = (q->front_index + copy_size) % q->block_size;
	}
	q->size += copied;
	q->el_count++;
	return 0;
}
EXPORT_FUNC(bqueue_push_back);

int bqueue_pop_front(struct bqueue* q, void* m, size_t s) {
	size_t copied = 0;
	struct queue_block *back = NULL;

	if (q->size < s) {
		flat_errs("bqueue underflow");
		return EFAULT;
	}

	if (list_empty(&q->head))
		return ENOENT;

	while (s > 0) {
		size_t avail_size = q->block_size - q->back_index;
		size_t copy_size = (s > avail_size) ? (avail_size) : (s);
		back = list_last_entry(&q->head, struct queue_block, head);
		memcpy((char*)m + copied, back->data + q->back_index, copy_size);
		copied += copy_size;
		if (s >= avail_size) {
			s = s - avail_size;
			list_del(&back->head);
			flat_free(back);
		}
		else
			s = 0;
		q->back_index = (q->back_index + copy_size) % q->block_size;
	}
	q->size -= copied;
	q->el_count--;

	return 0;
}


/*******************************************************
 * FIXUP set
 ******************************************************/
#define ADDR_KEY(p)	((((p)->inode)?((p)->inode->start):0) + (p)->offset)

static struct fixup_set_node* create_fixup_set_node_element(struct flat* flat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {
	struct fixup_set_node* n = (struct fixup_set_node*) flat_zalloc(flat,sizeof(struct fixup_set_node),1);
	if (n==0) return 0;
	n->inode = node;
	n->offset = offset;
	n->ptr = ptr;
	return n;
}

struct fixup_set_node *fixup_set_search(struct flat* flat, uintptr_t v) {
	struct rb_node *node = flat->FLCTRL.fixup_set_root.rb_root.rb_node;

	while (node) {
		struct fixup_set_node *data = container_of(node, struct fixup_set_node, node);

		if (v < ADDR_KEY(data)) {
			node = node->rb_left;
		}
		else if (v > ADDR_KEY(data)) {
			node = node->rb_right;
		}
		else {
			DBGS(" fixup_set_search(%lx): (%lx:%zu,%lx)\n",v,(unsigned long)data->inode,data->offset,(unsigned long)data->ptr);
			return data;
		}
	}

	return 0;
}
EXPORT_FUNC(fixup_set_search);

int fixup_set_reserve_address(struct flat* flat, uintptr_t addr) {

	struct fixup_set_node *data;
	struct rb_node **new_node, *parent;
	struct fixup_set_node* inode;

	inode = fixup_set_search(flat,addr);

	if (inode) {
		return EEXIST;
	}

	new_node = &(flat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	data = create_fixup_set_node_element(flat,0,addr,0);
	if (!data) {
		return ENOMEM;
	}

	/* Figure out where to put new node */
	while (*new_node) {
		struct fixup_set_node *this_node = container_of(*new_node, struct fixup_set_node, node);

		parent = *new_node;
		if (data->offset < ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_left);
		else if (data->offset > ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_right);
		else
			return EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new_node);
	rb_insert_color(&data->node, &flat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}
EXPORT_FUNC(fixup_set_reserve_address);

int fixup_set_reserve(struct flat* flat, struct flat_node* node, size_t offset) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new_node, *parent;

	DBGS(" fixup_set_reserve(%lx,%zu)\n",(uintptr_t)node,offset);

	if (node==0) {
		return EINVAL;
	}

	inode = fixup_set_search(flat,node->start+offset);

	if (inode) {
		return EEXIST;
	}

	data = create_fixup_set_node_element(flat,node,offset,0);
	if (!data) {
		return ENOMEM;
	}

	new_node = &(flat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new_node) {
		struct fixup_set_node *this_node = container_of(*new_node, struct fixup_set_node, node);

		parent = *new_node;
		if (ADDR_KEY(data) < ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_right);
		else
			return EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new_node);
	rb_insert_color(&data->node, &flat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}

int fixup_set_update(struct flat* flat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {

	struct fixup_set_node* inode;

	DBGS(" fixup_set_update(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,(uintptr_t)ptr);

	if (node==0) {
		flat_free(ptr);
		return EINVAL;
	}

	inode = fixup_set_search(flat,node->start+offset);

	if (!inode) {
		return ENOKEY;
	}

	if (!inode->inode) {
		if ((node->start + offset)!=inode->offset) {
			flat_errs("node address not matching reserved offset");
			return EFAULT;
		}
		rb_erase(&inode->node, &flat->FLCTRL.fixup_set_root.rb_root);
		return fixup_set_insert(flat,node,offset,ptr);
	}

	inode->ptr = ptr;

	return 0;
}

int fixup_set_insert(struct flat* flat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new_node, *parent;

	DBGS(" fixup_set_insert(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,(uintptr_t)ptr);

	if (!ptr) {
		DBGS("fixup_set_insert(...): ptr - EINVAL\n");
		return EINVAL;
	}

	if (node==0) {
		flat_free(ptr);
		DBGS("fixup_set_insert(...): node - EINVAL\n");
		return EINVAL;
	}

	inode = fixup_set_search(flat,node->start+offset);

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
			flat_free(ptr);
			DBGS("fixup_set_insert(...): EFAULT\n");
			return EFAULT;
		}
		flat_free(ptr);
		DBGS("fixup_set_insert(...): node - EEXIST\n");
		return EEXIST;
	}

	if (inode) {
		return fixup_set_update(flat,node, offset, ptr);
	}

	data = create_fixup_set_node_element(flat,node,offset,ptr);
	if (!data) {
		flat_free(ptr);
		return ENOMEM;
	}
	new_node = &(flat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new_node) {
		struct fixup_set_node *this_node = container_of(*new_node, struct fixup_set_node, node);

		parent = *new_node;
		if (ADDR_KEY(data) < ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_right);
		else {
			DBGS("fixup_set_insert(...): EEXIST\n");
			return EEXIST;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new_node);
	rb_insert_color(&data->node, &flat->FLCTRL.fixup_set_root.rb_root);

	DBGS("fixup_set_insert(...): 0\n");

	return 0;
}

int fixup_set_insert_force_update(struct flat* flat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new_node, *parent;

	DBGS(" fixup_set_insert_force_update(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,(uintptr_t)ptr);

	if (!ptr) {
		DBGS("fixup_set_insert_force_update(...): ptr - EINVAL\n");
		return EINVAL;
	}

	if (node==0) {
		flat_free(ptr);
		DBGS("fixup_set_insert_force_update(...): node - EINVAL\n");
		return EINVAL;
	}

	inode = fixup_set_search(flat,node->start+offset);

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
			flat_free(ptr);
			DBGS("fixup_set_insert_force_update(...): node - EEXIST\n");
			return EEXIST;
		}
	}

	if (inode && !inode->inode) {
		return fixup_set_update(flat,node, offset, ptr);
	}

	data = create_fixup_set_node_element(flat,node,offset,ptr);
	if (!data) {
		flat_free(ptr);
		return ENOMEM;
	}
	new_node = &(flat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new_node) {
		struct fixup_set_node *this_node = container_of(*new_node, struct fixup_set_node, node);

		parent = *new_node;
		if (ADDR_KEY(data) < ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_right);
		else {
			flat_free((void*)(((uintptr_t)data->ptr)&(~1)));
			data->ptr = ptr;
			return EAGAIN;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new_node);
	rb_insert_color(&data->node, &flat->FLCTRL.fixup_set_root.rb_root);

	DBGS(" fixup_set_insert_force_update(...): 0\n");

	return 0;
}
EXPORT_FUNC(fixup_set_insert_force_update);

int fixup_set_insert_fptr(struct flat* flat, struct flat_node* node, size_t offset, unsigned long fptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new_node, *parent;

	DBGS(" fixup_set_insert_fptr(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,fptr);

	if (!fptr) {
		return EINVAL;
	}

	if (node==0) {
		return EINVAL;
	}

	inode = fixup_set_search(flat,node->start+offset);

	if (inode && inode->inode) {
		if ((((unsigned long)inode->ptr)&(~1))!=fptr) {
			flat_errs("fixup_set_insert_fptr(...): multiple pointer mismatch for the same storage: (%lx vs %lx)\n",
					(((unsigned long)inode->ptr)&(~1)),fptr);
			return EFAULT;
		}
		return EEXIST;
	}

	if (inode) {
		return fixup_set_update(flat,node, offset, (struct flatten_pointer*)(fptr|1));
	}

	data = create_fixup_set_node_element(flat,node,offset,(struct flatten_pointer*)(fptr|1));
	if (!data) {
		return ENOMEM;
	}
	new_node = &(flat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new_node) {
		struct fixup_set_node *this_node = container_of(*new_node, struct fixup_set_node, node);

		parent = *new_node;
		if (ADDR_KEY(data) < ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_right);
		else
			return EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new_node);
	rb_insert_color(&data->node, &flat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}

int fixup_set_insert_fptr_force_update(struct flat* flat, struct flat_node* node, size_t offset, unsigned long fptr) {

	struct fixup_set_node* inode;
	struct fixup_set_node *data;
	struct rb_node **new_node, *parent;

	DBGS(" fixup_set_insert_fptr_force_update(%lx[%lx:%zu],%zu,%lx)\n",(uintptr_t)node,
			(node)?(node->start):0,(node)?(node->last-node->start+1):0,
			offset,fptr);

	if (!fptr) {
		return EINVAL;
	}

	if (node==0) {
		return EINVAL;
	}

	inode = fixup_set_search(flat,node->start+offset);

	if (inode && inode->inode) {
		if ((((unsigned long)inode->ptr)&(~1))!=fptr) {
			flat_errs("fixup_set_insert_fptr_force_update(...): multiple pointer mismatch for the same storage: (%lx vs %lx)\n",
					(((unsigned long)inode->ptr)&(~1)),fptr);
		}
		return EEXIST;
	}

	if (inode && !inode->inode) {
		return fixup_set_update(flat,node, offset, (struct flatten_pointer*)(fptr|1));
	}

	data = create_fixup_set_node_element(flat,node,offset,(struct flatten_pointer*)(fptr|1));
	if (!data) {
		return ENOMEM;
	}
	new_node = &(flat->FLCTRL.fixup_set_root.rb_root.rb_node);
	parent = 0;

	/* Figure out where to put new node */
	while (*new_node) {
		struct fixup_set_node *this_node = container_of(*new_node, struct fixup_set_node, node);

		parent = *new_node;
		if (ADDR_KEY(data) < ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_left);
		else if (ADDR_KEY(data) > ADDR_KEY(this_node))
			new_node = &((*new_node)->rb_right);
		else {
			flat_free((void*)(((uintptr_t)data->ptr)&(~1)));
			data->ptr = (struct flatten_pointer*)(fptr|1);
			return EAGAIN;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new_node);
	rb_insert_color(&data->node, &flat->FLCTRL.fixup_set_root.rb_root);

	return 0;
}
EXPORT_FUNC(fixup_set_insert_fptr_force_update);

static void fixup_set_print(struct flat* flat) {
	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
	FLATTEN_LOG_DEBUG("# Fixup set\n");
	FLATTEN_LOG_DEBUG("[\n");
	while(p) {
    	struct fixup_set_node* node = (struct fixup_set_node*)p;
    	if (node->ptr) {
			if (((unsigned long)node->ptr)&1) {
				uintptr_t newptr = ((unsigned long)node->ptr)&(~1);
				uintptr_t origptr = node->inode->storage->index+node->offset;
				FLATTEN_LOG_DEBUG(" %zu: (%lx:%zu)->(F) | %zu -> %zu\n",
					node->inode->storage->index,
					(unsigned long)node->inode,node->offset,
					origptr,newptr);
			}
			else {
				uintptr_t newptr = node->ptr->node->storage->index+node->ptr->offset;
				uintptr_t origptr = node->inode->storage->index+node->offset;
				FLATTEN_LOG_DEBUG(" %zu: (%lx:%zu)->(%lx:%zu) | %zu -> %zu\n",
						node->inode->storage->index,
						(unsigned long)node->inode,node->offset,
						(unsigned long)node->ptr->node,node->ptr->offset,
						origptr,newptr);
			}
    	}
    	else if (node->inode) {
    		/* Reserved node but never filled */
    		uintptr_t origptr = node->inode->storage->index+node->offset;
    		FLATTEN_LOG_DEBUG(" %zu: (%lx:%zu)-> 0 | %zu\n",
					node->inode->storage->index,
					(unsigned long)node->inode,node->offset,
					origptr);
    	}
    	else {
    		/* Reserved for dummy pointer */
    		FLATTEN_LOG_DEBUG(" (%lx)-> 0 | \n",(unsigned long)node->offset);
    	}
    	p = rb_next(p);
    }
	FLATTEN_LOG_DEBUG("]\n\n");
}

static int fixup_set_write(struct flat* flat, size_t* wcounter_p) {
	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
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

static int fixup_set_fptr_write(struct flat* flat, size_t* wcounter_p) {
	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
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

static size_t fixup_fptr_info_count(struct flat* flat) {
	char func_symbol[128];
	size_t symbol_len, func_ptr, count = sizeof(size_t);

	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		if (((unsigned long)node->ptr) & 1) {
			func_ptr = ((unsigned long)node->ptr) & ~(1ULL);
			symbol_len = flatten_func_to_name(func_symbol, sizeof(func_symbol), (void*) func_ptr);

			count += 2 * sizeof(size_t) + symbol_len;
		}
		p = rb_next(p);
	}
	return count;
}

static int fixup_set_fptr_info_write(struct flat* flat, size_t* wcounter_p) {
	char func_symbol[128];
	size_t symbol_len, func_ptr, orig_ptr;
	struct rb_node* p;

	FLATTEN_WRITE_ONCE(&flat->FLCTRL.HDR.fptr_count, sizeof(size_t), wcounter_p);

	p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		if (((unsigned long)node->ptr) & 1) {
			func_ptr = ((unsigned long)node->ptr) & ~(1ULL);
			orig_ptr = node->inode->storage->index+node->offset;
			symbol_len = flatten_func_to_name(func_symbol, sizeof(func_symbol), (void*) func_ptr);

			FLATTEN_WRITE_ONCE(&orig_ptr, sizeof(size_t), wcounter_p);
			FLATTEN_WRITE_ONCE(&symbol_len, sizeof(size_t), wcounter_p);
			FLATTEN_WRITE_ONCE(func_symbol, symbol_len, wcounter_p);
		}
		p = rb_next(p);
	}
	return 0;
}

static size_t mem_fragment_index_count(struct flat* flat) {

	struct rb_node * p = rb_first(&flat->FLCTRL.imap_root.rb_root);
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

static int mem_fragment_index_write(struct flat* flat, size_t* wcounter_p) {

	struct rb_node * p = rb_first(&flat->FLCTRL.imap_root.rb_root);
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

static int mem_fragment_index_debug_print(struct flat* flat) {

	struct rb_node * p = rb_first(&flat->FLCTRL.imap_root.rb_root);
	size_t index = 0;
	size_t fragment_size = 0;
	size_t mcount = 0;
	FLATTEN_LOG_DEBUG("# Fragment list\n");
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		fragment_size += node->storage->size;
		p = rb_next(p);
		if ((!p)||(node->last+1!=((struct flat_node*)p)->start)) {
			if (p) {
				size_t nindex = ((struct flat_node*)p)->storage->index;
				FLATTEN_LOG_DEBUG("%08zu [%zu]\n",index,nindex-index);
				index = nindex;
			}
			else {
				FLATTEN_LOG_DEBUG("%08zu [%zu]\n",index,fragment_size);
			}
			fragment_size = 0;
			mcount++;
		}
	};

	return 0;
}

static size_t fixup_set_count(struct flat* flat) {
	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
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

static size_t fixup_set_fptr_count(struct flat* flat) {
	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
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

static void fixup_set_destroy(struct flat* flat) {
	struct rb_node * p = rb_first(&flat->FLCTRL.fixup_set_root.rb_root);
	while(p) {
		struct fixup_set_node* node = (struct fixup_set_node*)p;
		rb_erase(p, &flat->FLCTRL.fixup_set_root.rb_root);
		p = rb_next(p);
		if (!(((unsigned long)node->ptr)&1)) {
			flat_free(node->ptr);
		}
		flat_free(node);
	};
}

/*******************************************************
 * Root Addr set
 ******************************************************/
static struct root_addr_set_node* root_addr_set_search(struct flat* flat, const char* name) {

	struct rb_node *node = flat->root_addr_set.rb_node;

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

static int root_addr_set_insert(struct flat* flat, const char* name, uintptr_t v) {

	struct root_addr_set_node* data = (struct root_addr_set_node*) flat_zalloc(flat, 1, sizeof(struct root_addr_set_node));
	struct rb_node **new_node, *parent = 0;
	data->name = (char*) flat_zalloc(flat, 1, strlen(name)+1);
	strcpy(data->name,name);
	data->root_addr = v;
	new_node = &(flat->root_addr_set.rb_node);

	/* Figure out where to put new node */
	while (*new_node) {
		struct root_addr_set_node* this_node = container_of(*new_node, struct root_addr_set_node, node);

		parent = *new_node;
		if (strcmp(data->name,this_node->name)<0)
			new_node = &((*new_node)->rb_left);
		else if (strcmp(data->name,this_node->name)>0)
			new_node = &((*new_node)->rb_right);
		else {
			flat_free((void*)data->name);
		    flat_free(data);
		    return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new_node);
	rb_insert_color(&data->node, &flat->root_addr_set);

	return 1;
}

int root_addr_append(struct flat* flat, uintptr_t root_addr) {
	struct root_addrnode* v = (struct root_addrnode*) flat_zalloc(flat, sizeof(struct root_addrnode), 1);
	if (!v)
		return ENOMEM;

	INIT_LIST_HEAD(&v->head);
	v->root_addr = root_addr;
	list_add_tail(&v->head, &flat->FLCTRL.root_addr_head);
	flat->FLCTRL.root_addr_count++;
	return 0;
}

EXPORT_FUNC(root_addr_append);

int root_addr_append_extended(struct flat* flat, size_t root_addr, const char* name, size_t size) {
	struct root_addr_set_node* root_addr_node = root_addr_set_search(flat, name);
	struct root_addrnode* v;

	if (root_addr_node)
		return EEXIST;

	v = (struct root_addrnode*) flat_zalloc(flat, sizeof(struct root_addrnode), 1);
	if (!v)
		return ENOMEM;

	INIT_LIST_HEAD(&v->head);
	v->root_addr = root_addr;
	v->name = name;
	v->index = flat->FLCTRL.root_addr_count;
	v->size = size;
	list_add_tail(&v->head, &flat->FLCTRL.root_addr_head);
	flat->FLCTRL.root_addr_count++;
	root_addr_set_insert(flat, name, root_addr);
	return 0;
}
EXPORT_FUNC(root_addr_append_extended);

static size_t root_addr_count(struct flat* flat) {
	struct root_addrnode *entry = NULL;
	size_t count = 0;

	list_for_each_entry(entry, &flat->FLCTRL.root_addr_head, head)
		count++;

	return count;
}

size_t root_addr_extended_count(struct flat* flat) {
	struct root_addrnode *entry = NULL;
	size_t count = 0;

	list_for_each_entry(entry, &flat->FLCTRL.root_addr_head, head) {
		if (entry->name)
			count++;
	}

	return count;
}

size_t root_addr_extended_size(struct flat* flat) {
	struct root_addrnode *entry = NULL;
	size_t size = 0, name_len, padding;

	list_for_each_entry(entry, &flat->FLCTRL.root_addr_head, head) {
		if (entry->name) {
			name_len = strlen(entry->name);
			padding = -name_len & 7;
			size += 3 * sizeof(size_t) + name_len + padding;
		}
	}

	return size;
}

static void root_addr_set_destroy(struct flat* flat) {

	struct rb_root* root = &flat->root_addr_set;
	struct rb_node * p = rb_first(root);
    while(p) {
        struct root_addr_set_node* data = (struct root_addr_set_node*)p;
        rb_erase(p, root);
        p = rb_next(p);
        flat_free((void*)data->name);
        flat_free(data);
    }
}

void interval_tree_print(struct rb_root *root) {

	struct rb_node * p;
	size_t total_size = 0;

	FLATTEN_LOG_DEBUG("# Interval tree\n");
	p = rb_first(root);
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		FLATTEN_LOG_DEBUG("(%lx)[%lx:%lx](%zu){%lx}\n",(unsigned long)node,(unsigned long)node->start,(unsigned long)node->last,
				node->last-node->start+1,(unsigned long)node->storage);
		total_size+=node->last-node->start+1;
		p = rb_next(p);
	};
	FLATTEN_LOG_DEBUG("Total size: %zu\n\n",total_size);
}

int interval_tree_destroy(struct flat* flat, struct rb_root *root) {
	struct interval_nodelist *h = 0, *i = 0;
	struct rb_node * p = rb_first(root);
	int rv = 0;
	while(p) {
		struct flat_node* node = (struct flat_node*)p;
		struct interval_nodelist* v;
		v = (struct interval_nodelist*) flat_zalloc(flat,sizeof(struct interval_nodelist),1);
		if (!v) {
			rv = ENOMEM;
			break;
		}
		interval_tree_remove(node,&flat->FLCTRL.imap_root);
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
    	flat_free(p->node);
    	flat_free(p);
    }
	return rv;
}


/*******************************************************
 * FLATTEN engine
 ******************************************************/
void flatten_init(struct flat* flat) {
	memset(&flat->FLCTRL,0,sizeof(struct FLCONTROL));
	INIT_LIST_HEAD(&flat->FLCTRL.storage_head);
	INIT_LIST_HEAD(&flat->FLCTRL.root_addr_head);
	flat->FLCTRL.fixup_set_root = RB_ROOT_CACHED;
	flat->FLCTRL.imap_root = RB_ROOT_CACHED;
	flat->root_addr_set.rb_node = 0;
	flat->mptrindex = 0;
	flat->msize = 0;
#if LINEAR_MEMORY_ALLOCATOR>0
	flat->msize = FLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE;
	flat->mpool = FLATTEN_BSP_ZALLOC(FLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE);
	if (!flat->mpool) {
		flat_errs("Failed to allocate initial kflat memory pool of size %lluu\n",FLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE);
		flat->error = ENOMEM;
	}
#else
	flat->mpool = 0;
#endif

	FLATTEN_LOG_CLEAR();
}

static void flatten_debug_info(struct flat* flat) {
	binary_stream_print(flat);
    interval_tree_print(&flat->FLCTRL.imap_root.rb_root);
    fixup_set_print(flat);
    mem_fragment_index_debug_print(flat);
}

static int flatten_write_internal(struct flat* flat, size_t* wcounter_p) {
	int err = 0;
	struct root_addrnode* entry = NULL;

	binary_stream_calculate_index(flat);
    binary_stream_update_pointers(flat);
    if (flat->FLCTRL.debug_flag) {
    	flatten_debug_info(flat);
    }
	flat->FLCTRL.HDR.magic = KFLAT_IMG_MAGIC;
	flat->FLCTRL.HDR.version = KFLAT_IMG_VERSION;
	flat->FLCTRL.HDR.last_load_addr = (uintptr_t) NULL;
	flat->FLCTRL.HDR.last_mem_addr = (uintptr_t) NULL;
	
    flat->FLCTRL.HDR.memory_size = binary_stream_size(flat);
    flat->FLCTRL.HDR.ptr_count = fixup_set_count(flat);
    flat->FLCTRL.HDR.fptr_count = fixup_set_fptr_count(flat);
    flat->FLCTRL.HDR.root_addr_count = root_addr_count(flat);
    flat->FLCTRL.HDR.root_addr_extended_count = root_addr_extended_count(flat);
    flat->FLCTRL.HDR.root_addr_extended_size = root_addr_extended_size(flat);
    flat->FLCTRL.HDR.fptrmapsz = fixup_fptr_info_count(flat);
    if(!flat->FLCTRL.mem_fragments_skip)
        flat->FLCTRL.HDR.mcount = mem_fragment_index_count(flat);
    else
        flat->FLCTRL.HDR.mcount = 0;
    FLATTEN_WRITE_ONCE(&flat->FLCTRL.HDR, sizeof(struct flatten_header), wcounter_p);

	list_for_each_entry(entry, &flat->FLCTRL.root_addr_head, head) {
		size_t root_addr_offset;
		if (entry->root_addr) {
			struct flat_node *node = PTRNODE(entry->root_addr);
			if (!node) {
				/* Actually nothing has been flattened under this root address */
				root_addr_offset = (size_t) - 1;
			} else {
				root_addr_offset = node->storage->index + (entry->root_addr - node->start);
			}
		} else {
			root_addr_offset = (size_t) - 1;
		}
		FLATTEN_WRITE_ONCE(&root_addr_offset, sizeof(size_t), wcounter_p);
	}

	entry = NULL;
	list_for_each_entry(entry, &flat->FLCTRL.root_addr_head, head) {
		if (entry->name) {
			size_t name_size = strlen(entry->name);
			size_t padding = -name_size & 7;
			size_t size_with_padding = name_size + padding;
			char padding_source[8] = {0};

			FLATTEN_WRITE_ONCE(&size_with_padding, sizeof(size_t), wcounter_p);
			FLATTEN_WRITE_ONCE(entry->name, name_size, wcounter_p);
			FLATTEN_WRITE_ONCE(padding_source, padding, wcounter_p);	// Align index to 8bytes
			FLATTEN_WRITE_ONCE(&entry->index, sizeof(size_t), wcounter_p);
			FLATTEN_WRITE_ONCE(&entry->size, sizeof(size_t), wcounter_p);
		}
	}

	if ((err = fixup_set_write(flat,wcounter_p))!=0) {
		return err;
	}
	if ((err = fixup_set_fptr_write(flat,wcounter_p))!=0) {
		return err;
	}
	if(!flat->FLCTRL.mem_fragments_skip) {
		if ((err = mem_fragment_index_write(flat,wcounter_p))!=0) {
			return err;
		}
	}
	if ((err = binary_stream_write(flat,wcounter_p))!=0) {
		return err;
	}
	if ((err = fixup_set_fptr_info_write(flat, wcounter_p)) != 0) {
		return err;
	}
    return 0;
}

int flatten_write(struct flat* flat) {

	size_t written = 0;
	int err;

	if ((err=flatten_write_internal(flat,&written))==0) {
		flat_infos("OK. Flatten size: %lu, %lu pointers, %zu root pointers, %lu function pointers, %lu continuous memory fragments, "
				"%zu bytes written, memory used: %zu, memory avail: %zu\n",
			flat->FLCTRL.HDR.memory_size,flat->FLCTRL.HDR.ptr_count,flat->FLCTRL.HDR.root_addr_count,flat->FLCTRL.HDR.fptr_count,
			flat->FLCTRL.HDR.mcount,written-sizeof(size_t),flat->mptrindex,flat->msize);
	}
	else {
		flat_errs("ERROR %d: Could not write flatten image. Flatten size: %lu, %lu pointers, %zu root pointers, %lu function pointers,"
				"%lu continuous memory fragments, %zu bytes written\n",flat->error,flat->FLCTRL.HDR.memory_size,
				flat->FLCTRL.HDR.ptr_count,flat->FLCTRL.HDR.root_addr_count,flat->FLCTRL.HDR.fptr_count,flat->FLCTRL.HDR.mcount,written-sizeof(size_t));
	}

	((struct flatten_header*)flat->area)->image_size = written;
	return err;
}
EXPORT_FUNC(flatten_write);

int flatten_fini(struct flat* flat) {
	struct root_addrnode *ptr = NULL;
	struct root_addrnode *tmp = NULL;
	binary_stream_destroy(flat);
    fixup_set_destroy(flat);
	list_for_each_entry_safe(ptr, tmp, &flat->FLCTRL.root_addr_head, head) {
		list_del(&ptr->head);
		flat_free(ptr);
	}
    interval_tree_destroy(flat,&flat->FLCTRL.imap_root.rb_root);
	root_addr_set_destroy(flat);
#if LINEAR_MEMORY_ALLOCATOR
    FLATTEN_BSP_FREE(flat->mpool);
    flat->mptrindex = 0;
    flat->msize = 0;
#endif
    return 0;
}

struct flat_node* flatten_acquire_node_for_ptr(struct flat* flat, const void* _ptr, size_t size) {
	struct flat_node *node = interval_tree_iter_first(&flat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr + size - 1);
	struct flat_node* head_node = 0;
	if (node) {
		uintptr_t p = (uintptr_t)_ptr;
    	struct flat_node *prev = NULL;
    	while(node) {
			if (node->start>p) {
				struct flat_node* nn;
				if (node->storage == 0) {
					flat->error = EFAULT;
					DBGS("%s(%lx): EFAULT (node(%lx)->storage==0)\n", __func__, (uintptr_t)_ptr, node);
					return 0;
				}
				nn = (struct flat_node*) flat_zalloc(flat,sizeof(struct flat_node),1);
				if (nn == 0) {
					flat->error = ENOMEM;
					DBGS("%s(%lx): ENOMEM\n",__func__, (uintptr_t)_ptr);
					return 0;
				}
				nn->start = p;
				nn->last = node->start-1;
				nn->storage = binary_stream_insert_front(flat, (void*)p, node->start-p, node->storage);
				interval_tree_insert(nn, &flat->FLCTRL.imap_root);
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
				flat->error = EFAULT;
				DBGS("%s(%lx): EFAULT (prev(%llx)->storage==0)\n", __func__, (uintptr_t)_ptr, (uint64_t)prev);
				return 0;
			}
			nn = (struct flat_node*) flat_zalloc(flat, sizeof(struct flat_node), 1);
			if (nn == NULL) {
				flat->error = ENOMEM;
				DBGS("%s(%lx): ENOMEM\n",__func__, (uintptr_t)_ptr);
				return 0;
			}
			nn->start = p;
			nn->last = (uintptr_t)_ptr + size - 1;
			nn->storage = binary_stream_insert_back(flat, (void*)p, (uintptr_t)_ptr + size - p, prev->storage);
			interval_tree_insert(nn, &flat->FLCTRL.imap_root);
		}
	} else {
    	struct blstream* storage;
    	struct rb_node* rb;
    	struct rb_node* prev;
    	node = (struct flat_node*) flat_zalloc(flat, sizeof(struct flat_node), 1);
    	if (!node) {
	    	flat->error = ENOMEM;
    		DBGS("%s(%lx): ENOMEM\n", __func__, (uintptr_t)_ptr);
			return 0;
		}
		node->start = (uint64_t)_ptr;
        node->last = (uint64_t)_ptr +  size - 1;
        interval_tree_insert(node, &flat->FLCTRL.imap_root);
        rb = &node->rb;
        prev = rb_prev(rb);
        if (prev) {
           	storage = binary_stream_insert_back(flat,_ptr, size,((struct flat_node*)prev)->storage);
        } else {
			struct rb_node* next = rb_next(rb);
			if (next)
				storage = binary_stream_insert_front(flat,_ptr, size,((struct flat_node*)next)->storage);
			else
				storage = binary_stream_append(flat,_ptr, size);
		}
		if (!storage) {
			flat->error = ENOMEM;
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
EXPORT_FUNC(flatten_acquire_node_for_ptr);

void flatten_generic(struct flat* flat, void* q, struct flatten_pointer* fptr, const void* p, size_t el_size, size_t count, uintptr_t custom_val, flatten_struct_t func_ptr, unsigned long shift) {
	int err;
	size_t i;
	struct flatten_pointer* __shifted;
	struct flat_node* __ptr_node;
	const void* _fp = (const void*)((char*)p+shift);

	DBGS("flatten_generic: ADDR(%lx)\n", (uintptr_t) _fp);

	if(flat->error || !ADDR_RANGE_VALID(_fp, count * el_size)) {
		DBGS("flatten_generic: error(%d), ADDR(0x%lx)", flat->error, (uintptr_t) _fp);
		return;
	}

	__shifted = flatten_plain_type(flat, _fp, count * el_size);
	if(__shifted == NULL) {
		DBGS("flatten_generic: flatten_plain_type() == NULL");
		flat->error = EFAULT;
		return;
	}

	if (shift != 0) {
		__ptr_node = interval_tree_iter_first(
				&flat->FLCTRL.imap_root, 
				(uintptr_t)_fp - shift,
				(uintptr_t)_fp - shift + 1);
		__shifted->node = __ptr_node;
		__shifted->offset = (uintptr_t)_fp - shift - __ptr_node->start;
	}

	err = fixup_set_insert_force_update(flat, fptr->node, fptr->offset, __shifted);
	if (err && err != EINVAL && err != EEXIST && err != EAGAIN) {
		DBGS("flatten_generic: fixup_set_insert_force_update(): err(%d)", err);
		flat->error = err;
	} else if (err != EEXIST) {
		struct fixup_set_node* struct_inode;
		err = 0;

		for (i = 0; i < count; ++i) {
			const void* target = (char*)_fp + i * el_size;
			struct_inode = fixup_set_search(flat, (uint64_t)target);
			if (!struct_inode) {
				struct flatten_job job = {0, };
				
				int err = fixup_set_reserve_address(flat, (uint64_t)target);
				if(err)
					break;

				job.size = 1;
				job.custom_val = custom_val;
				job.index = i;
				job.ptr = (struct flatten_base*)target;
				job.fun = func_ptr;
				err = bqueue_push_back(flat, (struct bqueue*) q, &job, sizeof(struct flatten_job));
				if (err) 
					break;
			}
		}

		if (err && err != EEXIST)
			flat->error = err;
	}
}
EXPORT_FUNC(flatten_generic);

void flatten_aggregate_generic(struct flat* flat, void* q, const void* _ptr, 
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
		_fp = (const void*) ( (char*)_p+_shift);

	if (flat->error || !ADDR_RANGE_VALID(_fp, el_size * count)) {
		DBGS("AGGREGATE_FLATTEN_GENERIC: error(%d), ADDR(%lx)\n", flat->error, (uintptr_t)OFFATTR(void**,_off));
		return;
	}
	__node = interval_tree_iter_first(
			&flat->FLCTRL.imap_root, 
			(uint64_t)_ptr + _off,
			(uint64_t)_ptr + _off + sizeof(void*) - 1);
	if (__node == NULL) {
		flat->error = EFAULT;
		return;
	}

	__shifted = flatten_plain_type(flat, _fp, el_size * count);
	if(__shifted == NULL) {
		DBGS("AGGREGATE_FLATTEN_GENERIC:flatten_plain_type(): NULL");
		flat->error = EFAULT;
		return;
	}
	if (_shift != 0) {
		__ptr_node = interval_tree_iter_first(
				&flat->FLCTRL.imap_root, 
				(uintptr_t)_fp - _shift,
				(uintptr_t)_fp - _shift + 1);
		__shifted->node = __ptr_node;
		__shifted->offset = (uintptr_t)_fp - _shift - __ptr_node->start;
	}

	if (post_f)
		__shifted = post_f(__shifted, OFFATTR(const struct flatten_base*, _off));

	err = fixup_set_insert_force_update(flat, __node, (uint64_t)_ptr - __node->start + _off, __shifted);
	if (err && err != EEXIST && err != EAGAIN) {
		DBGS("AGGREGATE_FLATTEN_GENERIC:fixup_set_insert_force_update(): err(%d)\n",err);
		flat->error = err;
		return;
	}
	if(err == EEXIST) return;

	err = 0;
	for (_i = 0; _i < count; ++_i) {
		struct flat_node *__struct_node = interval_tree_iter_first(
				&flat->FLCTRL.imap_root,
				(uint64_t)((char*)_fp + _i * el_size),
				(uint64_t)((char*)_fp + (_i + 1) * el_size - 1));
		if (__struct_node == NULL) {
			err = EFAULT;
			break;
		}

		__struct_inode = fixup_set_search(flat,(uint64_t)((char*)_fp + _i * el_size));
		if (!__struct_inode) {
			struct flatten_job __job;
			int err = fixup_set_reserve_address(flat,(uint64_t)((char*)_fp + _i * el_size));
			if (err) break;
			__job.node = 0;
			__job.offset = 0;
			__job.size = 1;
			__job.custom_val = (uintptr_t)custom_val;
			__job.index = _i;
			__job.ptr = (struct flatten_base*)((char*)_fp + _i * el_size);
			__job.fun = func_ptr;
			__job.fp = 0;
			__job.convert = 0;
			err = bqueue_push_back(flat, (struct bqueue*) q, &__job, sizeof(struct flatten_job));
			if (err) break;
		}
	}
	if (err && (err != EEXIST))
		flat->error = err;
}
EXPORT_FUNC(flatten_aggregate_generic);

void flatten_aggregate_generic_storage(struct flat* flat, void* q, const void* _ptr, 
		size_t el_size, size_t count, uintptr_t custom_val, ssize_t _off, flatten_struct_t func_ptr) {
	int err = 0;
	void* target;
	struct flatten_job job;
	struct fixup_set_node* inode;
	void* _fp = (unsigned char*)_ptr + _off;

	if(flat->error || !ADDR_RANGE_VALID(_fp, count * el_size)) {
		DBGS("flatten_aggregate_generic_storage: error(%d), ADDR(0x%lx)", flat->error, (uintptr_t) _fp);
		return;
	}

	for (size_t i = 0; i < count; ++i) {
		target = (unsigned char*)_ptr + _off + i * el_size;
		if (flat->error)
			break;
		
		inode = fixup_set_search(flat, (uintptr_t) target);
		if (!inode)
			err = fixup_set_reserve_address(flat, (uintptr_t) target);
		
		if(err && err != EEXIST) {
			flat->error = err;
			DBGS("AGGREGATE_FLATTEN_GENERIC_STORAGE: error(%d)\n", flat->error);
			break;
		}
		
		job.node = 0;
		job.offset = 0;
		job.size = 1;
		job.custom_val = custom_val;
		job.index = i;
		job.ptr = (struct flatten_base*) target;
		job.fun = func_ptr;
		job.fp = 0;
		job.convert = 0;
		bqueue_push_back(flat, (struct bqueue*) q, &job, sizeof(struct flatten_job));
	}
}
EXPORT_FUNC(flatten_aggregate_generic_storage);

struct flatten_pointer* flatten_plain_type(struct flat* flat, const void* _ptr, size_t _sz) {

	struct flat_node* node;
	struct flatten_pointer* flat_ptr;

	if (!_sz) {
		flat_errs("flatten_plain_type - zero size memory");
		return 0;
	}

	node = flatten_acquire_node_for_ptr(flat, _ptr, _sz);

	if (!node) {
		flat_errs("failed to acquire flatten node");
		return 0;
	}

	flat_ptr = make_flatten_pointer(flat,node,(uintptr_t)_ptr-node->start);
	if (!flat_ptr) {
		return 0;
	}

	return flat_ptr;
}
EXPORT_FUNC(flatten_plain_type);

void flatten_run_iter_harness(struct flat* flat, struct bqueue* bq) {
	size_t n = 0;
	ktime_t init_time, now;
	long long int total_time = 0;
	void* fp;
	struct flatten_job job;

	init_time = ktime_get();
	while((!flat->error) && (!bqueue_empty(bq))) {
		int err;

		DBGS("%s: queue iteration, size: %zu el_count: %ld\n",__func__, bqueue_size(bq),bqueue_el_count(bq));

		err = bqueue_pop_front(bq, &job, sizeof(struct flatten_job));
		if (err) {
			flat->error = err;
			break;
		}

		fp = job.fun(flat, job.ptr, job.size, job.custom_val, job.index, bq);
		if (job.convert != NULL)
			fp = job.convert((struct flatten_pointer*) fp, job.ptr);

		if (job.node != NULL) {
			err = fixup_set_insert_force_update(flat, job.node, job.offset, (struct flatten_pointer*) fp);
			if (err && err != EINVAL && err != EEXIST && err != EAGAIN) {
				flat->error = err;
				break;
			}
		} else {
			if (!fp) 
				break;
			flat_free(fp);
		}

		n++;
		now = ktime_get();
		DBGS("UNDER_ITER_HARNESS: recipes done: %lu, elapsed: %lld\n", n, now - init_time);

		if (now - init_time > FLAT_PING_TIME_NS) {
			total_time += now - init_time;
			if (total_time > FLAT_MAX_TIME_NS) {
				flat_errs("Timeout! Total time %lld [ms] exceeds maximum allowed %ld [ms]\n", 
							total_time / NSEC_PER_MSEC, FLAT_MAX_TIME_NS / NSEC_PER_MSEC);
				flat->error = EAGAIN;
				break;
			}
			flat_infos("Still working! done %lu recipes in total time %lld [ms], memory used: %zu, memory avail: %zu \n",
				n, total_time / NSEC_PER_MSEC, flat->mptrindex, flat->msize);
			init_time = ktime_get();
		}
	}
	total_time += ktime_get() - init_time;
	flat_infos("Done working with %lu recipes in total time %lld [ms], memory used: %zu, memory avail: %zu \n",
		n, total_time / NSEC_PER_MSEC, flat->mptrindex, flat->msize);
	bqueue_destroy(bq);
}
EXPORT_FUNC(flatten_run_iter_harness);
