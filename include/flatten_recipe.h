/**
 * @file flatten_recipe.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief TODO
 * 
 */
#ifndef FLATTEN_RECIPE_H
#define FLATTEN_RECIPE_H

#if defined(FLATTEN_KERNEL_BSP)
#include "kflat_uaccess.h"
#endif /* defined(FLATTEN_KERNEL_BSP) */

/*************************************
 * FUNCTION_FLATTEN macros for ARRAYS
 *************************************/
#define FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(FUNC_NAME, TARGET_FUNC, FULL_TYPE, FLSIZE)	\
struct flatten_pointer* FUNC_NAME(struct flat* flat, const void* ptr, size_t n, uintptr_t custom_val, unsigned long index, struct bqueue* __q) {    \
	size_t _i;			\
	void* _fp_first = NULL;		\
	const FULL_TYPE* _ptr = (const FULL_TYPE*) ptr;			\
	DBGS("%s(%lx,%zu)\n", __func__, (uintptr_t)_ptr, n);		\
	AGGREGATE_FLATTEN_ASSERT(n < INT_MAX, EINVAL);	/* Limit array size to some sane value */	\
	for (_i = 0; _i < n; ++_i) {					\
		void* _fp = (void*)TARGET_FUNC(flat, (FULL_TYPE*)((unsigned char*)_ptr + _i * FLSIZE), custom_val, index, __q);	\
		if (_fp == NULL) {			\
			flat_free(_fp_first);		\
			_fp_first = NULL;		\
			break;				\
		}					\
		if (_fp_first == NULL) _fp_first = _fp;	\
		else flat_free(_fp);			\
	}						\
	if (flat->error) 				\
		return NULL;				\
	return _fp_first;				\
}

/* We assume that when we have an array to structure type that contains flexible array members we cannot have more than single element of this array
 * When such situation happens, complain and force to write a custom recipe
 */
#define FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY_FLEXIBLE(FUNC_NAME, TARGET_FUNC, FULL_TYPE)	\
struct flatten_pointer* FUNC_NAME(struct flat* flat, const void* ptr, size_t n, uintptr_t custom_val, unsigned long index, struct bqueue* __q) {    \
	const FULL_TYPE* _ptr = (const FULL_TYPE*) ptr;			\
	void* _fp = NULL;	\
	if (n!=1) {	\
		DBGS("ERROR: Multiple elements in an array of structure type with flexible array members: [ " #FULL_TYPE " ]\n");	\
		flat->error = EFAULT;	\
		return NULL;	\
	}	\
	DBGS("%s(%lx,%zu)\n", __func__, (uintptr_t)_ptr, n);		\
	_fp = (void*)TARGET_FUNC(flat, (FULL_TYPE*)((unsigned char*)_ptr), custom_val, index, __q);	\
	if (flat->error) 				\
		return NULL;				\
	return _fp;				\
}

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY(FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_struct_array_##FLTYPE, flatten_struct_##FLTYPE, struct FLTYPE, sizeof(struct FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_FLEXIBLE(FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY_FLEXIBLE(flatten_struct_array_##FLTYPE, flatten_struct_##FLTYPE, struct FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_FLEXIBLE(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_struct_type_array_##FLTYPE, flatten_struct_type_##FLTYPE, FLTYPE, sizeof(FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE(FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY_FLEXIBLE(flatten_struct_type_array_##FLTYPE, flatten_struct_type_##FLTYPE, FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_UNION_ARRAY(FLTYPE) \
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_union_array_##FLTYPE, flatten_union_##FLTYPE, union FLTYPE, sizeof(union FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_UNION_ARRAY(FLTYPE) \
	extern struct flatten_pointer* flatten_union_array_##FLTYPE(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SPECIALIZE(TAG,FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_struct_array_##FLTYPE##_##TAG, flatten_struct_##FLTYPE##_##TAG, struct FLTYPE, sizeof(struct FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE##_##TAG(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY_FLEXIBLE(flatten_struct_array_##FLTYPE##_##TAG, flatten_struct_##FLTYPE##_##TAG, struct FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE##_##TAG(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE(TAG,FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_struct_type_array_##FLTYPE##_##TAG, flatten_struct_type_##FLTYPE##_##TAG, FLTYPE, sizeof(FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE##_##TAG(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY_FLEXIBLE(flatten_struct_type_array_##FLTYPE##_##TAG, flatten_struct_type_##FLTYPE##_##TAG, FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE##_##TAG(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_struct_array_##FLTYPE, flatten_struct_##FLTYPE, struct FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_struct_type_array_##FLTYPE, flatten_struct_type_##FLTYPE, FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct flat* flat, const void* _ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE) \
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_struct_array_##FLTYPE##_##TAG, flatten_struct_##FLTYPE##_##TAG, struct FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE) \
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE##_##TAG(struct flat* flat, const void* _ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE) \
	FUNCTION_DEFINE_FLATTEN_GENERIC_ARRAY(flatten_union_array_##FLTYPE, flatten_union_##FLTYPE, union FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE) \
	extern struct flatten_pointer* flatten_union_array_##FLTYPE(struct flat* flat, const void* ptr, size_t n, uintptr_t __cval, unsigned long __index, struct bqueue* __q);


/*************************************
 * FUNCTION_FLATTEN macros for types
 *************************************/
#define FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(FUNC_NAME, FULL_TYPE, FLSIZE, ...)  \
			\
struct flatten_pointer* FUNC_NAME(struct flat* flat, const void* ptr, uintptr_t __cval, unsigned long __index, struct bqueue* __q) {    \
            \
	static const short align_array[] = {8, 1, 2, 1, 4, 1, 2, 1}; \
	struct flat_node *__node;		\
	typedef FULL_TYPE _container_type __attribute__((unused)); \
	size_t _alignment = align_array[(uintptr_t) ptr % 8];  \
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
	const FULL_TYPE* _ptr = (const FULL_TYPE*) ptr;	\
	size_t type_size = FLSIZE;	\
	if (type_size==SIZE_MAX) {	\
		DBGS("ERROR: failed to detect flexible array size @ %lx\n",ptr);	\
		flat->error = EFAULT;	\
		return 0;	\
	}	\
        \
	DBGS("%s(%lx): [%zu]\n", __func__, (uintptr_t)_ptr, type_size);	\
	__node = flatten_acquire_node_for_ptr(FLAT_ACCESSOR, (void*) ptr, type_size);	\
	\
	__VA_ARGS__ \
	if (flat->error) {   \
		DBGS("%s(%lx): %d\n", __func__, (uintptr_t)_ptr,flat->error);	\
		return 0;	\
	}	\
	__node = flat_interval_tree_iter_first(&flat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(void*)-1);    \
	if (__node==0) {	\
		flat->error = EFAULT;	\
		DBGS("%s(%lx): EFAULT (__node==0)\n", __func__, (uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
	r = make_flatten_pointer(flat,__node,_node_offset);	\
	if (!r) {	\
		flat->error = ENOMEM;	\
		DBGS("%s(%lx): ENOMEM\n", __func__, (uintptr_t)_ptr);	\
		return 0;	\
	}			\
	return r;		\
}


#define FUNCTION_DEFINE_FLATTEN_STRUCT(FLTYPE,...)  	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE, struct FLTYPE, sizeof(struct FLTYPE), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_##FLTYPE(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(FLTYPE,FLSIZE,...)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE, struct FLTYPE, FLSIZE, __VA_ARGS__) \
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE(FLTYPE,...)  	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE, struct FLTYPE, FLATTEN_DETECT_OBJECT_SIZE((void*)ptr,SIZE_MAX), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_FLEXIBLE(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_FLEXIBLE(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_##FLTYPE(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_FLEXIBLE(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_type_##FLTYPE, FLTYPE, sizeof(FLTYPE), __VA_ARGS__) \
	FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_##FLTYPE(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(FLTYPE,FLSIZE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_type_##FLTYPE, FLTYPE, FLSIZE, __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_FLEXIBLE(FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_type_##FLTYPE, FLTYPE, FLATTEN_DETECT_OBJECT_SIZE((void*)ptr,SIZE_MAX), __VA_ARGS__) \
	FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_FLEXIBLE(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_##FLTYPE(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_UNION(FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_union_##FLTYPE, union FLTYPE, sizeof(union FLTYPE), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_UNION_ARRAY(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_UNION(FLTYPE) \
	extern struct flatten_pointer* flatten_union_##FLTYPE(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_UNION_ARRAY(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_UNION_SELF_CONTAINED(FLTYPE,FLSIZE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_union_##FLTYPE, union FLTYPE, FLSIZE, __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_SPECIALIZE(TAG,FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE##_##TAG, struct FLTYPE, sizeof(struct FLTYPE), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_##FLTYPE##_##TAG(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE_SPECIALIZE(TAG,FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE##_##TAG, struct FLTYPE, FLATTEN_DETECT_OBJECT_SIZE((void*)ptr,SIZE_MAX), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_##FLTYPE##_##TAG(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE##_##TAG, struct FLTYPE, FLSIZE, __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE)	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SPECIALIZE(TAG,FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_type_##FLTYPE##_##TAG, FLTYPE, sizeof(FLTYPE), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_##FLTYPE##_##TAG(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_FLEXIBLE_SPECIALIZE(TAG,FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_type_##FLTYPE##_##TAG, FLTYPE, FLATTEN_DETECT_OBJECT_SIZE((void*)ptr,SIZE_MAX), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_##FLTYPE##_##TAG(struct flat* flat, const void*, uintptr_t __cval, unsigned long __index, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE_SPECIALIZE(TAG,FLTYPE)

/*******************************
 * FLATTEN macros
 *******************************/
#define FLATTEN_GENERIC(p, EL_SIZE, COUNT, CUSTOM_VAL, FUNC, SHIFT)   \
	flatten_generic(FLAT_ACCESSOR, __q, __fptr, p, EL_SIZE, COUNT, CUSTOM_VAL, FUNC, SHIFT)

#define FLATTEN_STRUCT_ARRAY(T,p,n)	\
	DBGM3(FLATTEN_STRUCT_ARRAY,T,p,n);	\
	FLATTEN_GENERIC(p, sizeof(struct T), n, 0, flatten_struct_array_##T, 0)

#define FLATTEN_STRUCT_ARRAY_FLEXIBLE(T,p,n)	\
	do {	\
		size_t type_size;	\
		DBGM3(FLATTEN_STRUCT_ARRAY_FLEXIBLE,T,p,n);	\
		if (n!=1) {	\
			DBGS("ERROR: Multiple elements in an array of structure type with flexible array members: [ " #T " ]\n");	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		type_size = FLATTEN_DETECT_OBJECT_SIZE((void*)p,SIZE_MAX);	\
		if (type_size==SIZE_MAX) {	\
			DBGS("ERROR: failed to detect flexible array size @ %lx\n",p);	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		FLATTEN_GENERIC(p, type_size, n, 0, flatten_struct_array_##T, 0);	\
	} while(0)

#define FLATTEN_STRUCT(T,p)	\
	FLATTEN_STRUCT_ARRAY(T,p,1)

#define FLATTEN_STRUCT_FLEXIBLE(T,p)	\
	FLATTEN_STRUCT_ARRAY_FLEXIBLE(T,p,1)

#define FLATTEN_STRUCT_ARRAY_SHIFTED(T,p,n,s)	\
	DBGM4(FLATTEN_STRUCT_ARRAY_SHIFTED,T,p,n,s);	\
	FLATTEN_GENERIC(p, sizeof(struct T), n, 0, flatten_struct_array_##T, s)

#define FLATTEN_STRUCT_ARRAY_SHIFTED_FLEXIBLE(T,p,n,s)	\
	do {	\
		size_t type_size;	\
		DBGM3(FLATTEN_STRUCT_ARRAY_SHIFTED_FLEXIBLE,T,p,n);	\
		if (n!=1) {	\
			DBGS("ERROR: Multiple elements in an array of structure type with flexible array members: [ " #T " ]\n");	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		type_size = FLATTEN_DETECT_OBJECT_SIZE((void*)p,SIZE_MAX);	\
		if (type_size==SIZE_MAX) {	\
			DBGS("ERROR: failed to detect flexible array size @ %lx\n",p);	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		FLATTEN_GENERIC(p, type_size, n, 0, flatten_struct_array_##T, s);	\
	} while(0)

#define FLATTEN_STRUCT_SHIFTED(T,p,s)	\
	FLATTEN_STRUCT_ARRAY_SHIFTED(T,p,1,s)

#define FLATTEN_STRUCT_SHIFTED_FLEXIBLE(T,p,s)	\
	FLATTEN_STRUCT_ARRAY_SHIFTED_FLEXIBLE(T,p,1,s)

#define FLATTEN_STRUCT_ARRAY_SPECIALIZE(TAG,T,p,n)	\
	DBGM3(FLATTEN_STRUCT_ARRAY_SPECIALIZE,T,p,n);	\
	FLATTEN_GENERIC(p, sizeof(struct T), n, 0, flatten_struct_array_##T##_##TAG, 0)

#define FLATTEN_STRUCT_ARRAY_SPECIALIZE_FLEXIBLE(TAG,T,p,n)	\
	do {	\
		size_t type_size;	\
		DBGM3(FLATTEN_STRUCT_ARRAY_SPECIALIZE_FLEXIBLE,T,p,n);	\
		if (n!=1) {	\
			DBGS("ERROR: Multiple elements in an array of structure type with flexible array members: [ " #T " ]\n");	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		type_size = FLATTEN_DETECT_OBJECT_SIZE((void*)p,SIZE_MAX);	\
		if (type_size==SIZE_MAX) {	\
			DBGS("ERROR: failed to detect flexible array size @ %lx\n",p);	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		FLATTEN_GENERIC(p, type_size, n, 0, flatten_struct_array_##T##_##TAG, 0);	\
	} while(0)

#define FLATTEN_STRUCT_SPECIALIZE(TAG,T,p)	\
	FLATTEN_STRUCT_ARRAY_SPECIALIZE(TAG,T,p,1)

#define FLATTEN_STRUCT_SPECIALIZE_FLEXIBLE(TAG,T,p)	\
	FLATTEN_STRUCT_ARRAY_SPECIALIZE_FLEXIBLE(TAG,T,p,1)

#define FLATTEN_STRUCT_TYPE_ARRAY(T,p,n)	\
	DBGM3(FLATTEN_STRUCT_TYPE_ARRAY,T,p,n);	\
	FLATTEN_GENERIC(p, sizeof(T), n, 0, flatten_struct_type_array_##T, 0)

#define FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE(T,p,n)	\
	do {	\
		size_t type_size;	\
		DBGM3(FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE,T,p,n);	\
		if (n!=1) {	\
			DBGS("ERROR: Multiple elements in an array of structure type with flexible array members: [ " #T " ]\n");	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		type_size = FLATTEN_DETECT_OBJECT_SIZE((void*)p,SIZE_MAX);	\
		if (type_size==SIZE_MAX) {	\
			DBGS("ERROR: failed to detect flexible array size @ %lx\n",p);	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		FLATTEN_GENERIC(p, type_size, n, 0, flatten_struct_type_array_##T, 0);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE(T,p)	\
	FLATTEN_STRUCT_TYPE_ARRAY(T,p,1)

#define FLATTEN_STRUCT_TYPE_FLEXIBLE(T,p)	\
	FLATTEN_STRUCT_TYPE_ARRAY_FLEXIBLE(T,p,1)

#define FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED(T,p,n,s)	\
	DBGM4(FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED,T,p,n,s);	\
	FLATTEN_GENERIC(p, sizeof(T), n, 0, flatten_struct_type_array_##T, s)

#define FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED_FLEXIBLE(T,p,n,s)	\
	do {	\
		size_t type_size;	\
		DBGM3(FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED_FLEXIBLE,T,p,n);	\
		if (n!=1) {	\
			DBGS("ERROR: Multiple elements in an array of structure type with flexible array members: [ " #T " ]\n");	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		type_size = FLATTEN_DETECT_OBJECT_SIZE((void*)p,SIZE_MAX);	\
		if (type_size==SIZE_MAX) {	\
			DBGS("ERROR: failed to detect flexible array size @ %lx\n",p);	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		FLATTEN_GENERIC(p, type_size, n, 0, flatten_struct_type_array_##T, s);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE_SHIFTED(T,p,s)	\
	FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED(T,p,1,s)

#define FLATTEN_STRUCT_TYPE_SHIFTED_FLEXIBLE(T,p,s)	\
	FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED_FLEXIBLE(T,p,1,s)


#define FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE(TAG,T,p,n)	\
	DBGM3(FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE,T,p,n);	\
	FLATTEN_GENERIC(p, sizeof(T), n, 0, flatten_struct_type_array_##T##_##TAG, 0)

#define FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE_FLEXIBLE(TAG,T,p,n)	\
	do {	\
		size_t type_size;	\
		DBGM3(FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE_FLEXIBLE,T,p,n);	\
		if (n!=1) {	\
			DBGS("ERROR: Multiple elements in an array of structure type with flexible array members: [ " #T " ]\n");	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		type_size = FLATTEN_DETECT_OBJECT_SIZE((void*)p,SIZE_MAX);	\
		if (type_size==SIZE_MAX) {	\
			DBGS("ERROR: failed to detect flexible array size @ %lx\n",p);	\
			flat->error = EFAULT;	\
			break;	\
		}	\
		FLATTEN_GENERIC(p, type_size, n, 0, flatten_struct_type_array_##T##_##TAG, 0);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE_SPECIALIZE(TAG,T,p)	\
	FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE(TAG,T,p,1)

#define FLATTEN_STRUCT_TYPE_SPECIALIZE_FLEXIBLE(TAG,T,p)	\
	FLATTEN_STRUCT_TYPE_ARRAY_SPECIALIZE_FLEXIBLE(TAG,T,p,1)

#define FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,p,n)	\
	DBGM4(FLATTEN_STRUCT_ARRAY_SELF_CONTAINED,T,N,p,n);	\
	FLATTEN_GENERIC(p, N, n, 0, flatten_struct_array_##T, 0)

#define FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,T,N,p,n)	\
	DBGM5(FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE,TAG,T,N,p,n);	\
	FLATTEN_GENERIC(p, N, n, 0, flatten_struct_array_##T##_##TAG, 0)

#define FLATTEN_STRUCT_SELF_CONTAINED(T,N,p)	\
	FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,p,1)

#define FLATTEN_STRUCT_ARRAY_SHIFTED_SELF_CONTAINED(T,N,p,n,s)	\
	DBGM5(FLATTEN_STRUCT_ARRAY_SHIFTED_SELF_CONTAINED,T,N,p,n,s);	\
	FLATTEN_GENERIC(p, N, n, 0, flatten_struct_array_##T, s)

#define FLATTEN_STRUCT_SHIFTED_SELF_CONTAINED(T,N,p,s)	\
	FLATTEN_STRUCT_ARRAY_SHIFTED_SELF_CONTAINED(T,N,p,1,s)

#define FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(TAG,T,N,p)	\
	FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,T,N,p,1)

#define FLATTEN_UNION_ARRAY_SELF_CONTAINED(T,N,p,n)	\
	DBGM4(FLATTEN_UNION_ARRAY_SELF_CONTAINED,T,N,p,n);	\
	FLATTEN_GENERIC(p, N, n, 0, flatten_union_array_##T, 0)

#define FLATTEN_UNION_ARRAY_SHIFTED_SELF_CONTAINED(T,N,p,n,s)	\
	DBGM5(FLATTEN_UNION_ARRAY_SHIFTED_SELF_CONTAINED,T,N,p,n,s);	\
	FLATTEN_GENERIC(p, N, n, 0, flatten_union_array_##T, s)

#define FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,p,n)	\
	DBGM4(FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED,T,N,p,n);	\
	FLATTEN_GENERIC(p, N, n, 0, flatten_struct_type_array_##T, 0)

#define FLATTEN_STRUCT_TYPE_SELF_CONTAINED(T,N,p)	\
	FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,p,1)

#define FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED_SELF_CONTAINED(T,N,p,n,s)	\
	DBGM5(FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED_SELF_CONTAINED,T,N,p,n,s);	\
	FLATTEN_GENERIC(p, N, n, 0, flatten_struct_type_array_##T, s)

#define FLATTEN_STRUCT_TYPE_SHIFTED_SELF_CONTAINED(T,N,p,s)	\
	FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED_SELF_CONTAINED(T,N,p,1,s)

/*******************************
 * AGGREGATE macros
 *******************************/
#define AGGREGATE_FLATTEN_ASSERT(__expr,__err)	\
do {	\
	if (!(__expr)) {	\
		FLAT_ACCESSOR->error = __err;	\
		flat_errs("flatten assertion failed on: [" #__expr "]");	\
	}	\
} while(0)

/* AGGREGATE_*_STORAGE */
#define AGGREGATE_FLATTEN_GENERIC_STORAGE(FULL_TYPE,SIZE,TARGET,_off,n,CUSTOM_VAL)		\
	do {	\
		DBGM3(AGGREGATE_FLATTEN_GENERIC_STORAGE,FULL_TYPE,_off,n);	\
		DBGS("FULL_TYPE [%lx:%zu -> %lx], size(%zu), n(%ld)\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)((const FULL_TYPE*)((unsigned char*)(_ptr)+_off)),SIZE,n);	\
		flatten_aggregate_generic_storage(FLAT_ACCESSOR, __q, _ptr, SIZE, n, (uintptr_t)(CUSTOM_VAL), _off, TARGET); \
    } while(0)

#define AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(FULL_TYPE, FLSIZE, OFF, CUSTOM_VAL, TARGET)	\
	do {									\
		void* start, *end;					\
		ssize_t el_cnt;						\
											\
		bool rv = flatten_get_object(FLAT_ACCESSOR, (void*)_ptr, &start, &end);	\
		DBGS("flatten_get_object(): %d, start(%lx), end(%lx), size(%zu)\n",rv,start,end,end-start);	\
		if(!rv)								\
			break;							\
											\
		el_cnt = (long)(end - (void*)_ptr - OFF) / FLSIZE;	\
		if(el_cnt <= 0)						\
			break;							\
		AGGREGATE_FLATTEN_GENERIC_STORAGE(FULL_TYPE, FLSIZE, TARGET, OFF, el_cnt, CUSTOM_VAL);	\
	} while(0)

#define AGGREGATE_FLATTEN_GENERIC_COMPOUND_TYPE_STORAGE_FLEXIBLE(T,SIZE,OFF)	\
	do {									\
		void* start, *end;					\
		ssize_t el_cnt;						\
		const T* __p;						\
											\
		bool rv = flatten_get_object(FLAT_ACCESSOR, (void*)_ptr, &start, &end);	\
		if(!rv)								\
			break;							\
											\
		el_cnt = (long)(end - (void*)_ptr - OFF) / SIZE;	\
		if(el_cnt <= 0)						\
			break;							\
		__p = (const T*)((unsigned char*)(_ptr)+OFF);	\
		if (!FLAT_ACCESSOR->error) {	\
			struct flatten_pointer* fptr = flatten_plain_type(FLAT_ACCESSOR,__p,(el_cnt)*SIZE);	\
			if (fptr == NULL) {	\
				DBGS("AGGREGATE_FLATTEN_GENERIC_COMPOUND_TYPE_STORAGE_FLEXIBLE:flatten_plain_type(): NULL");	\
				FLAT_ACCESSOR->error = EFAULT;	\
			}	\
		}	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE(T,f,n)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(struct T, sizeof(struct T), flatten_struct_array_##T, offsetof(_container_type,f), n, 0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE(T,f,n)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(T, sizeof(T), flatten_struct_type_array_##T, offsetof(_container_type,f), n, 0)

#define AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE(T,f,n)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(union T, sizeof(union T), flatten_union_array_##T, offsetof(_container_type,f), n, 0)

#define AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_CUSTOM_INFO(T,f,n,CUSTOM_VAL)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(union T, sizeof(union T), flatten_union_array_##T, offsetof(_container_type,f), n, CUSTOM_VAL)

#define AGGREGATE_FLATTEN_STRUCT_STORAGE(T,f)	\
	AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE(T,f,1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE(T,f)	\
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE(T,f,1)

#define AGGREGATE_FLATTEN_UNION_STORAGE(T,f)	\
	AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE(T,f,1)

#define AGGREGATE_FLATTEN_UNION_STORAGE_CUSTOM_INFO(T,f,CUSTOM_VAL)	\
	AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_CUSTOM_INFO(T,f,1,CUSTOM_VAL)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF,n)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(struct T, SIZE, flatten_struct_array_##T, OFF, n, 0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF,n)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(T, SIZE, flatten_struct_type_array_##T, OFF, n, 0)

#define AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF,n)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(union T, SIZE, flatten_union_array_##T, OFF, n, 0)

#define AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_CUSTOM_INFO_SELF_CONTAINED(T,SIZE,f,OFF,n,CUSTOM_VAL)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(union T, SIZE, flatten_union_array_##T, OFF, n, CUSTOM_VAL)

#define AGGREGATE_FLATTEN_STRUCT_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF)	\
	AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF,1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF)	\
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF,1)

#define AGGREGATE_FLATTEN_UNION_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF)	\
	AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_SELF_CONTAINED(T,SIZE,f,OFF,1)

#define AGGREGATE_FLATTEN_UNION_STORAGE_CUSTOM_INFO_SELF_CONTAINED(T,SIZE,f,OFF,CUSTOM_VAL)	\
	AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_CUSTOM_INFO_SELF_CONTAINED(T,SIZE,f,OFF,1,CUSTOM_VAL)

#define AGGREGATE_FLATTEN_STRUCT_FLEXIBLE(T, f) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(struct T, sizeof(struct T), offsetof(_container_type, f), 0, flatten_struct_array_##T)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE(T, f)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, sizeof(T), offsetof(_container_type, f), 0, flatten_struct_type_array_##T)

#define AGGREGATE_FLATTEN_UNION_FLEXIBLE(T, f)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(union T, sizeof(union T), offsetof(_container_type, f), 0, flatten_union_array_##T)

#define AGGREGATE_FLATTEN_STRUCT_FLEXIBLE_SELF_CONTAINED(T, SIZE, f, OFF) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(struct T, SIZE, OFF, 0, flatten_struct_array_##T)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE_SELF_CONTAINED(T, SIZE, f, OFF) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, SIZE, OFF, 0, flatten_struct_type_array_##T)

#define AGGREGATE_FLATTEN_UNION_FLEXIBLE_SELF_CONTAINED(T, SIZE, f, OFF) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(union T, SIZE, OFF, 0, flatten_union_array_##T)

#define AGGREGATE_FLATTEN_TYPE_ARRAY_FLEXIBLE(T, f)	\
	AGGREGATE_FLATTEN_GENERIC_COMPOUND_TYPE_STORAGE_FLEXIBLE(T,sizeof(T),offsetof(_container_type,f))

#define AGGREGATE_FLATTEN_TYPE_ARRAY_FLEXIBLE_SELF_CONTAINED(T, N, f, OFF)	\
	AGGREGATE_FLATTEN_GENERIC_COMPOUND_TYPE_STORAGE_FLEXIBLE(T,N,OFF)

/* AGGREGATE_* */
#define AGGREGATE_FLATTEN_GENERIC(FULL_TYPE,TARGET,N,f,_off,n,CUSTOM_VAL,pre_f,post_f,_shift)	\
	do {	\
		size_t count = (n);	\
		DBGS("AGGREGATE_FLATTEN_GENERIC(%s, %s, N:0x%zu, off:0x%zu, n:0x%zu)\n", #FULL_TYPE, #f, N, _off, count);	\
		DBGS("  \\-> FULL_TYPE [%lx:%zu -> %lx]\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)OFFATTRN(_off,_shift));	\
		if(((uintptr_t)(pre_f) != 0) || ((uintptr_t)(post_f) != 0))	\
			DBGS("  \\-> PRE_F[%llx]; POST_F[%llx]\n",(uintptr_t)pre_f, (uintptr_t) post_f);	\
		flatten_aggregate_generic(FLAT_ACCESSOR, __q, _ptr, N, count, CUSTOM_VAL, _off, _shift, TARGET, pre_f, post_f); \
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,f,_off,n) \
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, N, f, _off, n, 0, 0, 0, 0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	AGGREGATE_FLATTEN_GENERIC(T, flatten_struct_type_array_##T, N, f, _off, n, 0, 0, 0, 0)

#define AGGREGATE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	AGGREGATE_FLATTEN_GENERIC(union T, flatten_union_array_##T, N, f, _off, n, 0, 0, 0, 0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY(T,f,n)	\
	DBGM3(AGGREGATE_FLATTEN_STRUCT_ARRAY,T,f,n); \
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T, sizeof(struct T), f, offsetof(_container_type, f), n)

#define AGGREGATE_FLATTEN_STRUCT(T,f)				\
	AGGREGATE_FLATTEN_STRUCT_ARRAY(T,f,1)

#define AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(T,N,f,_off) \
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,f,_off,1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(T,N,f,_off) \
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,f,_off,1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(T, f, n) \
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,sizeof(T),f,offsetof(_container_type, f), n)

#define AGGREGATE_FLATTEN_STRUCT_TYPE(T,f)	\
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(T,f,1)

#define AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY(T,f,pre_f,post_f,n)	\
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, sizeof(struct T), f, offsetof(_container_type, f), n, 0, pre_f, post_f, 0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_ARRAY(T,f,pre_f,post_f,n)	\
	AGGREGATE_FLATTEN_GENERIC(T, flatten_struct_type_array_##T, sizeof(T), f, offsetof(_container_type, f), n, 0, pre_f, post_f, 0)

#define AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED(T,N,f,_off,pre_f,post_f,n)	\
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, N, f, _off, n, 0, pre_f, post_f, 0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED(T,N,f,_off,pre_f,post_f,n)	\
	AGGREGATE_FLATTEN_GENERIC(T, flatten_struct_type_array_##T, N, f, _off, n, 0, pre_f, post_f, 0)

#define AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER(T,f,pre_f,post_f)	\
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY(T, f, pre_f, post_f, 1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER(T,f,pre_f,post_f)	\
	AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_ARRAY(T, f, pre_f, post_f, 1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f)	\
	AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED(T, N, f, _off, pre_f, post_f, 1)

#define AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f) \
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED(T, N, f, _off, pre_f, post_f, 1)

/* AGGREGATE_*_EMBEDDED_POINTER */
/* We would probably want the following versions at some point in time as well:
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_EMBEDDED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_EMBEDDED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_EMBEDDED_POINTER_ARRAY
 */

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, N,f,_off,n,0,0,0,_shift)

/* Please note that macro AGGREGATE_FLATTEN_UNION_ARRAY_SELF_CONTAINED_SHIFTED doesn't have much sense in case of a union
    as we cannot point to the middle of the union with a pointer
   Let's keep it here for consistency but don't allow to provide a shift value different than 0
 */
#define AGGREGATE_FLATTEN_UNION_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	AGGREGATE_FLATTEN_ASSERT(_shift==0,EINVAL);	\
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_union_array_##T, N,f,_off,n,0,0,0,0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC(T, flatten_struct_type_array_##T, N,f,_off,n,0,0,0,_shift)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_SHIFTED(T,f,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, sizeof(struct T),f,offsetof(_container_type,f),n,0,0,0,_shift)

#define AGGREGATE_FLATTEN_STRUCT_SHIFTED(T,f,_shift)	\
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, sizeof(struct T),f,offsetof(_container_type,f),1,0,0,0,_shift)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED(T,f,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC(T, flatten_struct_type_array_##T, sizeof(T),f,offsetof(_container_type,f),n,0,0,0,_shift)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_SHIFTED(T,f,_shift)	\
	AGGREGATE_FLATTEN_GENERIC(T, flatten_struct_type_array_##T, sizeof(T),f,offsetof(_container_type,f),1,0,0,0,_shift)

#define AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,pre_f,post_f,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, sizeof(struct T),f,offsetof(_container_type,f),n,0,pre_f,post_f,_shift)	

#define AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SHIFTED(T,f,pre_f,post_f,n,_shift)	\
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED(T, sizeof(struct T), f, offsetof(_container_type, f), pre_f, post_f, n, _shift)

/*******************************
 * AGGERGATE & FLATTEN macros for
 *  generic types
 *******************************/
#define FLATTEN_COMPOUND_TYPE_ARRAY(T,N,p,n)	\
	do {	\
		DBGM4(FLATTEN_COMPOUND_TYPE_ARRAY,T,N,p,n);	\
		if ((!FLAT_ACCESSOR->error)&&(ADDR_RANGE_VALID(p, (n)*N))) {   \
			int err = fixup_set_insert_force_update(FLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_plain_type(FLAT_ACCESSOR,(p),(n)*N));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				FLAT_ACCESSOR->error = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_COMPOUND_TYPE_ARRAY: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_TYPE_ARRAY(T,p,n)  	FLATTEN_COMPOUND_TYPE_ARRAY(T, sizeof(T), p, n)
#define FLATTEN_TYPE(T,p)			FLATTEN_COMPOUND_TYPE_ARRAY(T, sizeof(T), p, 1)

#define FLATTEN_STRING(p)	\
	do {	\
		DBGM1(FLATTEN_STRING,p);	\
		if ((!FLAT_ACCESSOR->error)&&(ADDR_VALID(p))) {   \
			int err = fixup_set_insert_force_update(FLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_plain_type(FLAT_ACCESSOR,(p),STRING_VALID_LEN(p)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				FLAT_ACCESSOR->error = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_STRING: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_FUNCTION_POINTER(p)	\
	do {	\
		DBGM1(FLATTEN_FUNCTION_POINTER,p);	\
		if ((!FLAT_ACCESSOR->error)&&(TEXT_ADDR_VALID(p))) {   \
			int err = fixup_set_insert_fptr_force_update(FLAT_ACCESSOR,__fptr->node,__fptr->offset,(unsigned long)p);	\
			if ((err) && (err!=EEXIST)) {	\
				FLAT_ACCESSOR->error = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_FUNCTION_POINTER: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)p);	\
	} while(0)

#define AGGREGATE_FLATTEN_TYPE_ARRAY(T,f,n)	\
	do {  \
		DBGS("AGGREGATE_FLATTEN_TYPE_ARRAY(%s, %s, n:0x%zu)\n", #T, #f, n);	\
		if ((!FLAT_ACCESSOR->error)&&(ADDR_RANGE_VALID(ATTR(f), (n) * sizeof(T)))) {   \
			size_t _off = offsetof(_container_type,f);	\
			struct flat_node *__node = flat_interval_tree_iter_first(&FLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				FLAT_ACCESSOR->error = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(FLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(FLAT_ACCESSOR,ATTR(f),(n)*sizeof(T)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					FLAT_ACCESSOR->error = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_TYPE_ARRAY: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)ATTR(f));	\
    } while(0)

#define AGGREGATE_FLATTEN_TYPE(T,f)	AGGREGATE_FLATTEN_TYPE_ARRAY(T, f, 1)

#define AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	do {  \
		DBGS("AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(%s, %s, N:0x%zu, off:0x%zu, n:0x%zu)\n", #T, #f, N, _off, n);	\
		DBGS("  \\->OFFATTR[%lx]\n",(uintptr_t)OFFATTR(void*,_off));	\
        if ((!FLAT_ACCESSOR->error)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n) * (N)))) {   \
			struct flat_node *__node = flat_interval_tree_iter_first(&FLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				FLAT_ACCESSOR->error = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(FLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(FLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					FLAT_ACCESSOR->error = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

#define AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(T,f,_off,n) \
	AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(T,sizeof(T),f,_off,n)
#define AGGREGATE_FLATTEN_TYPE_SELF_CONTAINED(T,f,_off) \
	AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(T,sizeof(T),f,_off,1)


#define AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(f,_off)	\
	do {  \
		DBGOF(AGGREGATE_FLATTEN_STRING_SELF_CONTAINED,f,"%lx:%zu",(unsigned long)OFFATTR(const char*,_off),(size_t)_off);	\
        if ((!FLAT_ACCESSOR->error)&&(ADDR_VALID(OFFATTR(void*,_off)))) {   \
			struct flat_node *__node = flat_interval_tree_iter_first(&FLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(char*)-1);    \
			if (__node==0) {	\
				FLAT_ACCESSOR->error = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(FLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(FLAT_ACCESSOR,OFFATTR(const char*,_off),STRING_VALID_LEN(OFFATTR(const char*,_off))));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					FLAT_ACCESSOR->error = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRING_SELF_CONTAINED: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

#define AGGREGATE_FLATTEN_STRING(f)	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(f, offsetof(_container_type,f))

#define AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(f,_off)	\
	do {	\
		DBGOF(AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off);	\
        if ((!FLAT_ACCESSOR->error)&&(TEXT_ADDR_VALID(OFFATTR(void*,_off)))) {   \
			struct flat_node *__node = flat_interval_tree_iter_first(&FLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(int (*)(void))-1);    \
			if (__node==0) {	\
				FLAT_ACCESSOR->error = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_fptr_force_update(FLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						(unsigned long)OFFATTR(void*,_off));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					FLAT_ACCESSOR->error = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)OFFATTR(void*,_off));	\
	} while (0)

#define AGGREGATE_FLATTEN_FUNCTION_POINTER(f) AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(f, offsetof(_container_type,f))

/* For each pointer 'v' (of type 'PTRTYPE') in the array of consecutive pointers in memory do some stuff with it
 * 'p' should actually point to the first element (first pointer) of this array
 * 's' is the size of the array (number of consecutive pointers)
 *  For example, if we have an allocated array of pointers of size 10 and the pointer that points to it:
 *    int** parr = malloc(10*sizeof(int*));
 *    // initialize the pointers in the array
 *  We can write:
 *    FOREACH_POINTER(int*,my_ptr,parr,10,
 *      // Do some stuff with it
 *    );
 *  Beware when you're writing a recipe for an array of pointers inside a structure and you access the member through the offset
 *  In such case it's different whether we have allocated array vs const array
 *    struct X {
 *      int** my_allocated_array; // allocated to 10 elements
 *      int* my_const_array[10];
 *    } *pX;
 *  In the first case the pointer to the first element of the array would be given by:
 *    OFFATTR(int*,offsetof(struct X,my_allocated_array)) -> (*((int**)((unsigned char*)(pX)+offsetof(struct X,my_allocated_array))))
 *  However in the second case we would have one indirection less:
 *    OFFADDR(int*,offsetof(struct X,my_allocated_array)) -> ((int**)((unsigned char*)(pX)+offsetof(struct X,my_const_array)))
 */ 
/* TODO: Use ADDR_RANGE_VALID */
#define FOREACH_POINTER(PTRTYPE,v,p,s,...)	\
	do {	\
		DBGM4(FOREACH_POINTER,PTRTYPE,v,p,s);	\
		if ((!FLAT_ACCESSOR->error)&&(ADDR_VALID(p))) {	\
			PTRTYPE const * _m = (PTRTYPE const *)(p);	\
			size_t _i, _sz = (s);	\
			for (_i=0; _i<_sz; ++_i) {	\
				struct flatten_pointer* __fptr = flatten_plain_type(FLAT_ACCESSOR,_m+_i,sizeof(void*));	\
				if (__fptr) {	\
					PTRTYPE v = *(_m+_i);	\
					__VA_ARGS__;	\
					flat_free(__fptr);	\
				} \
				else {	\
					FLAT_ACCESSOR->error = ENOMEM;	\
					break;	\
				}	\
			}	\
		}	\
		else DBGS("FOREACH_POINTER: error(%d), ADDR(%lx)\n",FLAT_ACCESSOR->error,(uintptr_t)p);	\
	} while(0)

#define FOR_POINTER(PTRTYPE, v, p, ...)	\
	FOREACH_POINTER(PTRTYPE, v, p, 1, __VA_ARGS__)

#define FOR_VIRTUAL_POINTER(p, ...)	\
	do {	\
		DBGM1(FOR_VIRTUAL_POINTER,p);	\
		if ((!FLAT_ACCESSOR->error)&&(ADDR_VALID(p))) {	\
			struct flatten_pointer* __fptr = make_flatten_pointer(FLAT_ACCESSOR,0,0);	\
			if (__fptr) {	\
				__VA_ARGS__;	\
				flat_free(__fptr);	\
			}	\
			else {	\
				FLAT_ACCESSOR->error = ENOMEM;	\
			}	\
		}	\
	} while(0)


/*******************************
 * FLATTEN entry point
 *******************************/
#define FOR_EXTENDED_ROOT_POINTER(p,__name,__size,...)	\
	do {	\
		struct bqueue* __q;	\
		struct flat* flat = FLAT_EXTRACTOR; \
		flat->_root_ptr = (void*)p;	\
		__q = &FLAT_ACCESSOR->bq;	\
		bqueue_clear(__q);	\
					\
		DBGS("FOR_EXTENDED_ROOT_POINTER(%s[%llx], %s, %llx)\n", #p, (uintptr_t)p, __name, __size); \
		if ((!FLAT_ACCESSOR->error)&&(ADDR_VALID(p))) {	\
			struct flatten_pointer* __fptr = make_flatten_pointer(FLAT_ACCESSOR,0,0);	\
			const void* __root_ptr __attribute__((unused)) = (const void*) p;       \
			if (__fptr) {	\
				__VA_ARGS__;	\
				flat_free(__fptr);	\
			}	\
			else {	\
				FLAT_ACCESSOR->error = ENOMEM;	\
			}	\
		}	\
		if (!FLAT_ACCESSOR->error) {	\
			if(__name != NULL)	{ \
				int err = root_addr_append_extended(FLAT_ACCESSOR, (uintptr_t)(p), __name, __size );	\
				if ((err) && (err!=EEXIST))		\
					FLAT_ACCESSOR->error = err;	\
			} else {	\
				FLAT_ACCESSOR->error = root_addr_append(FLAT_ACCESSOR, (uintptr_t)(p) );	\
			}	\
		}	\
			\
		flatten_run_iter_harness(FLAT_ACCESSOR);	\
	} while(0)

#define FOR_ROOT_POINTER(p,...) FOR_EXTENDED_ROOT_POINTER(p, NULL, 0, ##__VA_ARGS__)


#if defined(FLATTEN_KERNEL_BSP)
/*
 * Kernel space memory must not be accessed when using FOR_USER_ROOT_POINTER 
 */
#define FOR_EXTENDED_USER_ROOT_POINTER(p,__name,__size,...) \
    arch_enable_ua(); \
    FOR_EXTENDED_ROOT_POINTER(p,__name,__size,##__VA_ARGS__); \
    arch_disable_ua();

#define FOR_USER_ROOT_POINTER(p,...) FOR_EXTENDED_USER_ROOT_POINTER(p, NULL, 0, ##__VA_ARGS__)
#endif /* defined(FLATTEN_KERNEL_BSP) */



/* Try to detect the size of the heap object pointed to by '__ptr'
 * When successfully detected it returns the size of the object starting from '__ptr' to the end of the object
 * When detection fails returns the value passed in '__dEFAULT_size'
 */
#define FLATTEN_DETECT_OBJECT_SIZE(__ptr,__dEFAULT_size) \
		({			\
			void *__start, *__end;	\
			size_t __deduced_size;	\
			bool rv = flatten_get_object(FLAT_ACCESSOR, __ptr, &__start, &__end);	\
			DBGS("FLATTEN_DETECT_OBJECT_SIZE(%llx, %lld) -> (rv: %d)[from: %llx; to: %llx]\n", __ptr, __dEFAULT_size, rv, __start, __end); \
			__deduced_size = (uintptr_t)__end - (uintptr_t)__ptr + 1;	\
			(rv)?(__deduced_size):(__dEFAULT_size);	\
		})

/* The following dEFAULT macro argument implementation was based on https://stackoverflow.com/a/3048361 */
#define __GET_MACRO_3RD_ARG(a0, a1, a2, ...) a2
#define __GET_MACRO_4TH_ARG(a0, a1, a2, a3, ...) a3

#define __AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(f,__dEFAULT_size) \
	FLATTEN_DETECT_OBJECT_SIZE(ATTR(f),__dEFAULT_size)

#define __AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(f,_off,__dEFAULT_size) \
	FLATTEN_DETECT_OBJECT_SIZE(OFFATTR(void*,_off),__dEFAULT_size)

#define __AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_1_ARG_VARIANT(f)	\
	__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(f,1)
#define __AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_2_ARG_VARIANT(f,__dEFAULT_size)	\
	__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(f,__dEFAULT_size)

#define __AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED_2_ARG_VARIANT(f,_off)	\
	__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(f,_off,1)
#define __AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED_3_ARG_VARIANT(f,_off,__dEFAULT_size)	\
	__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(f,_off,__dEFAULT_size)

#define __CHOOSE_AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_VARIANT(...) \
	__GET_MACRO_3RD_ARG(__VA_ARGS__,	\
		__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_2_ARG_VARIANT,	\
		__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_1_ARG_VARIANT	\
	)
#define __CHOOSE_AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED_VARIANT(...) \
	__GET_MACRO_4TH_ARG(__VA_ARGS__,	\
		__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED_3_ARG_VARIANT,	\
		__AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED_2_ARG_VARIANT	\
	)

#define AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(...)	\
	__CHOOSE_AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_VARIANT(__VA_ARGS__)(__VA_ARGS__)

#define AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(...)	\
	__CHOOSE_AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED_VARIANT(__VA_ARGS__)(__VA_ARGS__)

#endif
