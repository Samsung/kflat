/**
 * @file flatten_impl.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief 
 * @version 0.1
 * @date 2023-05-24
 * 
 * 
 */

#ifndef FLATTEN_IMPL_H
#define FLATTEN_IMPL_H

/*************************************
 * FUNCTION DECLS
 *************************************/
int fixup_set_insert(struct flat* flat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr, enum fixup_encoding flags);
int fixup_set_update(struct flat* flat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr, enum fixup_encoding flags);
struct blstream* binary_stream_append(struct flat* flat, const void* data, size_t size);


#endif /* FLATTEN_IMPL_H */