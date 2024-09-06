/*
 * Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 *  C/C++ library for interacting with kflat images
 */

#ifndef UNFLATTEN_HPP
#define UNFLATTEN_HPP

#include <stdio.h>
#include <stdint.h>


/********************************
 * Exported types
 *******************************/
typedef void* CUnflatten;
typedef void* CUnflattenHeader;
typedef uintptr_t (*get_function_address_t)(const char* fsym);

typedef enum {
	// No error
	UNFLATTEN_OK = 0,

	// Invalid root pointer
	UNFLATTEN_INVALID_ROOT_POINTER,

	// Invalid argument
	UNFLATTEN_INVALID_ARGUMENT,

	// Invalid node offset
	UNFLATTEN_INVALID_OFFSET,

	// Invalid magic in read flattened image
	UNFLATTEN_INVALID_MAGIC,

	// Invalid pointer fix location
	UNFLATTEN_INVALID_FIX_LOCATION,

	// Invalid pointer fix destination
	UNFLATTEN_INVALID_FIX_DESTINATION,

	// Address points to an invalid location
	UNFLATTEN_INVALID_ADDRESS_POINTEE,

	// No next root pointer available
	UNFLATTEN_NO_NEXT_ROOT_POINTER,

	// Named root pointer not found
	UNFLATTEN_NOT_FOUND_NAMED_ROOT_POINTER,

	// FLCTRL is uninitialized
	UNFLATTEN_UNINITIALIZED_FLCTRL,

	// Index out of range
	UNFLATTEN_INDEX_OUT_OF_RANGE,

	// Failed to acquire read-lock on input file
	UNFLATTEN_FILE_LOCKED,

	// Unexpected open_mode
	UNFLATTEN_UNEXPECTED_OPEN_MODE,

	// Image size differs from header
	UNFLATTEN_DIFFERENT_IMAGE_SIZE,

	// Size of memory area with header exceeds size of an image
	UNFLATTEN_MEMORY_SIZE_BIGGER_THAN_IMAGE,

	// Memory fragment does not fit in flatten image
	UNFLATTEN_MEMORY_FRAGMENT_DOES_NOT_FIT,

	// Truncated file
	UNFLATTEN_TRUNCATED_FILE,

	// Incompatible version of flattened image
	UNFLATTEN_UNSUPPORTED_MAGIC,

	// Integer overflow
	UNFLATTEN_OVERFLOW,

	// Memory allocation failed
	UNFLATTEN_ALLOCATION_FAILED,

	// Interval extraction failed
	UNFLATTEN_INTERVAL_EXTRACTION_FAILED,

	// Memory was already fixed and is loaded at the same address as previously
	UNFLATTEN_ALREADY_FIXED,
	UNFLATTEN_STATUS_MAX,
} UnflattenStatus;

/********************************
 * C++ interface
 *******************************/
#ifdef __cplusplus
/**
 * @brief Due to complicated types dependencies, implementation details
 *        of UnflattenEngine class are hidden from end user. Use Flatten
 *        wrapper to conveniently access UnflattenEngine library in applications
 */
class UnflattenEngine;

/**
 * @brief User interface for accessing UnflattenEngine library
 * 
 */
class Unflatten {
	class UnflattenEngine* engine;

public:
	/**
	 * @brief construct a new (empty) instance of flatten image
	 * 
	 * @param level: debug level used for printing info 
	 */
	Unflatten(int level = 0);

	/**
	 * @brief destroy the Unflatten object
	 */
	~Unflatten();

	/**
	 * @brief load new kflat image from file. This method can be safely
	 *        called multiple times to load one image after another
	 * 
	 * @param file pointer to opened file with kflat image
	 * @param gfa  optional pointer to function resolving func pointers
	 * @param continuous_mapping whether to allocate dumped memory as one huge blob
	 * 			or as many small malloc objects (second variant is slower, but allows
	 * 			for detection of buffer overflows with ASAN)
	 * @return        0 on success, otherwise error code
	 */
	UnflattenStatus load(FILE* file, get_function_address_t gfa = NULL, bool continuous_mapping = false);

	/**
	 * @brief Provides information regarding kflat image file
	 *
	 * @param file pointer to opened file with kflat image
	 * @param arg  optional parameter to decide whith kflat image part information to provide
	 * @return        0 on success, otherwise error code
	 */
	UnflattenStatus info(FILE* file, const char* arg = 0);

	/**
	 * @brief free memory occupied by loaded image. Normally, there's no need
	 *        to invoke this function manually (both destructor and load()) calls
	 *        it already
	 */
	void unload();

	/**
	 * @brief Mark pointer as freed by some external code. This prevents double frees when image is unloaded.
	 * 
	 * @param mptr already freed pointer
	 */
	void mark_freed(void *mptr);

	/**
	 * @brief retrieve the pointer to the next flattened object
	 * 
	 * @return generic pointer to flattened object
	 */
	void* get_next_root(void);

	/**
	 * @brief retrieve the pointer to the n-th flattened object
	 * 
	 * @param idx ID of the object to retrieve from image
	 * @return generic pointer to requested flattened object
	 */
	void* get_seq_root(size_t idx);

	/**
	 * @brief retrieve named root pointer
	 * 
	 * @param name the name of root pointer provided to EXTENDED_ROOT_POINTER macro
	 * @param size[opt] place where size of flattened object will be stored
	 * @return generic pointer to named object or NULL in case of an error
	 */
	void* get_named_root(const char* name, size_t* size);

	/**
	 * @brief Replace all pointers to the provided memory range with a new variable. It can be
	 * 	used to replace global variable from image with local copy
	 *
	 * @param old_mem 	pointer to old memory
	 * @param new_mem 	pointer to new memory
	 * @param size 		size of memory chunked to be replaced
	 * @return ssize_t  number of chunkes replaced or negative value in case of an error
	 */
	ssize_t replace_variable(void* old_mem, void* new_mem, size_t size);

	/**
	 * @brief Provide description of a given status code
	 *
	 * @param  status status code
	 * @return status string description
	 */
	static const char *explain_status(UnflattenStatus status);
};

extern "C" {
#endif


/********************************
 * C interface
 *******************************/

/**
 * @brief Create a new instance of flatten library
 * 
 * @param level log level
 * @return CUnflatten instance or NULL in case of an error
 */
CUnflatten unflatten_init(int level);

/**
 * @brief Destroy instance of flatten library
 * 
 * @param flatten library instance
 */
void unflatten_deinit(CUnflatten flatten);

/**
 * @brief Load new kflat image from file. This method can be safely
 *        called multiple times without need of using unflatten_unload
 *
 * @param flatten library instance
 * @param file    pointer to opened file with kflat image
 * @param gfa     optional pointer to function resolving func pointers
 * @return        0 on success, any other values indicate an error
 */
UnflattenStatus unflatten_load(CUnflatten flatten, FILE* file, get_function_address_t gfa);

/**
 * @brief Load new kflat image from file. Works as unflatten_load except that
 * 		  loaded image will be stored as one continous blob in memory. Should
 * 		  provide better performance, but ASAN won't be able to detect overflows
 * 		  in such memory dump.
 *
 * @param flatten library instance
 * @param file    pointer to opened file with kflat image
 * @param gfa     optional pointer to function resolving func pointers
 * @return        0 on success, any other values indicate an error
 */
UnflattenStatus unflatten_load_continuous(CUnflatten flatten, FILE* file, get_function_address_t gfa);

/**
 * @brief Unload kflat image. Normally, there's no need for invoking this
 *        function manually - both unflatten_load and unflatten_deinit invokes
 *        unflatten_unload when necessary
 *
 * @param flatten library instance
 */
void unflatten_unload(CUnflatten flatten);

/**
 * @brief Print information about the flattened image
 *
 * @param flatten library instance
 * @param file    pointer to opened file with kflat image
 * @return        0 on success, any other values indicate an error
 */
UnflattenStatus unflatten_imginfo(CUnflatten flatten, FILE* file);

/**
 * @brief Retrieve the pointer to the next flattened object
 *
 * @param flatten library instance
 * @return        generic pointer to flattened object or NULL if an error occurred
 */
void* unflatten_root_pointer_next(CUnflatten flatten);

/**
 * @brief Retrieve the pointer to the n-th flattened object
 * 
 * @param flatten library instance
 * @param idx     ID of object to retrieve from image
 * @return        generic pointer to flattened object or NULL if an error occurred
 */
void* unflatten_root_pointer_seq(CUnflatten flatten, size_t idx);

/**
 * @brief Retrieve the pointer to the named flattened object
 * 
 * @param flatten 	library instance
 * @param name 		name of the object to retrieve
 * @param size[opt]	place where the size of target object will be stored 
 * @return void* 	generic pointer to the named flattened object or NULL
 */
void* unflatten_root_pointer_named(CUnflatten flatten, const char* name, size_t* size);

/**
 * @brief Mark pointer as freed by some external code. This prevents double frees when image is unloaded.
 * 
 * @param flatten library instance
 * @param mptr already freed pointer
 */
void unflatten_mark_freed(CUnflatten flatten, void *mptr);

/**
 * @brief Retrieve the pointer to the flatten image header structure
 * 
  * @return CUnflattenHeader 	generic pointer to the flatten image header structure or NULL
 */
CUnflattenHeader unflatten_get_image_header(CUnflatten flatten);

/**
 * @brief Retrieve the number of fragments in the flatten memory image
 * 
 * @param header 			image header instance
 * @return unsigned long 	number of memory fragments in the image
 */
unsigned long unflatten_header_fragment_count(CUnflattenHeader header);

/**
 * @brief Retrieve the size of the flatten memory
 * @param header 	image header instance
 * @return size_t 	size of the flatten memory
 */
size_t unflatten_header_memory_size(CUnflattenHeader header);

/**
 * @brief Replace all pointers to the provided memory range with new variable. It can be
 * 	used to replace global variable from image with local copy
 *
 * @param flatten 	library instance
 * @param old_mem 	pointer to old memory
 * @param new_mem 	pointer to new memory
 * @param size 		size of memory chunked to be replaced
 * @return ssize_t  number of chunkes replaced or negative value in case of an error
 */
ssize_t unflatten_replace_variable(CUnflatten flatten, void* old_mem, void* new_mem, size_t size);

/**
 * @brief Provide description of a given status code
 *
 * @param  status status code
 * @return status string description
 */
const char *unflatten_explain_status(UnflattenStatus status);

#ifdef __cplusplus
}
#endif
#endif /* UNFLATTEN_HPP */
