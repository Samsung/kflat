/* 
 * Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 *  C/C++ library for interacting with kflat images
 */

#include <stdio.h>
#include <stdint.h>


/********************************
 * Exported types
 *******************************/
typedef void* CUnflatten;
typedef void* CUnflattenHeader;
typedef uintptr_t (*get_function_address_t)(const char* fsym);


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
	int load(FILE* file, get_function_address_t gfa = NULL, bool continuous_mapping = false);

	/**
	 * @brief Provides information regarding kflat image file
	 *
	 * @param file pointer to opened file with kflat image
	 * @param arg  optional parameter to decide whith kflat image part information to provide
	 * @return        0 on success, otherwise error code
	 */
	int info(FILE* file, const char* arg = 0);

	/**
	 * @brief free memory occupied by loaded image. Normally, there's no need
	 *        to invoke this function manually (both destructor and load()) calls
	 *        it already
	 */
	void unload();

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
 * @return        0 on success, -1 if an error occurred
 */
int unflatten_load(CUnflatten flatten, FILE* file, get_function_address_t gfa);

/**
 * @brief Load new kflat image from file. Works as unflatten_load except that
 * 		  loaded image will be stored as one continous blob in memory. Should
 * 		  provide better performance, but ASAN won't be able to detect overflows
 * 		  in such memory dump.
 * 
 * @param flatten library instance
 * @param file    pointer to opened file with kflat image
 * @param gfa     optional pointer to function resolving func pointers
 * @return        0 on success, -1 if an error occurred
 */
int unflatten_load_continuous(CUnflatten flatten, FILE* file, get_function_address_t gfa);

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
 */
int unflatten_imginfo(CUnflatten flatten, FILE* file);

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

#ifdef __cplusplus
}
#endif
