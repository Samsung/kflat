/* 
 * Samsung R&D Poland - Mobile Security Group
 *  C/C++ library for interacting with kflat images
 */

#include <stdio.h>
#include <stdint.h>


/********************************
 * Exported types
 *******************************/
typedef void* CFlatten;
typedef void* CFlattenHeader;
typedef uintptr_t (*get_function_address_t)(const char* fsym);


/********************************
 * C++ interface
 *******************************/
#ifdef __cplusplus
/**
 * @brief Due to complicated types dependencies, implementation details
 *        of Unflatten class are hidden from end user. Use Flatten wrapper
 *        to conveniently access Unflatten library in applications
 */
class Unflatten;

/**
 * @brief User interface for accessing Unflatten library
 * 
 */
class Flatten {
	class Unflatten* engine;

public:
	/**
	 * @brief construct a new (empty) instance of flatten image
	 * 
	 * @param level: debug level used for printing info 
	 */
	Flatten(int level = 0);

	/**
	 * @brief destroy the Flatten object
	 */
	~Flatten();

	/**
	 * @brief load new kflat image from file. This method can be safely
	 *        called multiple times to load one image after another
	 * 
	 * @param file pointer to opened file with kflat image
	 * @param gfa  optional pointer to function resolving func pointers
	 * @return        0 on success, otherwise error code
	 */
	int load(FILE* file, get_function_address_t gfa = NULL);

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
 * @return CFlatten instance or NULL in case of an error
 */
CFlatten flatten_init(int level);

/**
 * @brief Destroy instance of flatten library
 * 
 * @param flatten library instance
 */
void flatten_deinit(CFlatten flatten);

/**
 * @brief Load new kflat image from file. This method can be safely
 *        called multiple times without need of using flatten_unload
 * 
 * @param flatten library instance
 * @param file    pointer to opened file with kflat image
 * @param gfa     optional pointer to function resolving func pointers
 * @return        0 on success, -1 if an error occurred
 */
int flatten_load(CFlatten flatten, FILE* file, get_function_address_t gfa);

/**
 * @brief Unload kflat image. Normally, there's no need for invoking this
 *        function manually - both flatten_load and flatten_deinit invokes
 *        flatten_unload when necessary
 * 
 * @param flatten library instance
 */
void flatten_unload(CFlatten flatten);

/**
 * @brief Print information about the flattened image
 * 
 * @param flatten library instance
 * @param file    pointer to opened file with kflat image
 */
int flatten_imginfo(CFlatten flatten, FILE* file);

/**
 * @brief Retrieve the pointer to the next flattened object
 * 
 * @param flatten library instance
 * @return        generic pointer to flattened object or NULL if an error occurred
 */
void* flatten_root_pointer_next(CFlatten flatten);

/**
 * @brief Retrieve the pointer to the n-th flattened object
 * 
 * @param flatten library instance
 * @param idx     ID of object to retrieve from image
 * @return        generic pointer to flattened object or NULL if an error occurred
 */
void* flatten_root_pointer_seq(CFlatten flatten, size_t idx);

/**
 * @brief Retrieve the pointer to the named flattened object
 * 
 * @param flatten 	library instance
 * @param name 		name of the object to retrieve
 * @param size[opt]	place where the size of target object will be stored 
 * @return void* 	generic pointer to the named flattened object or NULL
 */
void* flatten_root_pointer_named(CFlatten flatten, const char* name, size_t* size);

/**
 * @brief Retrieve the pointer to the flatten image header structure
 * 
  * @return CFlattenHeader 	generic pointer to the flatten image header structure or NULL
 */
CFlattenHeader flatten_get_image_header(CFlatten flatten);

/**
 * @brief Retrieve the number of fragments in the flatten memory image
 * 
 * @param header 			image header instance
 * @return unsigned long 	number of memory fragments in the image
 */
unsigned long flatten_header_fragment_count(CFlattenHeader header);

/**
 * @brief Retrieve the size of the flatten memory
 * @param header 	image header instance
 * @return size_t 	size of the flatten memory
 */
size_t flatten_header_memory_size(CFlattenHeader header);

#ifdef __cplusplus
}
#endif
