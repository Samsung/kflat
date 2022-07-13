/* 
 * Samsung R&D Poland - Mobile Security Group
 *  C/C++ library for interacting with kflat images
 */

#include <stdio.h>

typedef void* CFlatten;
typedef uintptr_t (*get_function_address_t)(const char* fsym);

#ifdef __cplusplus
class Unflatten;

class Flatten {
private:
	class Unflatten* engine;

public:
	Flatten(int level = 0);
	~Flatten();
	int load(FILE* file, get_function_address_t gfa = NULL);
	void unload();
    void* get_next_root(void);
    void* get_seq_root(size_t idx);
};

extern "C" {
#endif

CFlatten flatten_init(int level);
void flatten_deinit(CFlatten flatten);
int flatten_load(CFlatten flatten, FILE* file, get_function_address_t gfa);
void flatten_unload(CFlatten flatten);
void* flatten_root_pointer_next(CFlatten flatten);
void* flatten_root_pointer_seq(CFlatten flatten, size_t idx);

#ifdef __cplusplus
}
#endif
