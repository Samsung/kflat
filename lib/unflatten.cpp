/* 
 * Samsung R&D Poland - Mobile Security Group
 *  C/C++ library for interacting with kflat images
 */

#include <cassert>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <sys/time.h>

#include <map>
#include <vector>
#include <string>
#include <stdexcept>

#include "unflatten.hpp"

#define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

extern "C" {
#include "interval_tree_generic.h"
}

/********************************
 * Private data types
 *******************************/

struct interval_tree_node {
	struct rb_node rb;
	uintptr_t start;	/* Start of interval */
	uintptr_t last;	/* Last location _in_ interval */
	uintptr_t __subtree_last;
	void* mptr;
};

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST, __attribute__((used)), interval_tree)



struct flatten_header {
	size_t image_size;
	size_t memory_size;
	size_t ptr_count;
	size_t fptr_count;
	size_t root_addr_count;
	size_t root_addr_extended_count;
	size_t root_addr_extended_size;
	uintptr_t this_addr;
	size_t fptrmapsz;
	size_t mcount;
	uint64_t magic;
};

struct root_addrnode {
	struct root_addrnode* next;
	uintptr_t root_addr;
	const char* name;
	size_t index;
	size_t size;
};

struct FLCONTROL {
	struct rb_root_cached fixup_set_root;
	struct rb_root_cached imap_root;
	struct flatten_header HDR;
	struct root_addrnode* rhead;
	struct root_addrnode* rtail;
	struct root_addrnode* last_accessed_root;
	size_t root_addr_count;
	void* mem;
	std::map<std::string, uintptr_t> root_addr_map;
};

typedef uintptr_t (*get_function_address_t)(const char* fsym);


/********************************
 * Private class Unflatten
 *******************************/
class Unflatten {
private:
	constexpr static uint64_t FLATTEN_MAGIC = 0x464c415454454e00ULL;

	bool need_unload;
	enum {
		LOG_NONE = 0,
		LOG_INFO = 1,
		LOG_DEBUG,
	} loglevel;
	size_t readin;
	struct FLCONTROL FLCTRL;
	std::map<uintptr_t,std::string> fptrmap;
	struct timeval timeS;

	void* flatten_memory_start() {
		return (char*) FLCTRL.mem + \
				FLCTRL.HDR.ptr_count * sizeof(size_t) +  \
				FLCTRL.HDR.fptr_count * sizeof(size_t) + \
				FLCTRL.HDR.mcount * 2 * sizeof(size_t);
	}

	void time_mark_start() {
		gettimeofday(&timeS, NULL);
	}

	double time_elapsed() {
		struct timeval timeE;
		gettimeofday(&timeE, NULL);

		return (double)(timeE.tv_sec - timeS.tv_sec) + (timeE.tv_usec - timeS.tv_usec) / 1000000;
	}

	/***************************
	 * LIMITED LOGGING
	 **************************/
	void debug(const char* fmt, ...) {
		va_list args;
		if(loglevel < LOG_DEBUG)
			return;

		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		va_end(args);
	}

	void info(const char* fmt, ...) {
		va_list args;
		if(loglevel < LOG_INFO)
			return;

		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		va_end(args);
	}

	/***************************
	 * ROOT POINTERS
	 **************************/
	void* root_pointer_next() {
		assert(FLCTRL.rhead != NULL);
		
		if (FLCTRL.last_accessed_root == NULL)
			FLCTRL.last_accessed_root = FLCTRL.rhead;
		else if (FLCTRL.last_accessed_root->next)
			FLCTRL.last_accessed_root = FLCTRL.last_accessed_root->next;
		else
			assert(0);

		struct root_addrnode* last_root = FLCTRL.last_accessed_root;
		if (last_root->root_addr == (size_t) -1)
			return 0;

		if (interval_tree_iter_first(&FLCTRL.imap_root, 0, ULONG_MAX)) {	
			/* We have allocated each memory fragment individually */
			struct interval_tree_node *node = interval_tree_iter_first(
					&FLCTRL.imap_root,
					last_root->root_addr,
					last_root->root_addr + 8);
			assert(node != NULL);

			size_t node_offset = last_root->root_addr - node->start;
			return (char*)node->mptr + node_offset;
		}
		
		return (char*)flatten_memory_start() + last_root->root_addr;
	}

	void* root_pointer_seq(size_t index) {
		assert(FLCTRL.rhead != NULL);

		FLCTRL.last_accessed_root = FLCTRL.rhead;
		for (size_t i = 0; i < index; ++i) {
			if (FLCTRL.last_accessed_root->next)
				FLCTRL.last_accessed_root = FLCTRL.last_accessed_root->next;
			else
				assert(0);
		}

		if (FLCTRL.last_accessed_root->root_addr == (size_t) -1)
			return 0;

		if (interval_tree_iter_first(&FLCTRL.imap_root, 0, ULONG_MAX)) {	
			/* We have allocated each memory fragment individually */
			struct interval_tree_node *node = interval_tree_iter_first(
					&FLCTRL.imap_root,
					FLCTRL.last_accessed_root->root_addr,
					FLCTRL.last_accessed_root->root_addr + 8);
			assert(node != NULL);

			size_t node_offset = FLCTRL.last_accessed_root->root_addr - node->start;
			return (char*)node->mptr + node_offset;
		}

		return (char*)flatten_memory_start() + FLCTRL.last_accessed_root->root_addr;
	}

	void root_addr_append(uintptr_t root_addr) {
		struct root_addrnode* v = (struct root_addrnode*)calloc(1, sizeof(struct root_addrnode));
		assert(v != NULL);
		v->root_addr = root_addr;
		if (!FLCTRL.rhead) {
			FLCTRL.rhead = v;
			FLCTRL.rtail = v;
		}
		else {
			FLCTRL.rtail->next = v;
			FLCTRL.rtail = FLCTRL.rtail->next;
		}
		FLCTRL.root_addr_count++;
	}

	int root_addr_append_extended(size_t root_addr, const char* name, size_t size) {
		if (FLCTRL.root_addr_map.find(name) != FLCTRL.root_addr_map.end())
			return EEXIST;

		struct root_addrnode* v = (struct root_addrnode*)calloc(1, sizeof(struct root_addrnode));
		assert(v != NULL);
		v->root_addr = root_addr;
		v->name = name;
		v->index = FLCTRL.root_addr_count;
		v->size = size;
		if (!FLCTRL.rhead) {
			FLCTRL.rhead = v;
			FLCTRL.rtail = v;
		}
		else {
			FLCTRL.rtail->next = v;
			FLCTRL.rtail = FLCTRL.rtail->next;
		}
		FLCTRL.root_addr_count++;
		
		FLCTRL.root_addr_map.insert(std::pair<std::string,uintptr_t>(name,root_addr));
		return 0;
	}

	/***************************
	 * UNFLATTEN MEMORY
	 **************************/
	void read_file(void* dst, size_t size, size_t n, FILE* f) {
		size_t rd;

		rd = fread(dst, size, n, f);
		if(rd != n)
			throw std::invalid_argument("Truncated file");
		readin += sizeof(struct flatten_header);
	}
	

public:
	Unflatten(int _level = LOG_NONE) {
		memset(&FLCTRL, 0, sizeof(FLCTRL));
		need_unload = false;
		loglevel = (typeof(loglevel))_level;
	}

	int load(FILE* f, get_function_address_t gfa = NULL) {
		if(need_unload)
			unload();
		readin = 0;

		time_mark_start();
		read_file(&FLCTRL.HDR, sizeof(struct flatten_header), 1, f);
		if (FLCTRL.HDR.magic != FLATTEN_MAGIC)
			throw std::invalid_argument("Invalid magic while reading flattened image");

		std::vector<uintptr_t> root_ptr_vector;
		for (size_t i = 0; i < FLCTRL.HDR.root_addr_count; ++i) {
			size_t root_addr_offset;
			read_file(&root_addr_offset, sizeof(size_t), 1, f);
			root_ptr_vector.push_back(root_addr_offset);
			debug(" * root_addr: %lx\n", root_addr_offset);
		}

		std::map<size_t,std::pair<std::string,size_t>> root_ptr_ext_map;
		for (size_t i = 0; i < FLCTRL.HDR.root_addr_extended_count; ++i) {
			size_t name_size, index, size;
			read_file(&name_size,sizeof(size_t),1,f);
			
			char* name = new char[name_size];
			try {
				read_file((void*)name, name_size, 1, f);
				read_file(&index, sizeof(size_t), 1, f);
				read_file(&size, sizeof(size_t), 1, f);
				root_ptr_ext_map.insert({index, {std::string(name), size}});
			} catch(...) {
				delete[] name;
				throw;
			}
			delete[] name;
		}

		for (size_t i = 0; i < root_ptr_vector.size(); ++i) {
			if (root_ptr_ext_map.find(i) != root_ptr_ext_map.end())
				root_addr_append_extended(i, root_ptr_ext_map[i].first.c_str(), root_ptr_ext_map[i].second);
			else
				root_addr_append(root_ptr_vector[i]);
		}

		size_t memsz = FLCTRL.HDR.memory_size + \
						FLCTRL.HDR.ptr_count * sizeof(size_t) + \
						FLCTRL.HDR.fptr_count * sizeof(size_t) + \
						FLCTRL.HDR.mcount * 2 * sizeof(size_t);
		FLCTRL.mem = malloc(memsz);
		assert(FLCTRL.mem != NULL);

		read_file(FLCTRL.mem, 1, memsz, f);
		if (FLCTRL.HDR.fptr_count > 0 && FLCTRL.HDR.fptrmapsz > 0 && gfa) {
			char* fptrmapmem = (char*) malloc(FLCTRL.HDR.fptrmapsz);
			assert(fptrmapmem != NULL);

			read_file(fptrmapmem, 1, FLCTRL.HDR.fptrmapsz, f);
			size_t fptrnum = *((size_t*)fptrmapmem);
			fptrmapmem += sizeof(size_t);

			for (size_t kvi=0; kvi < fptrnum; ++kvi) {
				uintptr_t addr = *((uintptr_t*)fptrmapmem);
				fptrmapmem += sizeof(uintptr_t);

				size_t sz = *((size_t*)fptrmapmem);
				fptrmapmem += sizeof(size_t);

				std::string sym((const char*)fptrmapmem, sz);
				fptrmapmem += sz;
				fptrmap.insert(std::pair<uintptr_t,std::string>(addr, sym));
			}
			free(fptrmapmem - FLCTRL.HDR.fptrmapsz);
		}
		
		info(" #Unflattening done\n");
		info(" #Image read time: %lfs\n", time_elapsed());

		time_mark_start();
		size_t* minfoptr = (size_t*)((char*)FLCTRL.mem + FLCTRL.HDR.ptr_count * sizeof(size_t) + FLCTRL.HDR.fptr_count * sizeof(size_t));
		void* memptr = flatten_memory_start();
		info(" * memory size: %lu\n", FLCTRL.HDR.memory_size);
	 	debug("[ ");
	 	for (size_t i = 0; i < FLCTRL.HDR.memory_size; ++i)
	 		debug("%02x ",*((unsigned char*)memptr + i));
	 	debug("]\n");

		for (size_t i = 0; i < FLCTRL.HDR.mcount; ++i) {
			size_t index = *minfoptr++;
			size_t size = *minfoptr++;
			struct interval_tree_node *node = (struct interval_tree_node*)calloc(1, sizeof(struct interval_tree_node));
			node->start = index;
			node->last = index + size - 1;
			void* fragment = malloc(size);
			assert(fragment!=NULL);
			memcpy(fragment, (char*)memptr + index, size);
			node->mptr = fragment;
			interval_tree_insert(node, &FLCTRL.imap_root);
		}
		info(" #Creating memory time: %lfs\n", time_elapsed());

		time_mark_start();
		unsigned long fix_count = 0;
		for (size_t i = 0; i < FLCTRL.HDR.ptr_count; ++i) {
			void* mem = flatten_memory_start();
			size_t fix_loc = *((size_t*)FLCTRL.mem + i);
			debug("fix_loc: %zu\n",fix_loc);

			struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root, fix_loc, fix_loc + 8);
			assert(node != NULL);

			size_t node_offset = fix_loc-node->start;
			uintptr_t ptr = (uintptr_t)( *((void**)((char*)mem + fix_loc)) );
			struct interval_tree_node *ptr_node = interval_tree_iter_first(&FLCTRL.imap_root, ptr, ptr + 8);
			assert(ptr_node != NULL);

			/* Make the fix */
			size_t ptr_node_offset = ptr-ptr_node->start;
			*((void**)((char*)node->mptr + node_offset)) = (char*)ptr_node->mptr + ptr_node_offset;

			debug("%lx <- %lx (%lx)\n", fix_loc, ptr, *(unsigned long*)((char*)ptr_node->mptr + ptr_node_offset));
			fix_count++;
		}

		if (FLCTRL.HDR.fptr_count > 0 && gfa) {
			for (size_t fi = 0; fi < FLCTRL.HDR.fptr_count; ++fi) {
				size_t fptri = ((uintptr_t*)((char*)FLCTRL.mem + FLCTRL.HDR.ptr_count * sizeof(size_t)))[fi];
				struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root, fptri, fptri + 8);
				assert(node != NULL);

				size_t node_offset = fptri-node->start;
				uintptr_t fptrv = *((uintptr_t*)((char*)node->mptr + node_offset));
				if (fptrmap.find(fptrv) != fptrmap.end()) {
					// Fix function pointer
					uintptr_t nfptr = (*gfa)(fptrmap[fptrv].c_str());
					*((void**)((char*)node->mptr + node_offset)) = (void*)nfptr;
				}
			}
		}
		info(" #Fixing memory time: %lfs\n", time_elapsed());
		info("  Total bytes read: %zu\n", readin);
		info("  Number of allocated fragments: %zu\n", FLCTRL.HDR.mcount);
		info("  Number of fixed pointers: %lu\n", fix_count);

		need_unload = true;
		return 0;
	}

	void unload(void) {
		FLCTRL.rtail = FLCTRL.rhead;
		while(FLCTRL.rtail) {
			struct root_addrnode* p = FLCTRL.rtail;
			FLCTRL.rtail = FLCTRL.rtail->next;
			free(p);
		}
		free(FLCTRL.mem);
		fptrmap.clear();

		// TODO: clear interval tree nodes and memory fragments

		need_unload = false;
	}

	void* get_next_root(void) {
		return root_pointer_next();
	}

	void* get_seq_root(size_t idx) {
		return root_pointer_seq(idx);
	}

	~Unflatten() {
		if(need_unload)
			unload();
	}
};

/********************************
 * C++ API
 *******************************/
Flatten::Flatten(int level) {
	engine = new Unflatten(level);
}

Flatten::~Flatten() {
	delete engine;
}

int Flatten::load(FILE* file, get_function_address_t gfa) {
	return engine->load(file, gfa);
}

void Flatten::unload() {
	engine->unload();
}

void* Flatten::get_next_root() {
	return engine->get_next_root();
}

void* Flatten::get_seq_root(size_t idx) {
	return engine->get_seq_root(idx);
}

/********************************
 * C Wrappers
 *******************************/
CFlatten flatten_init(int level) {
	CFlatten flatten;
	try {
		flatten = new Unflatten(level);
	} catch(...) {
		return NULL;
	}
	return flatten;
}

void flatten_deinit(CFlatten flatten) {
	try {
		if(flatten != NULL)
			delete (Unflatten*)flatten;
	} catch(...) {
		return;
	}
}

int flatten_load(CFlatten flatten, FILE* file, get_function_address_t gfa) {
	try {
		return ((Unflatten*)flatten)->load(file, gfa);
	} catch(...) {
		return -1;
	}
}

void flatten_unload(CFlatten flatten) {
	try {
		((Unflatten*)flatten)->unload();
	} catch(...) {
		return;
	}
}

void* flatten_root_pointer_next(CFlatten flatten) {
	try {
		return ((Unflatten*)flatten)->get_next_root();
	} catch(...) {
		return NULL;
	}
}

void* flatten_root_pointer_seq(CFlatten flatten, size_t idx) {
	try {
		return ((Unflatten*)flatten)->get_seq_root(idx);
	} catch(...) {
		return NULL;
	}
}
