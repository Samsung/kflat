/* 
 * Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 *  C/C++ library for interacting with kflat images
 */

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <unistd.h>

#include <map>
#include <vector>
#include <memory>
#include <string>
#include <stdexcept>
#include <set>
#include <unordered_set>

#include "unflatten.hpp"

#define container_of(ptr, type, member) ({			\
  	const __typeof__( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

extern "C" {
#include "interval_tree_generic.h"
#include <flatten_image.h>
}

#ifdef __has_builtin
	#if __has_builtin(__builtin_uaddl_overflow)
		#define __SUPPORTS_BUILTIN_UADDL_OVERFLOW
	#endif
	#if __has_builtin(__builtin_umull_overflow)
		#define __SUPPORTS_BUILTIN_UMULL_OVERFLOW
	#endif
#endif

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

#define WITHIN_MEM_BOUNDS(ptr_, type_) ((char *)(ptr_) >= (char *)FLCTRL.mem && (char *)(ptr_) + sizeof(type_) < (char *)FLCTRL.mem + get_memsz())

INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST, __attribute__((used)), interval_tree)

struct root_addr_node {
	uintptr_t root_addr;
	const char* name;
	size_t size;
};

#define COLOR_STRING_RED "\033[0;31m"
#define COLOR_STRING COLOR_STRING_RED
#define COLOR_OFF "\033[0m"

/********************************
 * Private class UnflattenEngine
 *******************************/
class UnflattenEngine {
private:
	friend class Unflatten;

	bool need_unload;
	enum {
		LOG_NONE = 0,
		LOG_INFO = 1,
		LOG_DEBUG,
	} loglevel;
	size_t readin;
	
	struct FLCONTROL {
		struct flatten_header HDR;

		struct rb_root_cached imap_root;
		void* mem;
		bool is_continous_mode;

		ssize_t last_accessed_root;
		std::vector<struct root_addr_node> root_addr;
	} FLCTRL;

	std::map<std::string, std::pair<size_t, size_t>> root_addr_map;
	std::map<uintptr_t,std::string> fptrmap;
	std::unordered_set<void *> already_freed;
	
	struct timeval timeS;

	/***************************
	 * UTILITIES / MISC
	 **************************/
	inline void* flatten_memory_start() const {
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

		return (double)(timeE.tv_sec - timeS.tv_sec) + (timeE.tv_usec - timeS.tv_usec) / 1000000.0;
	}

	inline bool check_mul_overflow(size_t variable, size_t mul) const noexcept {
	#if defined(__SUPPORTS_BUILTIN_UMULL_OVERFLOW)
		size_t tmp;
		return __builtin_umull_overflow(variable, mul, &tmp);
	#elif defined(__SIZEOF_INT128__)
		__uint128_t result = (__uint128_t)variable * (__uint128_t)mul;
		return (result >> 64) != 0;
	#else
		size_t result = variable * mul;
		return variable != 0 && result / variable != mul;
	#endif
	}

	inline bool add_overflow(size_t a, size_t b, size_t* result) const noexcept {
	#if defined(__SUPPORTS_BUILTIN_UADDL_OVERFLOW)
		return __builtin_uaddl_overflow(a, b, result);
	#else
		size_t tmp = a + b;
		if(tmp < a)
			return true;
		*result = tmp;
		return false;
	#endif
	}

	/***************************
	 * LIMITED LOGGING
	 **************************/
	inline void debug(const char* fmt, ...) const {
		va_list args;
		if(loglevel < LOG_DEBUG)
			return;

		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		va_end(args);
	}

	inline void info(const char* fmt, ...) const {
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
	inline void* get_root_addr_mem(uintptr_t root_addr) {
		if (root_addr == (size_t) -1)
			return 0;

		if (interval_tree_iter_first(&FLCTRL.imap_root, 0, ULONG_MAX)) {	
			/* We have allocated each memory fragment individually */
			struct interval_tree_node *node = interval_tree_iter_first(
					&FLCTRL.imap_root,
					root_addr, root_addr + 8);
			if (node == NULL)
				throw std::invalid_argument("Invalid root pointer");

			size_t node_offset = root_addr - node->start;
			return (char*)node->mptr + node_offset;
		}
		
		return (char*)flatten_memory_start() + root_addr;
	}

	void* root_pointer_next() {
		if(FLCTRL.last_accessed_root >= (ssize_t)FLCTRL.root_addr.size() - 1)
			throw std::invalid_argument("No next root pointer available");
		FLCTRL.last_accessed_root++;
		
		struct root_addr_node* last_root = &FLCTRL.root_addr[FLCTRL.last_accessed_root];
		return (void*)last_root->root_addr;
	}

	void* root_pointer_seq(size_t index) {
		if(index >= FLCTRL.root_addr.size())
			throw std::invalid_argument("Index out-of-range for root pointer arrays");
		FLCTRL.last_accessed_root = index;

		struct root_addr_node* last_root = &FLCTRL.root_addr[FLCTRL.last_accessed_root];
		return (void*)last_root->root_addr;
	}

	void* root_pointer_named(const char* name, size_t* size) {
		size_t root_addr;

		try {
			auto& entry = root_addr_map.at(name);
			
			if(size)
				*size = entry.second;
			root_addr = entry.first;
		} catch(std::out_of_range& _) {
			return NULL;
		}

		return (void*)root_addr;
	}

	void root_addr_append(uintptr_t root_addr, const char* name = nullptr, size_t size = 0) {
		struct root_addr_node v {
			.root_addr = root_addr,
			.name = name,
			.size = size
		};
		FLCTRL.root_addr.push_back(v);
	}

	int root_addr_append_extended(size_t root_addr, const char* name, size_t size) {
		if (root_addr_map.find(name) != root_addr_map.end())
			return EEXIST;

		root_addr_append(root_addr, name, size);
		root_addr_map.insert({name, {root_addr, size}});
		return 0;
	}

	void fix_root_pointers(void) {
		for(auto& root_ptr : FLCTRL.root_addr)
			root_ptr.root_addr = (uintptr_t) get_root_addr_mem(root_ptr.root_addr);
		for(auto& [name, entry] : root_addr_map)
			entry.first = (uintptr_t) get_root_addr_mem(entry.first);
	}

	/***************************
	 * I/O ACCESS
	 **************************/
	enum open_mode_enum {
		UNFLATTEN_OPEN_MMAP,
		UNFLATTEN_OPEN_READ_COPY,
		UNFLATTEN_OPEN_MMAP_WRITE,
	} open_mode;
	int opened_file_fd;
	struct {
		FILE* opened_file_file;

		struct {
			void* opened_mmap_addr;
			size_t opened_mmap_size;
		};
	};
	int current_mmap_offset;

	/**
	 * @brief Main logic behind opening flatten image. Currently we support 3 different
	 *   open modes:
	 *     - OPEN_MMAP -> mmap input file into current VA as MAP_PRIVATE (COW)
	 *     - OPEN_MMAP_WRITE -> mmap input file into current VA as MAP_SHARED (changes
	 *         to mapped memory affects the underlying file)
	 *     - OPEN_READ_COPY -> load full flatten image as a copy into our VA
	 *   Furthermore, we handle 3 FCNTL file-lock states:
	 *     - O_UNLCK -> no one is using flatten image - we can do whatever we want with it
	 *     - O_RDLCK -> flatten image is locked for READ - we cannot edit it
	 *     - O_WRLCK -> flatten image is locked for WRITE - we cannot use it at all
	 * 
	 *   The idea behind this modes is as follow:
	 *     1) After dumping memory, all pointers in flatten image are offsets in blob
	 *     2) The first running instance of Unflatten library obtains O_WRLCK lock and opens
	 *        file in OPEN_MMAP_WRITE mode. Next, it replaces all offsets in flatten image with
	 *        valid pointers in current mapping and saves mapping base in flatten header (last_load_addr)
	 *     3) The next running instance of Unflatten lib obtains O_RDLCK and maps flatten image
	 *        at the same address as the first instance did - if it succeed, memory can be used
	 *        without any further modifications (pointers are still valid), if not:
	 *     4) Lock O_RDLCK, open file in OPEN_READ_COPY, copy it into local memory, fix locally 
	 *         and release O_RDLCK.
	 * 
	 *   The OPEN_MMAP mode is fastest, while the OPEN_READ_COPY is slowest, but OPEN_MMAP requires some
	 *   extra preresequites (like write access, RD_LOCK, mmap at the same address as previously), while
	 *   OPEN_READ_COPY works always.
	 * 
	 *   TL;DR: This function attempts to open input file in the fastest possible mode.
	 * 
	 * @param f handler to file opened with fopen
	 * @param support_write_lock flag indicating whether we want to support OPEN_MMAP_WRITE mode
	 * @param support_mmap whether we want to support any OPEN_MMAP* mode
	 */
	void open_file(FILE* f, bool support_write_lock = true, bool support_mmap = true) {
		int fd = fileno(f);
		opened_file_fd = fd;
		opened_file_file = f;
		current_mmap_offset = 0;
		open_mode = UNFLATTEN_OPEN_READ_COPY;

		opened_mmap_size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);

		int ret = 0;
		struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0,};

#ifndef KLEE_SUPPORT
		// Attempt to obtain write_lock
		if(support_write_lock && support_mmap){
			ret = fcntl(fd, F_SETLK, &lock);
			if(ret >= 0) {
				// Acquired exclusive write access
				read_file(&FLCTRL.HDR,sizeof(struct flatten_header),1);
				fseek(f, 0, SEEK_SET);
				if(!FLCTRL.HDR.last_load_addr){
					// rewrite image, mmap it and release lock
					opened_mmap_addr = mmap(NULL, opened_mmap_size,
						PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
					if(opened_mmap_addr != MAP_FAILED) {
						info("Opened file in write mode\n");
						open_mode = UNFLATTEN_OPEN_MMAP_WRITE;
						return;
					}
				}
				debug("Failed to open file in write mode - %s\n", strerror(errno));
			} else
				debug("Write-lock failed - %s\n", strerror(errno));
		} else
			info("Skipping write-lock as requested by callee\n");

		// Wait for read_lock
		lock.l_type = F_RDLCK;
		ret = fcntl(fd, F_SETLKW, &lock);
		if(ret < 0) {
			info("Failed to obtain read-lock - fcntl returned: %s\n", strerror(errno));
			throw std::runtime_error("Failed to acquire read-lock on input file");
		}

		// At this point we've got read_lock, check header and try to mmap file
		read_file(&FLCTRL.HDR,sizeof(struct flatten_header),1);
		fseek(f, 0, SEEK_SET);
		void* mmap_addr = (void*) FLCTRL.HDR.last_load_addr;
		if(mmap_addr != NULL && support_mmap) {	
			opened_mmap_addr = mmap(mmap_addr, opened_mmap_size, 
					PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
			if(opened_mmap_addr != MAP_FAILED) {
				// Succesfully mmaped file, hold lock till close_file
				info("Opened input file in mmap mode @ %p (size: %p)\n", 
					opened_mmap_addr, opened_mmap_size);
				open_mode = UNFLATTEN_OPEN_MMAP;
				return;
			} else
				debug("Failed to open input file in mmap mode - %s\n", strerror(errno));
		}
#endif
		// Mmap failed. The only thing left is to load whole image into memory
		info("Opened file in copy mode\n");
		open_mode = UNFLATTEN_OPEN_READ_COPY;
		return;
	}

	void close_file() {
		struct flock lock = { 0,  };
		lock.l_type = F_UNLCK;
		lock.l_start = 0;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;

		debug("Closing file with mode: '%d'\n", open_mode);
		switch(open_mode) {
			case UNFLATTEN_OPEN_MMAP:
			case UNFLATTEN_OPEN_MMAP_WRITE:
				debug("Releasing shared memory @ %p (sz:%zu)\n", 
					opened_mmap_addr, opened_mmap_size);
				munmap(opened_mmap_addr, opened_mmap_size);
				fcntl(opened_file_fd, F_SETLK, &lock);
			break;

			case UNFLATTEN_OPEN_READ_COPY:
				fcntl(opened_file_fd, F_SETLK, &lock);
			break;

			default:
				throw std::runtime_error("Unexpected open_mode in close_file() method");
		}

		opened_file_fd = -1;
		opened_file_file = NULL;
	}

	void read_file(void* dst, size_t size, size_t n) {
		size_t rd, total_size;

		switch(open_mode) {
			case UNFLATTEN_OPEN_MMAP:
			case UNFLATTEN_OPEN_MMAP_WRITE: {
				total_size = size * n;
				if(total_size + current_mmap_offset > opened_mmap_size)
					throw std::invalid_argument("Truncated file");

				memcpy(dst, (char*)opened_mmap_addr + current_mmap_offset, total_size);
				current_mmap_offset += total_size;
			}
			break;

			case UNFLATTEN_OPEN_READ_COPY: {
				rd = fread(dst, size, n, opened_file_file);
				if(rd != n)
					throw std::invalid_argument("Truncated file");
			}
			break;

			default:
				throw std::runtime_error("Unexpected open_mode in read_file() method");
		}

		readin += size * n;
	}


	/***************************
	 * UNFLATTEN MEMORY
	 **************************/
	inline void check_header(void) const {
		if (FLCTRL.HDR.magic != KFLAT_IMG_MAGIC)
			throw std::invalid_argument("Invalid magic while reading flattened image");
		if (FLCTRL.HDR.version != KFLAT_IMG_VERSION)
			throw std::invalid_argument(
					"Incompatible version of flattened image. Present (" +
					std::to_string(FLCTRL.HDR.version) + ") vs Supported (" +
					std::to_string(KFLAT_IMG_VERSION) + ")");
		if (FLCTRL.HDR.image_size > opened_mmap_size)
			throw std::invalid_argument("Image size specified in header differs from the actual one");

		bool overflow = false;
		overflow |= check_mul_overflow(FLCTRL.HDR.ptr_count, sizeof(size_t));
		overflow |= check_mul_overflow(FLCTRL.HDR.fptr_count, sizeof(size_t));
		overflow |= check_mul_overflow(FLCTRL.HDR.root_addr_count, sizeof(size_t));
		overflow |= check_mul_overflow(FLCTRL.HDR.mcount, 16);
		if (overflow)
			throw std::invalid_argument("Count fields in header are greater than maximum size");

		size_t total_size = 0;
		overflow |= add_overflow(total_size, FLCTRL.HDR.ptr_count * sizeof(size_t), &total_size);
		overflow |= add_overflow(total_size, FLCTRL.HDR.fptr_count * sizeof(size_t), &total_size);
		overflow |= add_overflow(total_size, FLCTRL.HDR.root_addr_count * sizeof(size_t), &total_size);
		overflow |= add_overflow(total_size, FLCTRL.HDR.root_addr_extended_size, &total_size);
		overflow |= add_overflow(total_size, FLCTRL.HDR.fptrmapsz, &total_size);
		overflow |= add_overflow(total_size, FLCTRL.HDR.mcount * 16, &total_size);
		overflow |= add_overflow(total_size, FLCTRL.HDR.memory_size, &total_size);
		if (overflow)
			throw std::invalid_argument("Integer overflow when adding fields count in image header");
		if (total_size > FLCTRL.HDR.image_size)
			throw std::invalid_argument("Size of memory area with header exceeds size of an image");
	}

	inline void parse_root_ptrs(void) {
		std::vector<uintptr_t> root_ptr_vector;
		for (size_t i = 0; i < FLCTRL.HDR.root_addr_count; ++i) {
			size_t root_addr_offset;
			read_file(&root_addr_offset, sizeof(size_t), 1);
			root_ptr_vector.push_back(root_addr_offset);
		}

		std::map<size_t,std::pair<std::string,size_t>> root_ptr_ext_map;
		for (size_t i = 0; i < FLCTRL.HDR.root_addr_extended_count; ++i) {
			size_t name_size, index, size;
			read_file(&name_size,sizeof(size_t),1);

			char* name = new char[name_size + 1];
			try {
				read_file((void*)name, name_size, 1);
				name[name_size] = '\0';
				read_file(&index, sizeof(size_t), 1);
				read_file(&size, sizeof(size_t), 1);
				root_ptr_ext_map.insert({index, {std::string(name), size}});
			} catch(...) {
				delete[] name;
				throw;
			}
			delete[] name;
		}

		for (size_t i = 0; i < root_ptr_vector.size(); ++i) {
			if (root_ptr_ext_map.find(i) != root_ptr_ext_map.end())
				root_addr_append_extended(root_ptr_vector[i], root_ptr_ext_map[i].first.c_str(), root_ptr_ext_map[i].second);
			else
				root_addr_append(root_ptr_vector[i]);
		}
	}

	inline size_t get_memsz() {
		return FLCTRL.HDR.memory_size + \
			FLCTRL.HDR.ptr_count * sizeof(size_t) + \
			FLCTRL.HDR.fptr_count * sizeof(size_t) + \
			FLCTRL.HDR.mcount * 2 * sizeof(size_t);
	}

	inline void parse_mem(void) {
		size_t memsz = get_memsz();

		switch(open_mode) {
			case UNFLATTEN_OPEN_READ_COPY:
				FLCTRL.mem = new char[memsz];
				read_file(FLCTRL.mem, 1, memsz);
				break;
			case UNFLATTEN_OPEN_MMAP:
			case UNFLATTEN_OPEN_MMAP_WRITE:
				if(current_mmap_offset + memsz > opened_mmap_size)
					throw std::invalid_argument("Truncated file (memory_size > image_size)");
				FLCTRL.mem = (char*)opened_mmap_addr + current_mmap_offset;
				current_mmap_offset += memsz;
				break;
		}
	}

	inline void release_mem(void) {
		if(open_mode == UNFLATTEN_OPEN_READ_COPY)
			delete[] (char*)FLCTRL.mem;
		FLCTRL.mem = NULL;
	}

	inline void parse_fptrmap(void) {
		char* orig_fptrmapmem, * fptrmapmem;

		if (FLCTRL.HDR.fptr_count <= 0 || FLCTRL.HDR.fptrmapsz <= 0)
			return;
		
		if(open_mode == UNFLATTEN_OPEN_READ_COPY) {
			orig_fptrmapmem = fptrmapmem = new char[FLCTRL.HDR.fptrmapsz];
			read_file(fptrmapmem, 1, FLCTRL.HDR.fptrmapsz);
		} else {
			if(current_mmap_offset + FLCTRL.HDR.fptrmapsz > opened_mmap_size)
					throw std::invalid_argument("Truncated file (fptrmapsz_end > image_size)");
			orig_fptrmapmem = fptrmapmem = (char*)opened_mmap_addr + current_mmap_offset;
			current_mmap_offset += FLCTRL.HDR.fptrmapsz;
		}

		size_t fptrnum = *(size_t*)fptrmapmem;
		fptrmapmem += sizeof(size_t);

		for (size_t kvi = 0; kvi < fptrnum; ++kvi) {
			uintptr_t addr = *(uintptr_t*)fptrmapmem;
			fptrmapmem += sizeof(uintptr_t);

			size_t sz = *(size_t*)fptrmapmem;
			fptrmapmem += sizeof(size_t);

			std::string sym((const char*)fptrmapmem, sz);
			fptrmapmem += sz;
			fptrmap.insert(std::pair<uintptr_t, std::string>(addr, sym));
		}
		
		if(open_mode == UNFLATTEN_OPEN_READ_COPY)
			delete[] orig_fptrmapmem;
	}

	/**
	 * @brief Fix all the pointers in flattened memory area
	 * 
	 */
	inline void fix_flatten_mem(bool continuous_mapping) {
		if(open_mode == UNFLATTEN_OPEN_MMAP) {
			// Memory was already fixed and is loaded at the same address as previously
			return;
		}

		for (size_t i = 0; i < FLCTRL.HDR.ptr_count; ++i) {
			void* mem = flatten_memory_start();
			size_t tmp;
			/*
			 * Extract fix location from image by accessing i-th element from ptr_array (which is at the start of 'mem' region).
			 *  Under each fix location there's an offset (measured from FLCTRL.HDR.last_mem_addr) which specifies where that
			 *  pointer should point to.
			 */
			size_t fix_loc = *((size_t*)FLCTRL.mem + i);
			if(fix_loc + sizeof(size_t) > FLCTRL.HDR.memory_size || add_overflow(fix_loc, sizeof(size_t), &tmp))
				throw std::invalid_argument("Invalid fix location in ptr_array for ptr no. " + std::to_string(i));
			uintptr_t ptr = *(uintptr_t*)((char*)mem + fix_loc);
			if(ptr < FLCTRL.HDR.last_mem_addr)
				throw std::invalid_argument("Invalid fix destination (offset is negative) for ptr no. " + std::to_string(i));
			ptr -= FLCTRL.HDR.last_mem_addr;
			if(ptr > FLCTRL.HDR.memory_size)
				throw std::invalid_argument("Invalid fix destination (offset is larger than memory size) for ptr no. " + std::to_string(i));

			if(continuous_mapping) {
				*((void**)((unsigned char*)mem + fix_loc)) = (unsigned char*)mem + ptr;
			} else {

				struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root, fix_loc, fix_loc + 8);
				if (node == NULL)
					throw std::invalid_argument("Address points to invalid location.");

				size_t node_offset = fix_loc - node->start;
				struct interval_tree_node *ptr_node = interval_tree_iter_first(&FLCTRL.imap_root, ptr, ptr + 8);
				if (ptr_node == NULL)
					throw std::invalid_argument("Address points to invalid location.");

				/* Make the fix */
				size_t ptr_node_offset = ptr - ptr_node->start;
				size_t mptr_size = node->last - node->start + 1;
				if (node_offset > mptr_size - 8)
					throw std::invalid_argument("Invalid node offset");
				*((void**)((char*)node->mptr + node_offset)) = (char*)ptr_node->mptr + ptr_node_offset;

				debug("%lx <- %lx (%hhx)\n", fix_loc, ptr, *(unsigned char*)((char*)ptr_node->mptr + ptr_node_offset));
			}
		}

		// After fixing image, update its base address and change to read-lock
		if(open_mode == UNFLATTEN_OPEN_MMAP_WRITE) {
			struct flatten_header* header = (struct flatten_header*) opened_mmap_addr;
			header->last_load_addr = (uintptr_t) opened_mmap_addr;
			header->last_mem_addr = (uintptr_t) flatten_memory_start();

			// Remap image as COW
			munmap(opened_mmap_addr, opened_mmap_size);
			opened_mmap_addr = mmap(opened_mmap_addr, opened_mmap_size, 
				PROT_READ | PROT_WRITE, MAP_PRIVATE, opened_file_fd, 0);

			struct flock lock = { 0,  };
			lock.l_type = F_RDLCK;
			lock.l_start = 0;
			lock.l_whence = SEEK_SET;
			lock.l_start = 0;
			fcntl(opened_file_fd, F_SETLK, &lock);

			open_mode = UNFLATTEN_OPEN_MMAP;
		}

		// Update header to reflect modified memory base address
		if(continuous_mapping)
			FLCTRL.HDR.last_mem_addr = (uintptr_t) flatten_memory_start();
	}


public:
	UnflattenEngine(int _level = LOG_NONE) {
		memset(&FLCTRL.imap_root, 0, sizeof(struct rb_root_cached));
		memset(&FLCTRL.HDR, 0, sizeof(struct flatten_header));
		FLCTRL.last_accessed_root = -1;
		FLCTRL.mem = 0;
		need_unload = false;
		loglevel = (decltype(loglevel))_level;
	}

	int imginfo(FILE* f, const char* arg) {
		if (need_unload)
			unload();
		open_file(f, false);
		read_file(&FLCTRL.HDR, sizeof(struct flatten_header), 1);
		check_header();

		printf("# Image size: %zu\n\n",FLCTRL.HDR.image_size);

		if ((!arg) || (!strcmp(arg,"-r"))) {
			printf("# root_addr_count: %zu\n",FLCTRL.HDR.root_addr_count);
			printf("[ ");
		}
		for (size_t i = 0; i < FLCTRL.HDR.root_addr_count; ++i) {
			size_t root_addr_offset;
			read_file(&root_addr_offset, sizeof(size_t), 1);
			if ((!arg) || (!strcmp(arg,"-r"))) {
				printf("%zu ",root_addr_offset);
			}
		}
		if ((!arg) || (!strcmp(arg,"-r"))) {
			printf("]\n\n");
			printf("# root_addr_extended_count: %zu\n",FLCTRL.HDR.root_addr_extended_count);
		}
		for (size_t i = 0; i < FLCTRL.HDR.root_addr_extended_count; ++i) {
			size_t name_size, index, size;
			read_file(&name_size, sizeof(size_t), 1);

			char* name = new char[name_size + 1];
			memset(name, 0, name_size);
			try {
				read_file((void*)name, name_size, 1);
				read_file(&index, sizeof(size_t), 1);
				read_file(&size, sizeof(size_t), 1);
				if ((!arg) || (!strcmp(arg,"-r"))) {
					printf(" %zu [%s:%lu]\n", index, name, size);
				}
			} catch(...) {
				delete[] name;
				throw;
			}
			delete[] name;
		}
		if ((!arg) || (!strcmp(arg,"-r"))) {
			printf("\n");
		}

		parse_mem();

		if ((!arg) || (!strcmp(arg,"-p"))) {
			printf("# ptr_count: %zu\n",FLCTRL.HDR.ptr_count);
			printf("[ ");
		}
		for (size_t i = 0; i < FLCTRL.HDR.ptr_count; ++i) {
			size_t *fix_loc = ((size_t*)FLCTRL.mem + i);
			if (WITHIN_MEM_BOUNDS(fix_loc, size_t)) {
				if ((!arg) || (!strcmp(arg,"-p"))) {
					printf("%zu ", *fix_loc);
				}
			}
		}
		if ((!arg) || (!strcmp(arg,"-p"))) {
			printf("]\n\n");
		}

		if ((!arg) || (!strcmp(arg,"-p"))) {
			printf("# fptr_count: %zu\n",FLCTRL.HDR.fptr_count);
			printf("[ ");
		}
		for (size_t fi = 0; fi < FLCTRL.HDR.fptr_count; ++fi) {
			size_t *fptri = ((uintptr_t*)((char*)FLCTRL.mem + FLCTRL.HDR.ptr_count * sizeof(size_t))) + fi;
			if (WITHIN_MEM_BOUNDS(fptri, size_t)) {
				if ((!arg) || (!strcmp(arg,"-p"))) {
					printf("%zu ", *fptri);
				}
			}
		}
		if ((!arg) || (!strcmp(arg,"-p"))) {
			printf("]\n\n");
		}

		unsigned char* memptr =
				((unsigned char*)FLCTRL.mem)+FLCTRL.HDR.ptr_count*sizeof(size_t)+FLCTRL.HDR.fptr_count*sizeof(size_t)+
					FLCTRL.HDR.mcount*2*sizeof(size_t);
		if ((!arg) || (!strcmp(arg,"-m")) || (!strcmp(arg,"-M"))) {
			std::set<size_t> fixset;
			for (size_t i=0; i<FLCTRL.HDR.ptr_count; ++i) {
				size_t fix_loc = *((size_t*)FLCTRL.mem+i);
				fixset.insert(fix_loc);
			}
			int ptrbyte_count=0;
			printf("# Memory size: %lu [not fixed]\n",FLCTRL.HDR.memory_size);
			for (unsigned long i=0; i<FLCTRL.HDR.memory_size; ++i) {
				if ((i%64)==0) {
					if ((arg) && (!strcmp(arg,"-m"))) {
						if (ptrbyte_count>0) printf(COLOR_OFF);
					}
					int n = printf("%lu:%lu: ",(i/64)*64+(i%64),(i/64)*64+(i%64)+63);
					for (int j=0; j<16-n; ++j) printf(" ");
					if ((arg) && (!strcmp(arg,"-m"))) {
						if (ptrbyte_count>0) printf(COLOR_STRING);
					}
				}
				if (fixset.find(i)!=fixset.end()) {
					if ((arg) && (!strcmp(arg,"-m"))) {
						printf(COLOR_STRING);
					}
					ptrbyte_count=8;
				}
				printf("%02x ",*((unsigned char*)memptr+i));
				if ((((i+1)%32)==0) && (i+1<FLCTRL.HDR.memory_size)) {
					if ((arg) && (!strcmp(arg,"-m"))) {
						if (ptrbyte_count>0) printf(COLOR_OFF);
					}
					printf(" | ");
					if ((arg) && (!strcmp(arg,"-m"))) {
						if (ptrbyte_count>0) printf(COLOR_STRING);
					}
				}
				if ((((i+1)%64)==0) && (i+1<FLCTRL.HDR.memory_size)) {
					if ((arg) && (!strcmp(arg,"-m"))) {
						if (ptrbyte_count>0) printf(COLOR_OFF);
					}
					printf("\n");
					if ((arg) && (!strcmp(arg,"-m"))) {
						if (ptrbyte_count>0) printf(COLOR_STRING);
					}
				}
				ptrbyte_count--;
				if (ptrbyte_count<=0) {
					if ((arg) && (!strcmp(arg,"-m"))) {
						printf(COLOR_OFF);
					}
				}
			}
			if ((arg) && (!strcmp(arg,"-m"))) {
				printf(COLOR_OFF);
			}
			printf("\n\n");
		}

		if ((!arg) || (!strcmp(arg,"-f"))) {
			printf("# Fragment count: %lu\n",FLCTRL.HDR.mcount);
			size_t* minfoptr = (size_t*)((char*)FLCTRL.mem + FLCTRL.HDR.ptr_count * sizeof(size_t) + FLCTRL.HDR.fptr_count * sizeof(size_t));
			for (size_t i = 0; i < FLCTRL.HDR.mcount; ++i) {
				size_t index = *minfoptr++;
				size_t size = *minfoptr++;
				printf("  %zu:[ %zu ]\n",index,size);
			}
			printf("\n");
		}

		if ((!arg) || (!strcmp(arg,"-a"))) {
			printf("# Function pointer map size: %zu\n",FLCTRL.HDR.fptrmapsz);
			// Compare fptrmapsz with sizeof(size_t) because we later dereference and read size_t fptrnum
			if (FLCTRL.HDR.fptr_count > 0 && FLCTRL.HDR.fptrmapsz >= sizeof(size_t)) {
				std::unique_ptr<char[]> fptrmapmem(new char[FLCTRL.HDR.fptrmapsz]);
				size_t offset = 0;
				
				if (fptrmapmem == nullptr)
					throw std::runtime_error("Failed to allocate memory for function pointers");

				read_file(fptrmapmem.get(), 1, FLCTRL.HDR.fptrmapsz);
				size_t fptrnum = *((size_t*)fptrmapmem.get());
				printf("# Function pointer count: %zu\n",fptrnum);
				offset += sizeof(size_t);

				for (size_t kvi=0; kvi < fptrnum; ++kvi) {
					if (offset + sizeof(uintptr_t) >= FLCTRL.HDR.fptrmapsz)
						break;
					uintptr_t addr = *((uintptr_t *)(fptrmapmem.get() + offset));
					offset += sizeof(uintptr_t);

					if (offset + sizeof(size_t) >= FLCTRL.HDR.fptrmapsz)
						break;

					size_t sz = *((size_t *)(fptrmapmem.get() + offset));
					offset += sizeof(size_t);

					if (offset + sz >= FLCTRL.HDR.fptrmapsz)
						break;
					std::string sym((const char *)(fptrmapmem.get() + offset), sz);
					offset += sz;
					printf("  [%s]: %08lx\n",sym.c_str(),addr);
				}
			}
		}

		release_mem();
		return 0;
	}

	int load(FILE* f, get_function_address_t gfa = NULL, bool continuous_mapping = false) {
		if(need_unload)
			unload();
		readin = 0;

		// When continous_mapping is disabled we have to always operate on
		//  local copy of flatten imaged, because memory chunks are not portable
		open_file(f, continuous_mapping, continuous_mapping);
		need_unload = true;

		time_mark_start();
		// Parse header info and load flattened memory
		read_file(&FLCTRL.HDR, sizeof(struct flatten_header), 1);
		check_header();
		parse_root_ptrs();
		parse_mem();
		if(gfa)
			parse_fptrmap();
		info(" #Unflattening done\n");
		info(" #Image read time: %lfs\n", time_elapsed());

		if(FLCTRL.HDR.mcount == 0)
			continuous_mapping = true;
		FLCTRL.is_continous_mode = continuous_mapping;

		// Convert continous memory into chunked area
		if(!continuous_mapping) {
			time_mark_start();
			size_t *minfoptr = (size_t*)((char*)FLCTRL.mem + FLCTRL.HDR.ptr_count * sizeof(size_t) + FLCTRL.HDR.fptr_count * sizeof(size_t));
			void *memptr = flatten_memory_start();
			info(" * memory size: %lu\n", FLCTRL.HDR.memory_size);

			for (size_t i = 0; i < FLCTRL.HDR.mcount; ++i) {
				size_t index = *minfoptr++;
				size_t size = *minfoptr++;
				if(index + size < index)
					throw std::invalid_argument("Size overflow for memory fragment no. " + std::to_string(i));
				if(index + size > FLCTRL.HDR.memory_size)
					throw std::invalid_argument("Memory fragment no. " + std::to_string(i) + " doesn't fit in flatten image");

				struct interval_tree_node *node = (struct interval_tree_node*)calloc(1, sizeof(struct interval_tree_node));
				node->start = index;
				node->last = index + size - 1;
				void* fragment = malloc(size);
				if (fragment == NULL)
					throw std::bad_alloc();
				memcpy(fragment, (char*)memptr + index, size);
				node->mptr = fragment;
				interval_tree_insert(node, &FLCTRL.imap_root);
			}
			info(" #Creating chunked memory time: %lfs\n", time_elapsed());
		}

		// Fix pointers
		time_mark_start();
		fix_flatten_mem(continuous_mapping);

		// Fix function pointers
		if (FLCTRL.HDR.fptr_count > 0 && gfa) {
			void* mem = flatten_memory_start();
			for (size_t fi = 0; fi < FLCTRL.HDR.fptr_count; ++fi) {
				size_t fptri = ((uintptr_t*)((char*)FLCTRL.mem + FLCTRL.HDR.ptr_count * sizeof(size_t)))[fi];
				if (fptrmap.find(fptri) == fptrmap.end())
					continue;
				
				// Fix function pointer
				uintptr_t nfptr = (*gfa)(fptrmap[fptri].c_str());

				if(continuous_mapping) {
					*((void**)((char*)mem + fptri)) = (void*)nfptr;
				} else {
					struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root, fptri, fptri + 8);
					if (node == NULL)
						throw std::invalid_argument("Function address points to invalid location.");

					size_t node_offset = fptri-node->start;
					*((void**)((char*)node->mptr + node_offset)) = (void*)nfptr;
				}
			}
		}

		fix_root_pointers();

		// At this point mode UNFLATTEN_OPEN_READ_COPY copied all memory to local RAM
		//  so there's no need to hold lock any longer
		if(open_mode == UNFLATTEN_OPEN_READ_COPY) {
			struct flock lock = { 0,  };
			lock.l_type = F_UNLCK;
			lock.l_start = 0;
			lock.l_whence = SEEK_SET;
			lock.l_start = 0;
			fcntl(opened_file_fd, F_SETLK, &lock);
		}

		info(" #Fixing memory time: %lfs\n", time_elapsed());
		info("  Total bytes read: %zu\n", readin);
		if(!continuous_mapping)
			info("  Number of allocated fragments: %zu\n", FLCTRL.HDR.mcount);
		info("  Number of fixed pointers: %lu\n", FLCTRL.HDR.ptr_count);
		return 0;
	}

	void unload(void) {
		struct interval_tree_node* node, *tmp;
		release_mem();
		fptrmap.clear();

		rbtree_postorder_for_each_entry_safe(node, tmp, &FLCTRL.imap_root.rb_root, rb) {
			// Don't call `interval_tree_remove` here - it might trigger rebalance and 
			//  invalidate iterator. The tree is going to be removed completely so it's
			//  sufficient to just clear imap_root at the end
			if (already_freed.find(node->mptr) == already_freed.end())
				free(node->mptr);


			free(node);
		}
		memset(&FLCTRL.imap_root, 0, sizeof(struct rb_root_cached));

		FLCTRL.root_addr.clear();
		root_addr_map.clear();
		FLCTRL.last_accessed_root = -1;
		need_unload = false;
		close_file();
	}

	void mark_freed(void *mptr) {
		already_freed.insert(mptr);
	}

	void* get_next_root(void) {
		return root_pointer_next();
	}

	void* get_seq_root(size_t idx) {
		return root_pointer_seq(idx);
	}

	void* get_named_root(const char* name, size_t* size) {
		return root_pointer_named(name, size);
	}

	void* get_image_header() {
		return &FLCTRL.HDR;
	}

	~UnflattenEngine() {
		if(need_unload)
			unload();
	}

	ssize_t replace_variable(void* old_mem, void* new_mem, size_t size) {
		ssize_t fixed = 0;
		if(old_mem == NULL || new_mem == NULL || size == 0) {
			info("Invalid arguments provided to .replace_variable (%p; %p; %zu)", 
				old_mem, new_mem, size);
			return -1;
		}

		if(open_mode == UNFLATTEN_OPEN_MMAP_WRITE)
			throw std::runtime_error("Unflatten is running in invalid open mode");
		if(FLCTRL.mem == NULL)
			throw std::runtime_error("FLCTRL.mem is not initialized");
		
		for (size_t i = 0; i < FLCTRL.HDR.ptr_count; ++i) {
			void* mem = flatten_memory_start();
			size_t fix_loc = *((size_t*)FLCTRL.mem + i);
			uintptr_t ptr = (uintptr_t)( *(void**)((char*)mem + fix_loc) ) - FLCTRL.HDR.last_mem_addr;

			if(FLCTRL.is_continous_mode) {
				void* target = (unsigned char*)mem + ptr;
				if(target >= old_mem && target <= (unsigned char*)old_mem + size - 8) {
					*(void**)((unsigned char*)mem + fix_loc) = (unsigned char*)new_mem + ((unsigned char*)target - (unsigned char*)old_mem);
					fixed++;
				}
			} else {

				struct interval_tree_node *node = interval_tree_iter_first(&FLCTRL.imap_root, fix_loc, fix_loc + 8);
				if (node == NULL)
					throw std::invalid_argument("Interval tree node could not be extracted");
				size_t node_offset = fix_loc-node->start;

				struct interval_tree_node *ptr_node = interval_tree_iter_first(&FLCTRL.imap_root, ptr, ptr + 8);
				if (ptr_node == NULL)
					throw std::invalid_argument("Interval tree node could not be extracted");
				size_t ptr_node_offset = ptr-ptr_node->start;

				void* target = (unsigned char*)ptr_node->mptr + ptr_node_offset;
				if(target >= old_mem && target <= (unsigned char*)old_mem + size - 8) {
					*((void**)((char*)node->mptr + node_offset)) = (unsigned char*)new_mem + ((unsigned char*)target - (unsigned char*)old_mem);
					fixed++;
				}
			}
		}

		// Replace variable in root and named_root pointers
		for (size_t i = 0; i < FLCTRL.HDR.root_addr_count; i++) {
			uintptr_t root_mem = FLCTRL.root_addr[i].root_addr;
			if(root_mem >= (uintptr_t)old_mem && root_mem < (uintptr_t)old_mem + size) {
				uintptr_t offset = root_mem - (uintptr_t)old_mem;
				FLCTRL.root_addr[i].root_addr = (uintptr_t)new_mem + offset;
				fixed++;
			}
		}
		for(auto& [name, entry] : root_addr_map) {
			if(entry.first >= (uintptr_t)old_mem && entry.first < (uintptr_t)old_mem + size) {
				uintptr_t offset = entry.first - (uintptr_t)old_mem;
				entry.first = (uintptr_t)new_mem + offset;
				fixed++;
			}
		}

		return fixed;
	}
};

/********************************
 * C++ API
 *******************************/
Unflatten::Unflatten(int level) {
	engine = new UnflattenEngine(level);
}

Unflatten::~Unflatten() {
	delete engine;
}

int Unflatten::load(FILE* file, get_function_address_t gfa, bool continuous_mapping) {
	return engine->load(file, gfa, continuous_mapping);
}

int Unflatten::info(FILE* file, const char* arg) {
	return engine->imginfo(file,arg);
}

void Unflatten::mark_freed(void *mptr) {
	return engine->mark_freed(mptr);
}

void Unflatten::unload() {
	engine->unload();
}

void* Unflatten::get_next_root() {
	return engine->root_pointer_next();
}

void* Unflatten::get_seq_root(size_t idx) {
	return engine->root_pointer_seq(idx);
}

void* Unflatten::get_named_root(const char* name, size_t* size) {
	return engine->root_pointer_named(name, size);
}

ssize_t Unflatten::replace_variable(void* old_mem, void* new_mem, size_t size) {
	return engine->replace_variable(old_mem, new_mem, size);
}

/********************************
 * C Wrappers
 *******************************/
CUnflatten unflatten_init(int level) {
	CUnflatten flatten;
	try {
		flatten = new UnflattenEngine(level);
	} catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to initalize kflat - `%s`\n", ex.what());
		return NULL;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to initalize kflat - exception occurred\n");
		return NULL;
	}
	return flatten;
}

void unflatten_deinit(CUnflatten flatten) {
	try {
		if(flatten != NULL)
			delete (UnflattenEngine*)flatten;
	} catch(...) {
		return;
	}
}

int unflatten_load(CUnflatten flatten, FILE* file, get_function_address_t gfa) {
	try {
		return ((UnflattenEngine*)flatten)->load(file, gfa);
	} catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to load image - `%s`\n", ex.what());
		return -1;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to load image - exception occurred\n");
		return -1;
	}
}

int unflatten_imginfo(CUnflatten flatten, FILE* file) {
	try {
		return ((UnflattenEngine*)flatten)->imginfo(file,0);
	} catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to print image information - `%s`\n", ex.what());
		return -1;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to print image information - exception occurred\n");
		return -1;
	}
}

int unflatten_load_continuous(CUnflatten flatten, FILE* file, get_function_address_t gfa) {
	try {
		return ((UnflattenEngine*)flatten)->load(file, gfa, true);
	} catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to load continous image - `%s`\n", ex.what());
		return -1;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to load continous image - exception occurred\n");
		return -1;
	}
}

void unflatten_unload(CUnflatten flatten) {
	try {
		((UnflattenEngine*)flatten)->unload();
	} catch(...) {
		return;
	}
}

void* unflatten_root_pointer_next(CUnflatten flatten) {
	try {
		return ((UnflattenEngine*)flatten)->get_next_root();
	} catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to get next root pointer - `%s`\n", ex.what());
		return NULL;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to get next root pointer - exception occurred\n");
		return NULL;
	}
}

void* unflatten_root_pointer_seq(CUnflatten flatten, size_t idx) {
	try {
		return ((UnflattenEngine*)flatten)->get_seq_root(idx);
	} catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to get seq root pointer - `%s`\n", ex.what());
		return NULL;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to get seq root pointer - exception occurred\n");
		return NULL;
	}
}

void* unflatten_root_pointer_named(CUnflatten flatten, const char* name, size_t* idx) {
	try {
		return ((UnflattenEngine*)flatten)->get_named_root(name, idx);
	}  catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to get named root pointer - `%s`\n", ex.what());
		return NULL;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to get named root pointer - exception occurred\n");
		return NULL;
	}
}

void unflatten_mark_freed(CUnflatten flatten, void *mptr) {
	try {
		((UnflattenEngine*)flatten)->mark_freed(mptr);
	} catch (std::exception& ex) {
		fprintf(stderr, "[UnflattenLib] Failed to mark pointer as freed - `%s`\n", ex.what());
	}
}

CUnflattenHeader unflatten_get_image_header(CUnflatten flatten) {
	try {
		return ((UnflattenEngine*)flatten)->get_image_header();
	}  catch(std::exception& ex) { 
		fprintf(stderr, "[UnflattenLib] Failed to get image header\n");
		return NULL;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to get image header - exception occurred\n");
		return NULL;
	}
}

unsigned long unflatten_header_fragment_count(CUnflattenHeader header) {
	return (unsigned long)((struct flatten_header*)header)->mcount;
}

size_t unflatten_header_memory_size(CUnflattenHeader header) {
	return (unsigned long)((struct flatten_header*)header)->memory_size;
}

ssize_t unflatten_replace_variable(CUnflatten flatten, void* old_mem, void* new_mem, size_t size) {
	try {
		return ((UnflattenEngine*)flatten)->replace_variable(old_mem, new_mem, size);
	} catch(std::exception& ex) {
		fprintf(stderr, "[UnflattenLib] Failed to replace variable references - `%s`\n", ex.what());
		return -1;
	} catch(...) {
		fprintf(stderr, "[UnflattenLib] Failed to replace variable references\n");
		return -1;
	}
}
