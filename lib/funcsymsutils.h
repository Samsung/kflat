#ifndef FUNCSYMSUTILS_H
#define FUNCSYMSUTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>

#define ELF_HEADER(__buff) ((Elf64_Ehdr *)(__buff))
#define SECTION_TABLE_START(__sh_table) ((void *) (__sh_table))
#define SECTION_TABLE_SIZE(__elf_header) ((__elf_header)->e_shentsize * (__elf_header)->e_shnum)
#define IS_VALID_INDEX(__idx, __max) ((__idx) >= 0 && (__idx) < (__max))

#define ELF_HEADER_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

/***********************
 * Exported types
************************/

/**
 * @brief Symbol name to symbol address mapping.
 * 
 */
typedef struct {
	unsigned long address;
	char *name;
} func_symbol_info;

/***********************
 * Exported functions
************************/

/**
 * @brief Create array of func_symbol_info variables with mapping of all .symtab symbols defined in the current process. 
 * 
 * @param num OUTPUT - number of entries in returned array.
 * @return func_symbol_info* Pointer to the func_symbol_info array.
 */
func_symbol_info *get_symbol_to_name_mapping(size_t *num);

/**
 * @brief Extract the address of a symbol with a given name.
 * 
 * @param func_info_table Pointer to array created with func_symbol_info *get_symbol_to_name_mapping;
.
 * @param n_entries Number of funcInfoTable entries.
 * @param name Symbol name
 * @return unsigned long Address of a symbol
 */
unsigned long lookup_func_by_name(func_symbol_info *func_info_table, size_t n_entries, const char *name);

/**
 * @brief Extract the name of a symbol at a given address.
 * 
 * @param func_info_table Pointer to array created with func_symbol_info *get_symbol_to_name_mapping;
.
 * @param n_entries Number of func_info_table entries.
 * @param address Symbol address
 * @return const char* Name of a symbol
 */
const char *lookup_func_by_address(func_symbol_info *func_info_table, size_t n_entries, unsigned long address);


/**
 * @brief Free all the memory used to store symbol info. NOTE. All symbol names returned by lookup_func_by_address are freed and become invalid after calling this function. 
 * 
 * @param func_info_table Pointer to array created with get_symbol_to_name_mapping.
 * @param n_entries Number of func_info_table entries.
 */
void cleanup_symbol_to_name_mapping(func_symbol_info *func_info_table, size_t n_entries);


#ifdef __cplusplus
}
#endif


#endif /* FUNCSYMSUTILS_H */
