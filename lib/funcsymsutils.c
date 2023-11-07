/**
 * @file uflat.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Userspace FLAT (UFLAT) API implementation
 * 
 */

#include "funcsymsutils.h"
#include "uflat.h"


static char *get_current_process_exec_path() {
	char *buff = (char *) malloc(256);
	ssize_t buff_len;
	if ((buff_len = readlink("/proc/self/exe", buff, 255)) != -1) {
		buff[buff_len] = '\0';
	}
	else {
		FLATTEN_LOG_DEBUG("Failed to read the /proc/self/exe symlink");
		free(buff);
		return NULL;
	}

	return buff;
}


static Elf64_Shdr *get_section_header_table(FILE *f, Elf64_Ehdr *ehdr) {
	Elf64_Shdr *sh_table = (Elf64_Shdr *) malloc(SECTION_TABLE_SIZE(ehdr));
	if (sh_table == NULL) {
		FLATTEN_LOG_DEBUG("Failed to alloc memory for Section Header Table");
		return NULL;
	}

	fseek(f, ehdr->e_shoff, SEEK_SET);
	size_t rv = fread(sh_table, sizeof(char), SECTION_TABLE_SIZE(ehdr), f);

	if (rv == 0) {
		FLATTEN_LOG_DEBUG("Failed to fread Section Header Table");
		free(sh_table);
		return NULL;
	}

	return sh_table;
}

/*
* This string table is used for the names of sections.
*/
static char *get_section_header_string_table(FILE *f, Elf64_Shdr *sh_table, size_t shstrtab_idx, size_t *str_tab_size) {
	Elf64_Shdr *sh_str_tab_hdr = &sh_table[shstrtab_idx];
	char *sh_str_tab = (char *) malloc(sh_str_tab_hdr->sh_size);

	if (sh_str_tab == NULL) {
		FLATTEN_LOG_DEBUG("Failed to alloc memory for .shstrtab");
		return NULL;
	}

	*str_tab_size = sh_str_tab_hdr->sh_size;

	fseek(f, sh_str_tab_hdr->sh_offset, SEEK_SET);
	size_t rv = fread(sh_str_tab, sizeof(char), sh_str_tab_hdr->sh_size, f);
	
	if (rv == 0) {
		FLATTEN_LOG_DEBUG("Failed to fread .shstrtab");
		free(sh_str_tab);
		return NULL;
	}

	return sh_str_tab;
}


static Elf64_Sym *get_sym_tab(FILE *f, Elf64_Shdr *sh_table, size_t sh_table_size, size_t *sym_tab_num) {
	Elf64_Shdr *symtab_hdr;
	int symtab_idx = -1;

	for (size_t i = 0; i < sh_table_size; i++) {
		if (sh_table[i].sh_type == SHT_SYMTAB) {
			symtab_idx = i;
			break;
		}
	}

	if (symtab_idx == -1) {
		FLATTEN_LOG_DEBUG("Failed to find .symtab in ELF file");
		return NULL;
	}
	

	symtab_hdr = &sh_table[symtab_idx];
	*sym_tab_num = symtab_hdr->sh_size / symtab_hdr->sh_entsize;

	Elf64_Sym *symtab = (Elf64_Sym *) malloc(symtab_hdr->sh_size);
	if (symtab == NULL) {
		FLATTEN_LOG_DEBUG("Failed to alloc memory for .symtab");
		return NULL;
	}

	fseek(f, symtab_hdr->sh_offset, SEEK_SET);
	size_t rv = fread(symtab, sizeof(char), sh_table[symtab_idx].sh_size, f);

	if (rv == 0) {
		FLATTEN_LOG_DEBUG("Failed to fread .symtab");
		free(symtab);
		return NULL;
	}

	return symtab;
}


/*
* This string table is used for the names of .symtab symbols. 
* NOTE. For the names of symbols in .dynsym there is yet another string table that can be found by
* looking at dynamic tags DT_STRTAB and DT_STRSZ.
*/

static char *get_sym_tab_str_tab(FILE *f, Elf64_Shdr *sh_table, size_t sh_table_size, char *sh_str_tab, size_t shstr_tab_size, size_t *str_tab_size) {
	Elf64_Shdr *str_tab_hdr = NULL; 
	for (size_t i = 0; i < sh_table_size; i++){	
		if (
				IS_VALID_INDEX(sh_table[i].sh_name, shstr_tab_size) &&
				strcmp(".strtab", &sh_str_tab[sh_table[i].sh_name]) == 0
			)
			str_tab_hdr = &sh_table[i];
	}

	if (str_tab_hdr == NULL) {
		FLATTEN_LOG_DEBUG("Failed to find .strtab section");
		return NULL;
	}

	char *str_tab = (char *) malloc(str_tab_hdr->sh_size);
	if (str_tab == NULL){
		FLATTEN_LOG_DEBUG("Failed to alloc memory for .strtab");
		return NULL;
	}
	*str_tab_size = str_tab_hdr->sh_size;

	fseek(f, str_tab_hdr->sh_offset, SEEK_SET);
	size_t rv = fread(str_tab, sizeof(char), str_tab_hdr->sh_size, f);

	if (rv == 0) {
		FLATTEN_LOG_DEBUG("Failed to fread .strtab");
		free(str_tab);
		return NULL;
	}

	return str_tab;
}


func_symbol_info *get_symbol_to_name_mapping(size_t *num) {
	func_symbol_info *func_info_table = NULL;
	unsigned long base_addr = 0;
	Elf64_Ehdr *ELF_header = NULL;
	Elf64_Shdr *sh_table = NULL;
	Elf64_Sym *sym_tab = NULL;
	char *sh_str_tab = NULL;
	char *str_tab = NULL;
	size_t shstr_tab_size;
	size_t sym_tab_num;
	size_t str_tab_size;
	size_t n_sym = 0;
	FILE *f = NULL;
	size_t rv;

	char *filepath = get_current_process_exec_path();
	if (filepath == NULL) {
		goto filename_is_null_err;
	}

	f = fopen(filepath, "r");
	if (f == NULL){
		FLATTEN_LOG_DEBUG("Failed to open %s", filepath);
		goto f_open_err;
	}
	free(filepath);

	// Read elf header from the very beginning of the file
	char ELF_hdr_buff[ELF_HEADER_SIZE];
	rv = fread(ELF_hdr_buff, sizeof(char), ELF_HEADER_SIZE, f);

	if (rv == 0) {
		FLATTEN_LOG_DEBUG("Failed to fread the ELF header");
		goto elf_hdr_read_err;
	}

	ELF_header = ELF_HEADER(ELF_hdr_buff);

	// Read Section Header Table
	sh_table = get_section_header_table(f, ELF_header);
	if (sh_table == NULL) {
        goto sh_table_read_err;
	}
	
	// Find the section containing names of all sections (.shstrtab)
	
	sh_str_tab = get_section_header_string_table(f, sh_table, ELF_header->e_shstrndx, &shstr_tab_size);
	if (sh_str_tab == NULL) {
        goto sh_str_tab_read_err;
	}

	// Read all symbols from .symtab
	
	sym_tab = get_sym_tab(f, sh_table, ELF_header->e_shnum, &sym_tab_num);
	if (sym_tab == NULL) {
        goto sym_tab_read_err;
	}

	// Read names of .symtab symbols from .strtab
	
	str_tab = get_sym_tab_str_tab(f, sh_table, ELF_header->e_shnum, sh_str_tab, shstr_tab_size, &str_tab_size);
	if (str_tab == NULL) {
        goto str_tab_read_err;
	}
	
	

	// Extract only relevant info - name and symbol value (relative address)
	func_info_table = (func_symbol_info *) calloc(sym_tab_num, sizeof(func_symbol_info));

	if (func_info_table == NULL) {
		goto func_info_table_alloc_err;
	}
	
	
	for (size_t i = 0; i < sym_tab_num; i++) {
		if (
				IS_VALID_INDEX(sym_tab[i].st_name, str_tab_size) &&
				strcmp(&str_tab[sym_tab[i].st_name], "uflat_init") == 0
			) {
			base_addr = (unsigned long) uflat_init - sym_tab[i].st_value;
			break;
		}
	}

	if (base_addr == 0) {
		FLATTEN_LOG_DEBUG("Base address of process is zero. Function pointers' name resolving might fail");
	}

	for (size_t i = 0; i < sym_tab_num; i++) {
		// Skip if empty name or address == 0
		if (str_tab[sym_tab[i].st_name] != '\0' && sym_tab[i].st_value != 0){
			func_info_table[n_sym].address = base_addr + sym_tab[i].st_value;
			func_info_table[n_sym].name = strdup(&str_tab[sym_tab[i].st_name]);
			n_sym++;
		}
	}


	// Update number of entries
	*num = n_sym;

filename_is_null_err:
func_info_table_alloc_err:
	free(str_tab);
str_tab_read_err:
	free(sym_tab);
sym_tab_read_err:
	free(sh_str_tab);
sh_str_tab_read_err:
	free(sh_table);
sh_table_read_err:
elf_hdr_read_err:
	fclose(f);
f_open_err:

	return func_info_table;
}




unsigned long lookup_func_by_name(func_symbol_info *func_info_table, size_t n_entries, const char *name) {
	if (func_info_table == NULL) {
		return 0;
	}

	size_t name_len = strlen(name);
	for (size_t i = 0; i < n_entries; i++) {
		if (strlen(func_info_table[i].name) == name_len && strncmp(func_info_table[i].name, name, name_len) == 0) {
			return func_info_table[i].address;
		}
	}

	return 0;
}


const char *lookup_func_by_address(func_symbol_info *func_info_table, size_t n_entries, unsigned long address) {
	if (func_info_table == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < n_entries; i++) {
		if (address == func_info_table[i].address) {
			return func_info_table[i].name;
		}
	}

	return NULL;
}


void cleanup_symbol_to_name_mapping(func_symbol_info *func_info_table, size_t n_entries) {
	if (func_info_table == NULL) {
		return;
	}

	for (size_t i = 0; i < n_entries; i++) {
		free(func_info_table[i].name);
	}

	free(func_info_table);
}

