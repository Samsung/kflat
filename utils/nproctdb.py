#!/usr/bin/env python3

""" KFlat recipes generator

	This module allows for automatic generation of KFlat recipes
	for the provided structure type. To use this module, you need
	to create db.json database with https://github.com/Samsung/CAS
	toolset.
"""

import argparse
import io
import json
import os
import sys
from typing import List, Optional, Tuple
from intervaltree import Interval, IntervalTree
import itertools
import hashlib
import re

try:
	import libftdb
except ImportError:
	sys.exit("Failed to import libftdb module. Make sure your PYTHONPATH"
			 " env is pointing to the output directory of CAS repo")

__authors__ = "Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)"


##################################
# Static variables
##################################

OFFSET_KIND_SYMBOLIC=1
OFFSET_KIND_CONCRETE=2
OFFSET_KIND_MIXED=3

##################################
# Global helpers
##################################
def indent(s, n=1):
	return "\n".join([" " * n * RecipeGenerator.TABSIZE + x for x in s.split("\n")])

def ptrNestedRefName(refname, ptrLevel, nestedPtr=False, refoffset=0, const_array_member=False):
	if ptrLevel > 0:
		return "__" + "_".join(refname.split(".")) + "_" + str(ptrLevel)
	elif not nestedPtr:
		return refname
	if not const_array_member:
		return "/*ATTR(%s)*/ OFFATTR(void**,%d)" % (refname, refoffset)
	else:
		return "/*ATTR(%s)*/ OFFADDR(void**,%d)" % (refname, refoffset)

def ptrNestedRefNameOrRoot(refname, ptrLevel, nestedPtr=False, refoffset=0):
	if ptrLevel > 0:
		return "__" + "_".join(refname.split(".")) + "_" + str(ptrLevel)
	return "__root_ptr"

def isAnonRecordDependent(RT, depT, ftdb) -> bool:
	if RT.id == depT.id:
		return True
	elif (depT.classname == "const_array" or depT.classname == "incomplete_array") and depT.refs[0] == RT.id:
		# struct { u16 index; u16 dist;} near[0];
		return True
	elif depT.classname == "pointer" and depT.refs[0] == RT.id:
		return True
	else:
		if depT.classname == "const_array" or depT.classname == "incomplete_array":
			depT = ftdb.types[depT.refs[0]]
			if depT.classname == "const_array" or depT.classname == "incomplete_array" and depT.refs[0] == RT.id:
				return True
	return False

def prepend_non_empty_lines(s,v):
	return "\n".join([v+x if len(x)>0 else x for x in s.split("\n")])

def extra_newline(s):
	if not s.endswith("\n"):
		return s+"\n"
	else:
		return s

##################################
# Error handling
##################################
class MultipleFunctionException(Exception):
	pass

class NoFunctionException(Exception):
	pass

##################################
# Recipes generator
##################################
class RecipeBase(object):
	def __init__(self,recipe,custom_include_list,simple,to_check,check_union,to_fix,have_flexible_member,custom_recipe):
		self.recipe = recipe
		self.simple = simple
		self.to_check = to_check
		self.check_union = check_union
		self.to_fix = to_fix
		self.have_flexible_member = have_flexible_member
		self.custom_include_list = custom_include_list
		self.custom_recipe = custom_recipe

	def __attrs__(self):
		s=""
		attrs = list()
		if self.simple:
			attrs.append("SIMPLE")
		if self.to_check:
			attrs.append("CHECK")
		if self.check_union:
			attrs.append("UNION")
		if self.to_fix:
			attrs.append("FIX")
		if len(attrs) > 0:
			s = "/* %s */\n" % (" - ".join(attrs))
		return s

	def get_custom_include_list(self):
		return self.custom_include_list

class RecordRecipe(RecipeBase):
	# Flatten struct recipe
	def __init__(self,T,RT,recipe,include,loc,custom_include_list,simple,to_check,check_union,to_fix,have_flexible_member,custom_recipe=False):
		super(RecordRecipe, self).__init__(recipe,custom_include_list,simple,to_check,check_union,to_fix,have_flexible_member,custom_recipe)
		self.RT = RT
		self.include = include # Can be None
		self.loc = loc
	def __str__(self):
		s = super(RecordRecipe, self).__attrs__()
		if self.custom_recipe is True:
			s+="/* Custom recipe for 'struct %s' */\n"%(self.RT.str)
			s+="/* Type definition:\n%s */\n"%(self.RT.defstring)
		s+=self.recipe+"\n"
		return s

class TypenameRecipe(RecipeBase):
	# Flatten struct_type recipe with auto-generated typename
	def __init__(self,typename,RT,recipe,custom_include_list,simple,to_check,check_union,to_fix,have_flexible_member):
		super(TypenameRecipe, self).__init__(recipe,custom_include_list,simple,to_check,check_union,to_fix,have_flexible_member,False)
		self.typename = typename
		self.RT = RT
	def __str__(self):
		s = super(TypenameRecipe, self).__attrs__()
		s+=self.recipe+"\n"
		return s

class RecordTypeRecipe(RecipeBase):
	# Flatten struct_type recipe
	def __init__(self,TPD,RT,recipe,includes,custom_include_list,simple,to_check,check_union,to_fix,have_flexible_member,custom_recipe=False):
		super(RecordTypeRecipe, self).__init__(recipe,custom_include_list,simple,to_check,check_union,to_fix,have_flexible_member,custom_recipe)
		self.TPD = TPD
		self.RT = RT
		self.includes = includes # Can be None
	def __str__(self):
		s = super(RecordTypeRecipe, self).__attrs__()
		if self.custom_recipe is True:
			s+="/* Custom recipe for 'struct %s' (aka '%s') */\n"%(self.RT.str,self.TPD.name)
			s+="/* Type definition:\n%s */\n"%(self.RT.defstring)
		s+=self.recipe+"\n"
		return s

class MemberFunctor(object):
	def __init__(self,method):
		self.method = method
	def call(self,param):
		return self.method(param)

class RecipeGenerator(object):

	# 0 - STRUCT/UNION
	# 1 - struct tag
	# 2 - struct size
	# 3 - internal recipe string
	# 4 - extra type definition
	template_flatten_struct_recipe = """{4}FUNCTION_DEFINE_FLATTEN_{0}_SELF_CONTAINED({1},{2},
{3}
);"""

	# 0 - typename
	# 1 - typesize
	# 2 - internal recipe string
	# 3 - extra type definition
	template_flatten_struct_type_recipe = """{3}FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED({0},{1},
{2}
);"""

	# 0 - struct tag
	# 1 - internal recipe string
	# 2 - extra type definition
	template_flatten_define_struct_flexible_recipe = """{2}FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE({0},
{1}
);"""

	# 0 - typename
	# 1 - internal recipe string
	# 2 - extra type definition
	template_flatten_define_struct_type_flexible_recipe = """{2}FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_FLEXIBLE({0},
{1}
);"""

	# 0 - STRUCT/UNION
	# 1 - struct tag
	# 2 - struct size
	# 3 - refname
	# 4 - member offset
	# 5 - shift size
	# 6 - record count
	# 7 - additional pointer info
	# 8 - safe info
	template_flatten_struct_member_recipe =\
		"  /* AGGREGATE_FLATTEN_STRUCT_ARRAY({1},{3},{6}); */\n{7}AGGREGATE_FLATTEN_{0}_ARRAY_SELF_CONTAINED_SHIFTED({1},{2},{3},{4},{6},{5}); {8}"

	# 0 - typename
	# 1 - typesize
	# 2 - refname
	# 3 - member offset
	# 4 - shift size
	# 5 - record count
	# 6 - additional pointer info
	# 7 - safe info
	template_flatten_struct_type_member_recipe =\
		"  /* AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY({0},{2},{5}); */\n{6}AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED_SHIFTED({0},{1},{2},{3},{5},{4}); {7}"

	# 0 - STRUCT/UNION
	# 1 - struct tag
	# 2 - struct size
	# 3 - refname
	# 4 - record count
	# 5 - safe info
	# 6 - extra message
	# 7 - shift value
	template_flatten_struct_pointer_recipe = "{6}FLATTEN_{0}_ARRAY_SHIFTED_SELF_CONTAINED({1},{2},{3},{4},{7}); {5}"

	# 0 - typename
	# 1 - typesize
	# 2 - refname
	# 3 - record count
	# 4 - safe info
	# 5 - extra message
	# 6 - shift value
	template_flatten_struct_type_pointer_recipe = "{5}FLATTEN_STRUCT_TYPE_ARRAY_SHIFTED_SELF_CONTAINED({0},{1},{2},{3},{6}); {4}"


	# 0 - typename
	# 1 - refname
	# 2 - element count
	# 3 - member offset
	# 4 - safe info
	# 5 - extra message
	template_flatten_type_array_member_recipe = "  /* AGGREGATE_FLATTEN_TYPE_ARRAY({0},{1},{2}); */\n{5}AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED({0},{1},{3},{2}); {4}"

	# 0 - typename
	# 1 - refname
	# 2 - element count
	# 3 - typesize
	# 4 - member offset
	# 5 - safe info
	# 6 - extra message
	template_flatten_compound_type_array_member_recipe =\
		"  /* AGGREGATE_FLATTEN_TYPE_ARRAY({0},{1},{2}); */\n{6}AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED({0},{3},{1},{4},{2}); {5}"

	# 0 - typename
	# 1 - refname
	# 2 - element count
	# 3 - safe info
	# 4 - extra message
	template_flatten_type_array_pointer_recipe = "{4}FLATTEN_TYPE_ARRAY({0},{1},{2}); {3}"

	# 0 - typename
	# 1 - typesize
	# 2 - refname
	# 3 - element count
	# 4 - safe info
	# 5 - extra message
	template_flatten_compound_type_array_pointer_recipe = "{5}FLATTEN_COMPOUND_TYPE_ARRAY({0},{1},{2},{3}); {4}"

	# 0 - refname
	# 1 - member offset
	# 2 - safe info
	# 3 - extra message
	template_flatten_string_member_recipe = "  /* AGGREGATE_FLATTEN_STRING({0}); */\n{3}AGGREGATE_FLATTEN_STRING_SELF_CONTAINED({0},{1}); {2}"

	# 0 - refname
	# 1 - safe info
	# 2 - extra message
	template_flatten_string_pointer_recipe = "{2}FLATTEN_STRING({0}); {1}"

	# 0 -
	# 1 - member offset
	template_flatten_fptr_member_recipe = "  /* AGGREGATE_FLATTEN_FUNCTION_POINTER({0}); */\nAGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED({0},{1});"

	# 0 -
	template_flatten_fptr_pointer_recipe = "FLATTEN_FUNCTION_POINTER({0});"

	# 0 -
	# 1 - refname
	# 2 - member offset
	# 3 - element count
	# 4 -
	# 5 -
	# 6 - safe info
	# 7 - internal pointer flattening recipe
	# 8 - extra message
	template_flatten_pointer_recipe = """{8}AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED({0},{1},{2},{3});\nFOREACH_POINTER({0},{4},{5},{3},{6}
{7}
);"""

	# 0 -
	# 1 -
	# 2 -
	# 3 - element count
	# 4 - safe info
	# 5 - internal pointer flattening recipe
	# 6 - extra message
	template_flatten_pointer_storage_recipe = """{6}FOREACH_POINTER({0},{1},{2},{3},{4}
{5}
);"""

	# 0 -
	# 1 -
	# 2 -
	# 3 - array size
	# 4 -
	template_flatten_pointer_array_recipe = """FOREACH_POINTER({0},{1},{2},{3},
{4}
);"""

	# 0 - element count
	# 1 - struct tag
	# 2 - refname
	# 3 - member offset
	# 4 - safe info
	# 5 - size of the struct tag
	template_flatten_struct_array_storage_recipe = "AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE_SELF_CONTAINED({1},{5},{2},{3},{0}); {4}"

	# 0 - element count
	# 1 - union tag
	# 2 - refname
	# 3 - member offset
	# 4 - safe info
	# 5 - size of the union tag
	template_flatten_union_array_storage_recipe = "AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_SELF_CONTAINED({1},{5},{2},{3},{0}); {4}"

	# 0 - element count
	# 1 - typename
	# 2 - refname
	# 3 - member offset
	# 4 - safe info
	# 5 - size of the typename
	template_flatten_struct_type_array_storage_recipe = "AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE_SELF_CONTAINED({1},{5},{2},{3},{0}); {4}"

	# 0 - struct tag
	# 1 - element size
	# 2 - refname
	# 3 - member offset
	# 4 - safe info
	template_flatten_struct_flexible_recipe = "AGGREGATE_FLATTEN_STRUCT_FLEXIBLE_SELF_CONTAINED({0},{1},{2},{3}); {4}"

	# 0 - union tag
	# 1 - element size
	# 2 - refname
	# 3 - member offset
	# 4 - safe info
	template_flatten_union_flexible_recipe = "AGGREGATE_FLATTEN_UNION_FLEXIBLE_SELF_CONTAINED({0},{1},{2},{3}); {4}"

	# 0 - typename
	# 1 - element size
	# 2 - refname
	# 3 - member offset
	# 4 - safe info
	template_flatten_struct_type_flexible_recipe = "AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE_SELF_CONTAINED({0},{1},{2},{3}); {4}"

	# 0 - typename
	# 1 - typesize
	# 2 - refname
	# 3 - member offset
	template_flatten_type_array_flexible_recipe = "AGGREGATE_FLATTEN_TYPE_ARRAY_FLEXIBLE_SELF_CONTAINED({0},{1},{2},{3}); {4}"

	# 0 - member pointer typestring
	# 1 - member array element size
	# 2 - member array offset
	# 3 - member array refname
	# 4 -
	# 5 -
	# 6 - recipe body
	# 7 - extra message
	# 8 - safe info
	template_flatten_pointer_array_flexible_recipe = \
"""{7}AGGREGATE_FLATTEN_TYPE_ARRAY_FLEXIBLE_SELF_CONTAINED({0},{1},{3},{2}); {8}
  FOREACH_POINTER(
    {0},
    {4},
    {5},
    (FLATTEN_DETECT_OBJECT_SIZE({5},{1})/{1}),
  {6}
  );"""

	# 0 - sizeof(struct list_head)
	# 1 - 'list_head' member name
	# 2 - 'list_head' member offset
	# 3 - 'list_head.next' member offset
	# 4 - 'list_head.prev' member offset
	# 5 - container type string the list entries points to
	# 6 - offset of the 'list_head' member in the container type
	# 7 - size of the container type
	# 8 - additional information
	template_aggregate_flatten_list_head_struct_member_recipe =\
"""{8}AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(list_head,{0},{1}.next,{3},1);
AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(list_head,{0},{1}.prev,{4},1);
{{
	struct {5}* __entry;
	list_for_each_entry_from_offset(__entry, &OFFATTR(struct list_head,{2}), {6} ) {{
		FOR_VIRTUAL_POINTER(__entry,
				FLATTEN_STRUCT_ARRAY_SELF_CONTAINED({5},{7},__entry,1);
		);
	}}
}}"""

	# 0 - sizeof(struct list_head)
	# 1 - pointer to global variable
	# 2 - container type string the list entries points to
	# 3 - offset of the 'list_head' member in the container type
	# 4 - size of the container type
	# 5 - additional information
	template_flatten_list_head_struct_member_recipe =\
"""{5}FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(list_head,{0},{1},1);
{{
	struct {2}* __entry;
	struct list_head* __lhead = (struct list_head*){1};
	list_for_each_entry_from_offset(__entry, __lhead, {3} ) {{
		FLATTEN_STRUCT_ARRAY_SELF_CONTAINED({2},{4},__entry,1);
	}}
}}"""

	template_flatten_struct_array_self_contained = \
		"FUNCTION_DEFINE_FLATTEN_{0}_ARRAY_SELF_CONTAINED({1},{2});"
	template_flatten_struct_type_array_self_contained = \
		"FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED({0},{1});"
	template_flatten_declare_struct_array_self_contained = \
		"FUNCTION_DECLARE_FLATTEN_{0}_ARRAY_SELF_CONTAINED({1});"
	template_flatten_declare_struct_type_array_self_contained = \
		"FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED({0});"

	# 0 - STRUCT/UNION
	# 1 - struct tag
	# 2 - struct size
	# 3 - refname
	# 4 - element count
	# 5 - extra message
	template_flatten_struct_array_pointer_self_contained = \
		"{5}FLATTEN_{0}_ARRAY_SELF_CONTAINED({1},{2},{3},{4});"

	# 0 - typename
	# 1 - typesize
	# 2 - refname
	# 3 - element count
	# 4 - extra message
	template_flatten_struct_type_array_pointer_self_contained = \
		"{4}FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED({0},{1},{2},{3});"


	## Arguments:
	##  - list of global variables
	##	- pre handler for finding global vars
	##  - list of recipe registrations
	##  - list of recipe de-registrations
	template_output_recipes_source = """/* This file is autogenerated (with possible requirement of minor modifications). Do it at your own peril! */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>
#include <linux/percpu-defs.h>

#include "kflat.h"
#include "kflat_recipe.h"

#include "common.h"

%s


static void prehandler_globals_search(struct kflat* kflat) {
	%s

}

%s

KFLAT_RECIPE_LIST(
%s
);

KFLAT_RECIPE_MODULE("Autogenerated kFlat recipe for %s");
"""


	template_output_recipes_trigger_source = """/* This file is autogenerated (with possible requirement of minor modifications). Do it at your own peril! */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

#include "common.h"

%s%s
"""

	template_output_recipe_handler = """
static void handler_{0}(struct kflat* kflat, struct probe_regs* regs) {{
	{1}

	{2}
}}
"""

	# 0 - full type of argument
	# 1 - position of argument
	# 2 - size of argument
	# 3 - argument shift
	# 4 - real type string of the argument (after the possible shift)
	# 5 - size of the real type
	# 6 - additional information (if any)
	# 7 - additional triggers specification
	template_output_struct_arg_handler = """
	// Dump argument no. {1}
	{{
		{0} *target = ({0}*) regs->arg{1};
{6}
		FOR_EXTENDED_ROOT_POINTER(target, "_func_arg_{1}", {2},
				FLATTEN_STRUCT_SHIFTED_SELF_CONTAINED({4}, {5}, target, {3});{7}
		);
	}}
"""

	# 0 - full type of argument
	# 1 - position of argument
	# 2 - size of argument
	# 3 - argument shift
	# 4 - real type string of the argument (after the possible shift)
	# 5 - size of the real type
	# 6 - additional information (if any)
	# 7 - additional triggers specification
	template_output_struct_type_arg_handler = """
	// Dump argument no. {1}
	{{
		{0} *target = ({0}*) regs->arg{1};
{6}
		FOR_EXTENDED_ROOT_POINTER(target, "_func_arg_{1}", {2},
				FLATTEN_STRUCT_TYPE_SHIFTED_SELF_CONTAINED({4}, {5}, target, {3});{7}
		);
	}}
"""

	# 0 - name of global variable inc. kernel module
	# 1 - unique hash of global variable
	template_output_global_variable = """
static void* {1} = NULL;"""

	# 0 - name of global variable inc. kernel module
	# 1 - unique hash of global variable
	# 2 - additional code for validating memory size of builtin types (empty for non built-in types)
	template_output_global_pre_handler = """
	{1} = flatten_global_address_by_name("{0}");{2}"""

	# 0 - name of global variable inc. kernel module
	# 1 - unique hash of global variable
	# 2 - size of global variable according to FTDB
	template_validate_inmem_code = """if({1} != NULL && flatten_validate_inmem_size((unsigned long){1}, {2} /* FTDB size value */ )) {{
	flat_errs(\"Size difference between FTDB and kallsyms for {0} global\");
	{1} = NULL;
}}"""

	# 0 - name of global variable inc. kernel module
	# 1 - name of global var
	# 2 - size of global var
	# 3 - flattening commands
	# 4 - unique hash of global variable
	# 5 - pointer to be flattened
	# 6 - definition of the global
	# 7 - global hash
	template_output_global_handler = """
	// Dump global {0}
	// hash: '{7}'
	/* {6} */
	do {{
		void* addr = {4}; /* Addr set by pre_handler */
		if(addr == NULL) {{
			pr_err("skipping global {0} ...");
			break;
		}}

		FOR_EXTENDED_ROOT_POINTER({5}, "{1}", {2},
{3}
		);
	}} while(0);
"""

	# 0 - name of global variable inc. kernel module
	# 1 - name of global var
	# 2 - size of global var
	# 3 - flattening commands
	# 4 - unique hash of global variable
	# 5 - pointer to be flattened
	# 6 - definition of the global
	# 7 - global hash
	template_output_per_cpu_global_handler = """
	// Dump global indirect per_cpu variable {0}
	// hash: '{7}'
	/* {6} */
	do {{
		void* per_cpu_var = NULL;
		void* addr = {4}; /* Addr set by pre_handler */
		if(addr == NULL) {{
			pr_err("skipping global {0} ...");
			break;
		}}
		per_cpu_var = this_cpu_ptr(*(void**)addr);

		FOR_EXTENDED_ROOT_POINTER(&per_cpu_var, "{1}", {2},
{3}
		);
	}} while(0);
"""

	# Well, some of the struct types below are pulled in when <linux/module.h> and <linux/kflat.h> headers are included in the generated module source file
	# So either blacklisting the below or extracting required symbols from both headers above
	struct_type_blacklist = set([
		"kgid_t",
		"kuid_t",
		"uuid_t",
		"Elf64_Sym",
		"pgd_t",
		"cpumask_t",
		"wait_queue_head_t",
		"atomic64_t",
		"atomic_long_t",
		"atomic_t",
		"rwlock_t",
		"seqlock_t",
		"seqcount_t",
		"spinlock_t",
		"kernel_cap_t",
		"arch_spinlock_t",
		"raw_spinlock_t",
		"wait_queue_entry_t",
		"pgprot_t",
		"mm_segment_t",
		"kernel_siginfo_t",
		"nodemask_t",
		"pg_data_t",
		"guid_t",
		"seqcount_raw_spinlock_t",
		"irq_cpustat_t"])

	## Arguments
	##  - recipe module name
	##  - list of object files for the interface module
	template_cmake_recipes = """# Auto-generated CMake file
set(KBUILD_CMD $(MAKE) M=${{CMAKE_CURRENT_BINARY_DIR}} src=${{CMAKE_CURRENT_SOURCE_DIR}} ${{KBUILD_FLAGS}} modules)
set(RECIPE_SOURCE_NAME {1})
set(TARGET_NAME {0})

string(REPLACE ";" " " RECIPE_SOURCE_NAME "${{RECIPE_SOURCE_NAME}}")

set(DEPENDENT_SOURCES ${{RECIPE_SOURCE_NAME}})
string(REPLACE ".o" ".c" DEPENDENT_SOURCES "${{DEPENDENT_SOURCES}}")

configure_file(${{PROJECT_SOURCE_DIR}}/cmake/Kbuild.recipe_template.in ${{CMAKE_CURRENT_SOURCE_DIR}}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${{RECIPE_SOURCE_NAME}}
    COMMAND ${{KBUILD_CMD}}
    WORKING_DIRECTORY ${{CMAKE_CURRENT_BINARY_DIR}}
    VERBATIM
)
add_custom_target(${{TARGET_NAME}} ALL DEPENDS kflat_core ${{RECIPE_SOURCE_NAME}})
"""

	template_common_recipes = """#ifndef __COMMON_H__
#define __COMMON_H__

%s

%s
%s

%s

%s

#endif /* __COMMON_H__ */
"""

	TABSIZE = 2

	FLATTEN_STRUCT_BLACKLIST = set(["kflat","hrtimer_clock_base"])
	FLATTEN_STRUCT_TYPE_BLACKLIST = set([])

	def __init__(self,args):
		if args.database.endswith('.json') and not os.path.exists(args.database + '.img'):

			print('--- Creating FTDB database')
			with open(args.database, "rb") as f:
				db = json.load(f)
			libftdb.create_ftdb(db, args.database + '.img', True)
			print(f'--- FTDB database created at {args.database}.img')
			del db

		if os.path.exists(args.database + '.img'):
			args.database += '.img'

		self.ftdb = libftdb.ftdb()
		self.ftdb.load(args.database,debug=False,quiet=True)
		print(f'--- Database loaded from {args.database}')

		self.gftdb = None
		if args.global_database is not None:
			self.gftdb = libftdb.ftdb()
			self.gftdb.load(args.global_database,debug=False,quiet=True)

		self.include_dirs = list()
		if args.include_dirs is not None:
			self.include_dirs+=args.include_dirs.split(":")

		self.ignore_structs = set([])
		self.ignore_struct_types = set([])
		if args.ignore_structs is not None:
			self.ignore_structs|=set(args.ignore_structs.split(","))
			self.ignore_struct_types|=set(args.ignore_structs.split(","))
		self.anontype_index = 0
		self.check_count = 0
		self.gen_count = 0
		self.ignore_count = 0
		self.not_safe_count = 0
		self.member_count = 0
		self.member_recipe_count = 0
		self.not_used_count = 0
		self.user_count = 0
		self.pointer_to_struct_count = 0
		self.verified_pointer_to_struct_count = 0
		self.structs_done = list()
		self.structs_done_match = set([])
		self.struct_types_done = list()
		self.struct_types_done_match = set([])
		self.structs_missing = set([])
		self.struct_types_blacklisted = set([])
		self.structs_blacklisted = set([])
		self.ptr_in_union = list()
		self.flexible_array_members = list()
		self.incomplete_array_member_storage = list()
		self.complex_members = list()
		self.complex_pointer_members = list()
		self.enum_pointers = list()
		self.user_memory_pointer_members = list()
		self.char_pointers = list()
		self.void_pointers = list()
		self.void_pointers_resolved = list()
		self.void_pointers_resolved_ambiguous = list()
		self.void_pointers_not_resolved = list()
		self.generic_pointer_members = list()
		self.generic_pointer_members_unresolved = list()
		self.generic_pointer_members_resolved_unambiguously = list()
		self.builtin_pointers = list()

		self.includes = set([])
		self.unresolved_struct_includes = list()
		self.unresolved_struct_type_includes = list()

		self.record_recipes = list()
		self.typename_recipes = list()
		self.record_type_recipes = list()
		self.warnings = list()

		self.debug = args.verbose

		if self.debug:
			print("--- Total number of global variables: %d"%(len(self.ftdb.globals)))
			print("--- Number of distinct types used by global variables: %d"%(len(set([x.type for x in self.ftdb.globals]))))
			print("--- Total number of functions: %d"%(len(self.ftdb.funcs)))
			print("--- Number of record types: %d"%(len([x for x in self.ftdb.types if x.classname=="record"])))

		self.anon_record_id_map = {}
		self.anon_enum_id_map = {}

		self.global_base_addr = 0
		self.allowed_members = {}
		self.anchor_list = set([])
		self.char_type = self.get_char_type()

		self.sizeof_pattern = re.compile("@\{\s*[st]\:[\w]+\s*\}")
		self.this_member_pattern = re.compile("#\{\s*[\w\.]+\s*\}")
		self.typedef_pattern = re.compile("\&\{\s*[steg]\:[\w]+\s*\:?[\w]*\s*\}")
		self.offsetof_pattern = re.compile("\$\{\s*[\w]+\s*,\s*[st]\:[\w]+\s*\}")
		self.enum_value_pattern = re.compile("\%\{\s*[e]\:[\w]+\:[\w]+\s*\}")
		self.global_pattern = re.compile("\*\{\s*[\w]+\s*\}")
		self.include_pattern = re.compile("\^\{\s*.+\s*\}")
		self.adddep_pattern = re.compile("\!\{\s*[st]\:[\w]+\s*\}")
		self.include_config_pattern = re.compile("\~\{\s*.+\s*\}")

		self.custom_recipe_map = {}
		self.custom_recipe_member_map = {}
		self.additional_custom_recipe_deps = {}
		self.members_with_custom_recipes = list()

	def get_func_module_name(self, func):
		"""
			For a given function `func` (FTDB func object) returns the module name
			where it resides
		"""
		mids_without_vmlinux = [mid for mid in func.mids if not self.gftdb.modules[mid].endswith('/vmlinux')]
		mids_with_bazel_sandboxes_merged = list({''.join(self.gftdb.modules[mid].split('__main__/out/')[1:]): mid for mid in mids_without_vmlinux}.values())
		if len(func.mids) == 1:
			target_mid = func.mids[0]
		elif len(mids_without_vmlinux) == 1:
			target_mid = mids_without_vmlinux[0]
		elif len(mids_with_bazel_sandboxes_merged) == 1:
			target_mid = mids_with_bazel_sandboxes_merged[0]
		else:
			raise RuntimeError("Failed to uniquely match kernel module for input function")
		return os.path.basename(self.gftdb.modules[target_mid]).replace('.ko', '').replace('-', '_')

	def get_off_target_entry(self):
		with open('ids.json', 'r') as f:
			funcs = json.load(f)['entry_funcs']
		if len(funcs) != 1:
			raise RuntimeError("Unexpected number of entrypoint function IDs found in ids.json")

		if '@' in funcs[0]:
			name, loc = funcs[0].split('@')
			funcs = [f for f in self.gftdb.funcs.entry_by_name(name) if f.location.split(':')[0] == loc]
		else:
			funcs = [f for f in self.gftdb.funcs.entry_by_name(funcs[0])]
			if len(funcs) > 1:
				raise RuntimeError("Failed to uniquely identify function - use format <name@location>")
		return funcs[0]

	def gen_recipe_id(self):
		if self.gftdb is None:
			raise ValueError("Cannot generate recipe_id without global FTDB database")

		target = self.get_off_target_entry()
		module = self.get_func_module_name(target)
		return (module + ':' if module != 'vmlinux' else '') + target.name

	def gen_args_list(self, func):
		if self.gftdb is None:
			raise ValueError("Cannot generate list of input arguments without global FTDB database")
		if 'init_data' not in self.gftdb:
			raise ValueError("Arguments list can only be generated for FTDB imported to aot.py (no 'init_data')")

		func_inits = [init for init in self.gftdb.init_data if init['name'] == func]
		if len(func_inits) > 1:
			raise RuntimeError("Unexpected number of entries in init_data for input function")
		elif len(func_inits) == 0:
			raise RuntimeError("Cannot find target function in init_file - provide list of arguments manually")
		func_init = func_inits[0]

		func_entry = self.get_off_target_entry()
		func_args = [d for d in sorted(func_entry.locals, key=lambda x: x.id) if d.parm]

		args_list = []
		for i, arg in enumerate(func_args):
			skip = False
			for item in func_init['items']:
				if arg.name in item['name']:
					skip = True
					break

			if skip or i >= 4:
				continue
			if func_init['interface'] == 'ioctl' and i >= 1:
				continue

			target = self.gftdb.types[arg.type].refs
			if len(target) == 0:
				continue
			args_list.append(f'{self.gftdb.types[target[0]].str}@{i+1}')
		print(f"Detected following input arguments: {args_list}")
		return args_list

	def _find_member_offset(self,RT,member_to_find,ftdb):

		real_refs = list()
		ignore_count=0
		for i in range(len(RT.refnames)-RT.attrnum):
			if i in RT.decls and ( RT.refnames[i]!="__!anonrecord__" or (i+1<len(RT.refs) and
				isAnonRecordDependent(ftdb.types[RT.refs[i]],ftdb.types[RT.refs[i+1]],ftdb))):
				ignore_count+=1
				continue
			real_refs.append( (RT.refs[i],RT.refnames[i],RT.memberoffsets[i-ignore_count],[],[]) )
		while len(real_refs)>0:
			mTID,mName,mOff,mOffLst,rfnLst = real_refs.pop(0)
			refname = ".".join(rfnLst+[mName])
			moffset = sum(mOffLst+[mOff])
			MT = ftdb.types[mTID]
			if MT.classname=="typedef":
				MT = self.walkTPD(MT,ftdb)
			if MT.classname=="record":
				if member_to_find==refname:
					return moffset
				internal_real_refs = list()
				if not member_to_find.startswith(refname):
					continue
				ignore_count=0
				for i in range(len(MT.refnames)-MT.attrnum):
					if i in MT.decls and ( MT.refnames[i]!="__!anonrecord__" or (i+1<len(MT.refs) and
						isAnonRecordDependent(ftdb.types[MT.refs[i]],ftdb.types[MT.refs[i+1]],ftdb))):
						ignore_count+=1
						continue
					else:
						member_list = list()
						if mName!="__!anonrecord__":
							member_list.append(mName)
						internal_real_refs.append( (MT.refs[i],MT.refnames[i],MT.memberoffsets[i-ignore_count],mOffLst+[mOff],rfnLst+member_list) )
				real_refs = internal_real_refs+real_refs
				continue
			if member_to_find==refname:
				return moffset
		return None

	def _has_flexible_member(self,RT,ftdb):

		real_refs = list()
		ignore_count=0
		last_member_type = None
		for i in range(len(RT.refnames)-RT.attrnum):
			if i in RT.decls and ( RT.refnames[i]!="__!anonrecord__" or (i+1<len(RT.refs) and
				isAnonRecordDependent(ftdb.types[RT.refs[i]],ftdb.types[RT.refs[i+1]],ftdb))):
				ignore_count+=1
				continue
			real_refs.append( (RT.refs[i],RT.refnames[i],RT.memberoffsets[i-ignore_count],[],[]) )
		while len(real_refs)>0:
			mTID,mName,mOff,mOffLst,rfnLst = real_refs.pop(0)
			refname = ".".join(rfnLst+[mName])
			moffset = sum(mOffLst+[mOff])
			MT = ftdb.types[mTID]
			if MT.classname=="typedef":
				MT = self.walkTPD(MT,ftdb)
			if MT.classname=="record":
				internal_real_refs = list()
				ignore_count=0
				for i in range(len(MT.refnames)-MT.attrnum):
					if i in MT.decls and ( MT.refnames[i]!="__!anonrecord__" or (i+1<len(MT.refs) and
						isAnonRecordDependent(ftdb.types[MT.refs[i]],ftdb.types[MT.refs[i+1]],ftdb))):
						ignore_count+=1
						continue
					else:
						member_list = list()
						if mName!="__!anonrecord__":
							member_list.append(mName)
						internal_real_refs.append( (MT.refs[i],MT.refnames[i],MT.memberoffsets[i-ignore_count],mOffLst+[mOff],rfnLst+member_list) )
				real_refs = internal_real_refs+real_refs
				continue
			last_member_type = MT
		if last_member_type is None:
			return False
		if last_member_type.classname=='const_array' or last_member_type.classname=='incomplete_array':
			sz = last_member_type.size//8
			if sz==0:
				# Currently we can have FP in such case when we have an array of non-zero size of empty structs of size 0
				#  Why would anyone do that anyway?
				return True
		return False

	def _find_enum_type_by_tag(self,tag,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		results = [
			x
			for x in ftdb.types
			if x.classname == 'enum' and x.str == tag and not x.isConst()
		]
		if len(results)==0:
			print(f"EE- Failed to locate enum type with tag - '{tag}'")
			exit(1)
		if len(results)>1:
			print(f"EE- Failed to uniquely identify enum type with tag - '{tag}'")
			exit(1)
		return results[0]

	def _find_record_type_by_tag(self,tag,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		results = [
			x
			for x in ftdb.types
			if x.classname == 'record' and x.str == tag and not x.isConst()
		]
		if len(results) == 0:
			print(f"EE- Failed to locate structure type with tag - '{tag}'")
			exit(1)
		elif len(results) > 1:
			print(f"EE- Failed to uniquely identify structure type with tag - '{tag}'")
			exit(1)
		return results[0]

	def _find_record_type_by_typestring(self,typestring,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		prefix,tag = typestring.split(":")
		if prefix=='s':
			TPD = None
			RT = self._find_record_type_by_tag(tag,ftdb)
		elif prefix=='t':
			TPD = self._find_typedef_type_by_name(tag,ftdb)
			RT = self.walkTPD(TPD,ftdb)
			if RT.classname!='record':
				print(f"EE- Couldn't resolve a typestring to record type - '{typestring}'")
		else:
			print(f"EE- Invalid prefix in record typestring - '{typestring}'")
		return RT,TPD

	def _find_typedef_type_by_name(self,name,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		results = [
			x
			for x in ftdb.types
			if x.classname == 'typedef' and x.name == name and not x.isConst()
		]
		if len(results) == 0:
			print(f"EE- Failed to locate typedef'ed type with name - '{name}'")
			exit(1)
		elif len(results) > 1:
			print(f"EE- Failed to uniquely identify typedef'ed type with name - '{name}'")
			exit(1)
		return results[0]

	def _find_builtin_type_by_name(self,name,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		results = [
			x
			for x in ftdb.types
			if x.classname == 'builtin' and x.str == name and not x.isConst()
		]
		if len(results) == 0:
			print(f"EE- Failed to locate builtin type - '{name}'")
			exit(1)
		elif len(results) > 1:
			# Just pick one (for builtin types)
			pass
		return results[0]

	"""
	@{s:net_device} -> sizeof(struct net_device)
	# ${__member__,s:binary_header} -> offsetof(strut binary_header,__member__)
	"""
	def _type_offset_calculate(self,offset,kind=OFFSET_KIND_MIXED,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		if isinstance(offset,int):
			return str(offset)
		m = self.sizeof_pattern.search(offset)
		while m:
			__prefix,__tag = m.group()[2:-1].split(":")
			if __prefix=='s':
				size = self._find_record_type_by_tag(__tag,ftdb).size//8
				tp = f'struct {__tag}'
			else:
				size = self._find_typedef_type_by_name(__tag,ftdb).size//8
				tp = f'{__tag}'
			if kind==OFFSET_KIND_CONCRETE:
				replacement_string = f'((size_t){size})'
			elif kind==OFFSET_KIND_SYMBOLIC:
				replacement_string = f'(sizeof({tp}))'
			else:
				replacement_string = f'((size_t){size}/*sizeof({tp})*/)'
			offset = offset[:m.span()[0]] + replacement_string + offset[m.span()[1]:]
			m = self.sizeof_pattern.search(offset)
		m = self.offsetof_pattern.search(offset)
		while m:
			offsetof_params = m.group()[2:-1]
			offT = offsetof_params.split(",")
			if len(offT)!=2:
				print(f"EE- Invalid offsetof specification string: '{offsetof_params}'")
				exit(1)
			member = offT[0]
			record_string = offT[1]
			RT,TPD = self._find_record_type_by_typestring(record_string,ftdb)
			offval = self._find_member_offset(RT,member,ftdb)
			if offval is None:
				print(f"EE- Failed to compute record offset for member '{member}' @ '{record_string}'")
				exit(1)
			__prefix,__tag = record_string.split(":")
			if __prefix=='s':
				tp = f'struct {__tag}'
			else:
				tp = f'{__tag}'
			if kind==OFFSET_KIND_CONCRETE:
				replacement_string = f'((size_t){offval//8})'
			elif kind==OFFSET_KIND_SYMBOLIC:
				replacement_string = f'(offsetof({member},{tp}))'
			else:
				replacement_string = f'((size_t){offval//8}/*offsetof({member},{tp})*/)'
			offset = offset[:m.span()[0]] + replacement_string + offset[m.span()[1]:]
			m = self.offsetof_pattern.search(offset)
		return offset

	"""
	#{__member__} -> offsetof(__this_,__member__)
	"""
	def instantiate_this_member_patterns(self,s,record_string,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		RT = None
		m = self.this_member_pattern.search(s)
		while m:
			member = m.group()[2:-1]
			if RT is None:
				RT,TPD = self._find_record_type_by_typestring(record_string,ftdb)
			offset = self._find_member_offset(RT,member,ftdb)
			if offset is None:
				print(f"EE- Failed to compute record offset for member '{member}' @ '{record_string}'")
				exit(1)
			s = s[:m.span()[0]] + f'((void*)((unsigned char*)_ptr + {offset})/*{member}*/)' + s[m.span()[1]:]
			m = self.this_member_pattern.search(s)
		return s

	"""
	&{t:table} -> defstring of t:table
	"""
	def instantiate_typedef_patterns(self,s,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		m = self.typedef_pattern.search(s)
		while m:
			pattern = m.group()[2:-1]
			tt = pattern.split(":")
			kind,name = (tt[0],tt[1])
			typename = None
			if len(tt)>2:
				typename = tt[2]
			if kind=='g':
				if not ftdb.globals.contains_name(name):
					print(f"EE- Failed to find global variable by name '{name}'")
					exit(1)
				gL = ftdb.globals.entry_by_name(name)
				if len(gL)>1:
					print(f"EE- Failed to uniquely identify global variable by name '{name}'")
					exit(1)
				s = s[:m.span()[0]] + f'{gL[0].defstring};' + s[m.span()[1]:]
			else:
				# We need to handle type definitions
				if kind=='t':
					tp = self._find_typedef_type_by_name(name,ftdb)
					T = self.walkTPD(tp,ftdb)
				elif kind=='s':
					T = self._find_record_type_by_tag(name,ftdb)
				elif kind=='e':
					T = self._find_enum_type_by_tag(name,ftdb)
				else:
					print(f"EE- Unsupported type definition pattern: '{pattern}'")
					exit(1)
				if typename is not None:
					s = s[:m.span()[0]] + f'typedef {T.defstring} {typename};' + s[m.span()[1]:]
				else:
					s = s[:m.span()[0]] + f'{T.defstring};' + s[m.span()[1]:]
			m = self.typedef_pattern.search(s)
		return s

	"""
	%{e:amd_hw_ip_block_type:MAX_HWIP} -> enum_value(MAX_HWIP)
	"""
	def instantiate_enum_value_patterns(self,s,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		m = self.enum_value_pattern.search(s)
		while m:
			enumvaluestring = m.group()[2:-1]
			enumstring = ":".join(enumvaluestring.split(":")[:2])
			enumval = enumvaluestring.split(":")[-1]
			tpkind,tpname = enumstring.split(":")
			if tpkind!='e':
				print(f"EE- Invalid enum prefix '{tpkind}' in '{enumstring}'")
				exit(1)
			eT = self._find_enum_type_by_tag(tpname,ftdb)
			if enumval not in eT.identifiers:
				print(f"EE- Invalid enum value '{enumval}' in enum '{enumstring}'")
				exit(1)
			eT.values[eT.identifiers.index(enumval)]
			s = s[:m.span()[0]] + f'(({ftdb.types[eT.refs[0]].str}){eT.values[eT.identifiers.index(enumval)]}/*{enumvaluestring}*/)' + s[m.span()[1]:]
			m = self.enum_value_pattern.search(s)
		return s

	"""
	*{__global_symbol} -> __global_symbol*
	"""
	def instantiate_global_patterns(self,s):
		m = self.global_pattern.search(s)
		while m:
			global_name = m.group()[2:-1]
			s = s[:m.span()[0]] + f'(flatten_global_address_by_name("{global_name}")/*{global_name}*/)' + s[m.span()[1]:]
			m = self.global_pattern.search(s)
		return s

	"""
	^{__file} -> #include <__file>
	"""
	def instantiate_include_patterns(self,s):
		m = self.include_pattern.search(s)
		include_list = list()
		while m:
			fn = m.group()[2:-1]
			skip_newline=0
			if s[m.span()[1]]=='\n':
				skip_newline=1
			s = s[:m.span()[0]] + s[m.span()[1]+skip_newline:]
			include_list.append("<"+fn+">")
			m = self.include_pattern.search(s)
		return (s,include_list)

	"""
	!{s:ip} -> add dep for struct ip
	"""
	def instantiate_adddep_patterns(self,s,record_string):
		m = self.adddep_pattern.search(s)
		while m:
			depstring = m.group()[2:-1]
			skip_newline=0
			if s[m.span()[1]]=='\n':
				skip_newline=1
			s = s[:m.span()[0]] + s[m.span()[1]+skip_newline:]
			if record_string not in self.additional_custom_recipe_deps:
				self.additional_custom_recipe_deps[record_string] = set()
			self.additional_custom_recipe_deps[record_string].add(depstring)
			m = self.include_pattern.search(s)
		return s

	def resolve_additional_custom_recipe_deps(self,record_string):
		result_set = set()
		working_set = set()
		if record_string in self.additional_custom_recipe_deps:
			working_set|=self.additional_custom_recipe_deps[record_string]
		while len(working_set)>0:
			dep = working_set.pop()
			result_set.add(dep)
			if dep in self.additional_custom_recipe_deps:
				working_set|={x for x in self.additional_custom_recipe_deps[dep] if x not in result_set}
		return result_set

	def parse_arguments(self, args: List[str], globals_file: Optional[str] = None, func: Optional[str] = None) -> Tuple[list, list, set]:
		"""
		Accepted input format:
			func_args: <type>@<number>			- device@1, device
			globals: <global_name>:location		- poolinfo_table:char/random.c
		Returns:
			 func_args_to_dump
				[
					(	record_typename,
						argument_pos_starting_from_1,
						typesize_in_bytes,
						record_classname ('record' or 'typedef'),
						type offset
					),
					...
				]
			globals_to_dump
				[
					(	global_type_str,
						global_type_id,
						global_name,
						module_name_for_global,
						global_type_size_in_bytes
						global_hash
					),
					...
				]
			deps
				[
					(
						recipe_gen_type_id
						recipe_gen_type_str
					),
					...
				]
		"""
		func_args_to_dump = []
		globals_to_dump = []
		deps = set()

		def _find_RI_for_str(type: str) -> Tuple[tuple, int]:
			tt = type.split(":")
			tpkind,tpname = (tt[0],tt[1])
			if tpkind!='s' and tpkind!='t':
				return (None,None)
			if tpkind=='s':
				results = [
					x
					for x in self.ftdb.types
					if x.classname == 'record' and x.str == tpname and not x.isConst()
				]
			else:
				results = [
					x
					for x in self.ftdb.types
					if x.classname == 'typedef' and x.name == tpname and not x.isConst()
				]
			if len(results) == 0:
				print(f"EE- Failed to locate structure type with string - '{type}'")
				exit(1)
			elif len(results) > 1:
				print(f"EE- Failed to uniquely identify structure type with string - '{type}'")
				exit(1)

			res = results[0]
			return (res.id, res.str if res.classname == 'record' else res.name)

		def _find_RI_for_func(type: str) -> Tuple[tuple, int]:
			results = [
				x
				for x in self.ftdb.types
				if x.classname == 'record' and x.str == type and not x.isConst()
			] +\
			[
				x
				for x in self.ftdb.types
				if x.classname == 'typedef' and x.name == type and not x.isConst()
			]
			if len(results) == 0:
				print(f"EE- Failed to locate structure type named - '{type}'")
				exit(1)
			elif len(results) > 1:
				print(f"EE- Failed to uniquely identify structure type named - '{type}'")
				exit(1)

			res = results[0]
			return (res.id, res.str if res.classname == 'record' else res.name), res.size // 8, res.classname

		def _find_RI_for_global(name: str = '', loc_suffix: str = '') -> Tuple[tuple, str]:
			results = [x for x in self.ftdb.globals
						if x.name == name and self.ftdb.sources[x.fid].endswith(loc_suffix)]
			if len(results) == 0:
				print(f"WW- Failed to locate global named - '{name}' @ {loc_suffix}")
				return None
			elif len(results) > 1:
				print(f"EE- Failed to uniquely identify global named - '{name}' @ {loc_suffix}")
				return None
			result = results[0]
			type = self.ftdb.types[result.type]
			module = ''	# TODO: use gftdb to properly detect global variable module - for now default to vmlinux

			nonConstType = type.toNonConst()
			RT,TPD = self.resolve_record_type(nonConstType.id)
			if RT is None:
				return ((None,None), module, type.size // 8, result.hash)
			return ((RT.id if TPD is None else TPD.id,RT.str if TPD is None else TPD.name), module, type.size // 8, result.hash)

		def trig_info_valid(trig_info):
			if "type" not in trig_info:
				return True
			if trig_info["type"]=="update" or trig_info["type"]=="append":
				return True
			return False

		def trig_info_update(trig_info):
			if "type" not in trig_info or trig_info["type"]=="update":
				return True
			return False

		def trig_info_with_update(trig_info_list):
			for trig_info in trig_info_list:
				if trig_info_update(trig_info):
					return trig_info
			return None

		def trig_info_additional_deps(trig_info):
			deps_list = set()
			if 'deps' in trig_info:
				deps = trig_info["deps"]
				if isinstance(deps,str):
					deps = [deps]
				for x in deps:
					deps_list.add(_find_RI_for_str(x))
			return deps_list

		func_info = [fT[3] for fT in self.config["OT_info"]["functions"] if fT[0]==func]
		if len(func_info)==0:
			print (f'EE- Cannot find function information in the OT config file for function \'{func}\'')
			exit(1)
		if len(func_info)>1:
			print (f'EE- Cannot uniquely identify function information in the OT config file for function \'{func}\'')
			exit(1)
		func_loc = func_info[0].split(":")[0]

		trigger_info_map = {}
		if func and "trigger_list" in self.config["base_config"]:
			for ti,trig_info in enumerate(self.config["base_config"]["trigger_list"]):
				if not trig_info_valid(trig_info):
					print (f'WW- Ignored invalid trigger type \'{trig_info["type"]}\' in trigger_list[config] at index \'{ti}\'')
					continue
				if isinstance(trig_info["trigger_fn"],str):
					func_list = [trig_info["trigger_fn"]]
				else:
					func_list = trig_info["trigger_fn"]
				for fn in func_list:
					fnT = [x.strip() for x in fn.split("@")]
					__fn = fnT[0]
					__loc = ""
					if len(fnT)>1:
						__loc = fnT[1]
					if __loc!="" and __loc not in func_loc:
						continue
					if __fn!=func:
						continue
					if __fn in trigger_info_map:
						if trig_info_update(trig_info) and trig_info_with_update(trigger_info_map[fn]) is not None:
							print (f'EE- Duplicated update information in trigger_list[config] regarding function \'{fn}\'')
							exit(1)
						trigger_info_map[__fn].append(trig_info)
					else:
						trigger_info_map[__fn] = [trig_info]

		for arg in args:
			if ':' in arg:
				name, loc = arg.split(':')
				GRI = _find_RI_for_global(name, loc)
				if GRI is None:
					continue
				dep, module, size, hash = GRI
				globals_to_dump.append((dep[1], dep[0], name, module, size, hash))
				if dep[0] is not None:
					deps.add(dep)
			else:
				if not func:
					continue
				# default to first function argument
				pos = 1
				if '@' in arg:
					arg, pos = arg.split('@')
				# [0:res.id, 1:res.str if res.classname == 'record' else res.name), 2:res.size // 8, 3:res.classname, 4:offset]
				if func in trigger_info_map:
					trig_info = trig_info_with_update(trigger_info_map[func])
					if trig_info and int(pos)-1==trig_info["arg_index"]:
						# Config file tells us to use specific type for this argument
						dep, size, classname = _find_RI_for_func(trig_info["arg_type"].split(":")[1])
						func_args_to_dump.append((trig_info["arg_type"].split(":")[1], int(pos), size, classname, self._type_offset_calculate(trig_info["offset"],OFFSET_KIND_MIXED),True))
						deps.add(dep)
						deps|=trig_info_additional_deps(trig_info)
						continue
				dep, size, classname = _find_RI_for_func(arg)
				func_args_to_dump.append((arg, int(pos), size, classname, 0))
				deps.add(dep)
				argStr = ("____%s____%d"%(func,int(pos)-1))
				if "ptr_config" in self.config and "container_of_parm_map" in self.config["ptr_config"]:
					if argStr in self.config["ptr_config"]["container_of_parm_map"]:
						e = self.config["ptr_config"]["container_of_parm_map"][argStr][0]
						tp = self.ftdb.types.entry_by_id(e["tpid"])
						deps.add((tp.id,tp.str if tp.classname == 'record' else tp.name))
				if func in trigger_info_map:
					for trig_info in trigger_info_map[func]:
						if int(pos)-1==trig_info["arg_index"] and "type" in trig_info and trig_info["type"]=='append':
							# Config file tells us to add additional trigger for this argument
							dep, size, classname = _find_RI_for_func(trig_info["arg_type"].split(":")[1])
							if isinstance(func_args_to_dump[-1],tuple):
								func_args_to_dump[-1] = [func_args_to_dump[-1]]
							func_args_to_dump[-1].append((trig_info["arg_type"].split(":")[1], int(pos), size, classname, self._type_offset_calculate(trig_info["offset"],OFFSET_KIND_MIXED),True))
							deps.add(dep)
							deps|=trig_info_additional_deps(trig_info)

		if globals_file:
			ofid_map = {}
			for u in self.ftdb.sources:
				basename = u[1].split("/")[-1]
				if 'stub' in basename:
					continue
				original_fid = int(basename.split("_")[-1].split(".")[0])
				ofid_map[original_fid] = u
			with open(globals_file, 'r') as f:
				for hashT in f.read().split('\n'):
					hT = hashT.split()
					if len(hT)<2:
						continue
					if "/" in hT[0]:
						name = hT[0].split("/")[0]
						source_info = ofid_map[int(hT[1])]
						loc = source_info[1].split("/")[-1]
					else:
						name = hT[0]
						loc = ''
					GRI = _find_RI_for_global(name, loc)
					if GRI is None:
						continue
					dep, module, size, hash = GRI

					# FIXME: Move it to some config file
					if hash in ['__per_cpu_offset', 'jiffies', '__start_rodata', '__end_rodata']:
						print(f"Ignoring blacklisted global '{hash}'")
						continue

					globals_to_dump.append((dep[1], dep[0], name, module, size, hash, hT[0], hT[2] if len(hT)>2 else ""))
					if dep[0] is not None:
						deps.add(dep)

		if len(args)<=0:
			# Add a list of records to process from config file
			if 'OT_info' in self.config and 'record_done' in self.config['OT_info']:
				for r in self.config['OT_info']['record_done']:
					dep = _find_RI_for_str(r)
					if dep[0] is not None:
						deps.add(dep)

		return func_args_to_dump, globals_to_dump, deps

	def parse_structures_config(self, name: str, func: Optional[str] = None) -> None:

		try:
			with open(name, 'r') as f:
				self.config = json.load(f)
		except IOError:
			print(f"EE- Cannot open configuration file {name}")
			exit(1)

		try:
			for name, specs in self.config["base_config"]["allowed_members"].items():
				self.allowed_members[name] = set()
				for spec in specs:
					self.allowed_members[name].add(spec['name'])
		except KeyError:
			print("EE- Invalid format of config file")
			exit(1)

		if 'OT_info' in self.config and 'anchor_types' in self.config['OT_info']:
			self.anchor_list = set(self.config['OT_info']['anchor_types'])

		# Parse custom recipes
		if "base_config" in self.config and "custom_recipes" in self.config["base_config"]:
			custom_recipes = self.config["base_config"]["custom_recipes"]
			if "custom_recipe_variants" in self.config["base_config"]:
				custom_recipe_variants = self.config["base_config"]["custom_recipe_variants"]
				func_info = [fT[3] for fT in self.config["OT_info"]["functions"] if fT[0]==func]
				if len(func_info)==0:
					print (f'EE- Cannot find function information in the OT config file for function \'{func}\'')
					exit(1)
				if len(func_info)>1:
					print (f'EE- Cannot uniquely identify function information in the OT config file for function \'{func}\'')
					exit(1)
				func_loc = func_info[0].split(":")[0]
				for trigger_fn,custom_recipe_spec in custom_recipe_variants.items():
					fnT = [x.strip() for x in trigger_fn.split("@")]
					__fn = fnT[0]
					__loc = ""
					if len(fnT)>1:
						__loc = fnT[1]
					if __loc!="" and __loc not in func_loc:
						pass
					elif __fn!=func:
						pass
					else:
						for mStr,custom_recipe in custom_recipe_spec.items():
							custom_recipes[mStr] = custom_recipe
			if self.gftdb is None:
				print ("WW- global database not specified. Skipping parsing custom recipes")
			else:
				for key_str,code in custom_recipes.items():
					keyT = key_str.split(":")
					m = self.include_config_pattern.search(code)
					while m:
						fn = m.group()[2:-1]
						if not os.path.isabs(fn):
							fn = os.path.join(os.path.dirname(__file__),fn)
						try:
							with open(fn,"r") as f:
								code = code[:m.span()[0]] + f.read() + code[m.span()[1]:]
						except IOError as e:
							print(f"EE- Failed to open custom recipe file - '{fn}'")
							exit(1)
						m = self.include_config_pattern.search(code)
					s = self._type_offset_calculate(code,OFFSET_KIND_MIXED,self.gftdb)
					s = self.instantiate_this_member_patterns(s,":".join(key_str.split(":")[:2]).lstrip("@"),self.gftdb)
					s, include_list = self.instantiate_include_patterns(s)
					s = self.instantiate_adddep_patterns(s,":".join(key_str.split(":")[:2]).lstrip("@"))
					s = self.instantiate_global_patterns(s)
					s = self.instantiate_enum_value_patterns(s,self.gftdb)
					s = self.instantiate_typedef_patterns(s,self.gftdb)
					if len(keyT)>2:
						if s not in self.custom_recipe_member_map:
							self.custom_recipe_member_map[key_str] = (s,include_list)
						else:
							if not key_str.startswith("@"):
								print(f"WW- Custom recipe already exists for member '{key_str}' (additional recipe ignored)")
							else:
								ks = key_str.lstrip("@")
								print(f"WW- Custom recipe already exists for member '{ks}' accessible by single refname (additional recipe ignored)")
					else:
						if s not in self.custom_recipe_map:
							self.custom_recipe_map[key_str] = (s,include_list)
						else:
							print(f"WW- Custom recipe already exists for record '{key_str}' (additional recipe ignored)")

			# Parse custom pointers map
			self.custom_ptr_map = None
			if 'custom_ptr_map' in self.config['base_config']:
				self.custom_ptr_map = self.config['base_config']['custom_ptr_map']
			if 'custom_ptr_map_variants' in self.config['base_config']:
				custom_ptr_map_variants = self.config['base_config']['custom_ptr_map_variants']
				if self.custom_ptr_map is None:
					self.custom_ptr_map = {}
				func_info = [fT[3] for fT in self.config["OT_info"]["functions"] if fT[0]==func]
				if len(func_info)==0:
					print (f'EE- Cannot find function information in the OT config file for function \'{func}\'')
					exit(1)
				if len(func_info)>1:
					print (f'EE- Cannot uniquely identify function information in the OT config file for function \'{func}\'')
					exit(1)
				func_loc = func_info[0].split(":")[0]
				for trigger_fn,custom_ptr_spec in custom_ptr_map_variants.items():
					fnT = [x.strip() for x in trigger_fn.split("@")]
					__fn = fnT[0]
					__loc = ""
					if len(fnT)>1:
						__loc = fnT[1]
					if __loc!="" and __loc not in func_loc:
						pass
					elif __fn!=func:
						pass
					else:
						for mStr,tpnfo in custom_ptr_spec.items():
							self.custom_ptr_map[mStr] = tpnfo

	def collect_call_tree(self, name: str):

		discovered = set()
		def count_params_and_rets(func) -> int:
			# returns number of arguments AND return values
			has_return = 0
			for deref in func.derefs:
				if deref.kindname == 'return':
					has_return = 1
					break
			return func.nargs + has_return

		def add_subfuncs(func):
			for id in func.calls:
				if id in discovered:
					continue
				try:
					f = self.ftdb.funcs.entry_by_id(id)
				except libftdb.error:
					continue

				if count_params_and_rets(f) == 0:
					# Skip functions not changing context
					continue
				discovered.add(f.id)
				add_subfuncs(f)

		nameT = name.split("@")
		targets = [x for x in self.ftdb.funcs if x.name == nameT[0]]
		if len(targets) > 1:
			# Try to disambiguate the function name based on file
			if len(nameT)>0 and nameT[1]!="":
				if os.path.isabs(nameT[1]):
					targets = [x for x in targets if x["abs_location"]==nameT[1]]
				else:
					targets = [x for x in targets if x["abs_location"].endswith(nameT[1])]
			if len(targets) > 1:
				print(f"EE- Function name '{nameT[0]}' is ambiguous")
				exit(1)
		if len(targets) == 0:
			print(f"EE- Function named '{nameT[0]}' was not found in db.json or failed to disambiguate")
			exit(1)
		target = targets[0]
		add_subfuncs(target)

		self.call_tree = [target]
		for fid in discovered:
			self.call_tree.append(self.ftdb.funcs.entry_by_id(fid))

	def safeInfo(self,safe):
		safe_info = ""
		if not safe:
			safe_info = " /* not SAFE */"
			self.not_safe_count+=1
		return safe_info

	def walkTPD(self,TPD,ftdb=None):
		if ftdb is None:
			ftdb = self.ftdb
		T = ftdb.types[TPD.refs[0]]
		if T.classname=="typedef":
			return self.walkTPD(T,ftdb)
		else:
			return T

	def get_char_type(self):
		for T in self.ftdb.types:
			if T.classname=='builtin' and 'char' in T.str:
				return T

	def isTypeConst(self, T):
		return 'c' in T.qualifiers

	def typeToNonConst(self, T):
		if T is None or not self.isTypeConst(T):
			return T
		for type in self.ftdb.types:
			if type.str != T.str:
				continue
			elif type.classname=="record_forward":
				continue
			elif type.hash.split(':')[3] != T.hash.split(':')[3]:
				continue
			elif self.isTypeConst(type):
				continue
			return type
		return T

	# Walk through pointer or array types and extract underlying record type
	# Returns (RT,TPD) pair where:
	#  RT: underlying record type
	#  TPD: if the underlying record type was a typedef this is the original typedef type
	# In case record type cannot be resolved returns (None,None) pair
	def resolve_record_type(self,TID,TPD=None):

		T = self.ftdb.types[TID]
		if T.classname=="record" or T.classname=="record_forward":
			return T,TPD
		elif T.classname=="pointer" or T.classname=="const_array" or T.classname=="incomplete_array":
			TPD = None
			return self.resolve_record_type(T.refs[0],TPD)
		elif T.classname=="typedef":
			if TPD is None:
				TPD = T
			return self.resolve_record_type(T.refs[0],TPD)
		elif T.classname=="attributed":
			return self.resolve_record_type(T.refs[0],TPD)
		else:
			return None,None

	def get_anonstruct_typename(self,T):
		if T.id in self.anon_record_id_map:
			anonstruct_type_name = self.anon_record_id_map[T.id]
		else:
			anonstruct_type_name = "anonstruct_type_%d_t"%(self.anontype_index)
			self.anontype_index = self.anontype_index+1
			self.anon_record_id_map[T.id] = anonstruct_type_name
		return anonstruct_type_name

	def get_anonenum_typename(self,T):
		if T.id in self.anon_enum_id_map:
			anonenum_type_name = self.anon_enum_id_map[T.id]
		else:
			anonenum_type_name = "anonenum_type_%d_t"%(self.anontype_index)
			self.anontype_index = self.anontype_index+1
			self.anon_enum_id_map[T.id] = anonenum_type_name
		return anonenum_type_name

	# T - const/incomplete array type
	# returns:
	#   el_count: total number of elements in the multidimensional array; if there's incomplete array in the first dimension this returns -1
	#			  in case the element type has size 0 (i.e. empty struct of size 0) the element count is 0 regardless of number of elements
	#   AT: array element type
	#   ATPD: if the array element type is a typedef this is the original typedef type
	#   dN: number of array dimensions
	def resolve_multidimentional_array_type(self,T):
		dN=0
		Tsz = T.size
		if T.classname=='incomplete_array':
			Tsz=-1
		while T.classname=='const_array' or T.classname=='incomplete_array':
			AT = self.ftdb.types[T.refs[0]]
			ATPD = None
			if AT.classname=="typedef":
				ATPD = AT
				AT = self.walkTPD(AT)
			T = AT
			dN+=1
		return -1 if Tsz==-1 else Tsz//AT.size if AT.size!=0 else 0,AT,ATPD,dN

	def generate_flatten_record(self,out,rT,pteEXT,pteEXTmsg,refname,refoffset,tab,element_count_expr,element_count_extra_msg,TPDrT=None,nestedPtr=False,ptr_in_array=False,safe=False):
		PTEoff = 0
		if pteEXT is not None and pteEXT[0]>=0:
			if isinstance(pteEXT[1],int):
				PTEoff=-pteEXT[1]
			else:
				PTEoff="-(%s)"%(pteEXT[1][0])
		if TPDrT:
			if not nestedPtr:
				recipe = indent(RecipeGenerator.template_flatten_struct_type_member_recipe.format(
						TPDrT.name,
						TPDrT.size//8,
						refname,
						refoffset//8,
						PTEoff,
						element_count_expr,
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
						self.safeInfo(safe)
					),tab)
			else:
				recipe = indent(RecipeGenerator.template_flatten_struct_type_pointer_recipe.format(
						TPDrT.name,
						TPDrT.size//8,
						refname if not ptr_in_array else ptrNestedRefName(refname,1),
						element_count_expr,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
						PTEoff
					),tab)
			out.write(recipe+"\n")
			self.struct_deps.add((TPDrT.id,TPDrT.name))
			self.record_typedefs.add((TPDrT.name,rT.str,rT.id))
			return TPDrT.name
		else:
			if rT.str=="":
				anonstruct_type_name = self.get_anonstruct_typename(rT)
				self.anon_typedefs.append((rT.id,anonstruct_type_name))
				if not nestedPtr:
					recipe = indent(RecipeGenerator.template_flatten_struct_type_member_recipe.format(
							anonstruct_type_name,
							rT.size//8,
							refname,
							refoffset//8,
							PTEoff,
							element_count_expr,
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
							self.safeInfo(safe)
						),tab)
				else:
					recipe = indent(RecipeGenerator.template_flatten_struct_type_pointer_recipe.format(
							anonstruct_type_name,
							rT.size//8,
							refname if not ptr_in_array else ptrNestedRefName(refname,1),
							element_count_expr,
							self.safeInfo(safe),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
							PTEoff
						),tab)
				out.write(recipe+"\n")
				self.struct_deps.add((rT.id,anonstruct_type_name))
				return anonstruct_type_name
			else:
				__tag = "struct" if rT.isunion is False else "union"
				if not nestedPtr:
					assert rT.isunion is False or (isinstance(PTEoff,int) and PTEoff==0), "Invalid shift size != 0 (or code expression) for union member"
					recipe = indent(RecipeGenerator.template_flatten_struct_member_recipe.format(
							"STRUCT" if rT.isunion is False else "UNION",
							rT.str,
							rT.size//8,
							refname,
							refoffset//8,
							PTEoff,
							element_count_expr,
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
							self.safeInfo(safe)
						),tab)
				else:
					recipe = indent(RecipeGenerator.template_flatten_struct_pointer_recipe.format(
							"STRUCT" if rT.isunion is False else "UNION",
							rT.str,
							rT.size//8,
							refname if not ptr_in_array else ptrNestedRefName(refname,1),
							element_count_expr,
							self.safeInfo(safe),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
							PTEoff
						),tab)
				if rT.classname=="record_forward":
					if len([x for x in self.ftdb.types if x.classname=="record" and x.str==rT.str])<=0:
						recipe = "/* MISSING STRUCT: %s */"%(rT.str)
				out.write(recipe+"\n")
				self.struct_deps.add((rT.id,rT.str))
				return "%s %s"%(__tag,rT.str)

	def get_element_count(self,mStr,dStr,ptr_in_array=False):

			# Normally we cannot know whether the pointer points to a single struct or an array of structs (or other types)
			# Try to conclude that from information in config file, otherwise we will try to detect it at runtime
			# When the detection fails we will assume there's a single element pointed there (default value)
			record_count_tuple = [1,None,None,'','default']
			# [0] record_count (If this is None then the dereference expression gives us ambiguous results; more info in extra field)
			# [1] record_count_expr (This is the code expression that yields the record count (exclusively used if not None))
			# [2] record_count_extra
			# [3] record_count_extra_kind (either 'deref', 'assign', 'function', 'functionptr', 'direct' or 'nested')
			# [4] record_count_kind (either 'direct', 'derived' or 'default')
			haveCount = False
			if 'base_config' in self.config:
				# First check if this information is given to us directly
				if 'custom_element_count_map' in self.config['base_config']:
					ecM = self.config['base_config']['custom_element_count_map']
					element_count_nfo = None
					if "#"+dStr in ecM:
						element_count_nfo = ecM["#"+dStr]
					if element_count_nfo is None and mStr in ecM:
						element_count_nfo = ecM[mStr]
					if element_count_nfo is not None:
						haveCount = True
						if isinstance(element_count_nfo,int):
							record_count_tuple[0] = element_count_nfo
						else:
							record_count_tuple[1] = (self._type_offset_calculate(element_count_nfo,OFFSET_KIND_CONCRETE),self._type_offset_calculate(element_count_nfo,OFFSET_KIND_SYMBOLIC))
						record_count_tuple[4] = 'direct'
				if 'force_detect_object_size' in self.config['base_config']:
					fdM = self.config['base_config']['force_detect_object_size']
					if not haveCount and mStr in fdM:
						haveCount = True
						record_count_tuple[0] = None
						record_count_tuple[2] = fdM[mStr]
						record_count_tuple[3] = 'direct'

			if not haveCount and not ptr_in_array:
				# Ok, so try to conclude this information from precomputed data
				if 'ptr_config' in self.config:
					# First check if in dereference expression this member is never used with offset > 0 (or with any variables used in the offset expression)
					#  or we don't have dereference information for this member (meaning it was never used in dereference expressions)
					deref_offset = 0
					if 'deref_map' in self.config['ptr_config'] and 'assign_list' in self.config['ptr_config'] and 'me_calls' in self.config['ptr_config'] and 'me_refcalls' in self.config['ptr_config']:
						deref_map = self.config['ptr_config']['deref_map']
						if mStr in deref_map:
							dL = deref_map[mStr]
							deref_offset = sum([x[0]+x[1] for x in dL])
						if deref_offset>0:
							# The conclusion gives us ambiguous results (either we use the member with non-zero offset at dereference expresion or other variables are involved)
							record_count_tuple[0] = None
							record_count_tuple[2] = dL
							record_count_tuple[3] = 'deref'
							return record_count_tuple
						# Now check if this member is not used in the right-hand side of any assignment expression
						#  (otherwise we wouldn't be sure if the assigned value is not used at some other dereference expression somewhere else)
						assign_list = self.config['ptr_config']['assign_list']
						if mStr in assign_list:
							# Our member is on the right hand side of some assignment expression; we conclude ambiguously
							record_count_tuple[0] = None
							record_count_tuple[2] = assign_list[mStr]
							record_count_tuple[3] = 'assign'
							return record_count_tuple
						# Finally check if this member has not been passed to any function
						#  (if it has then we cannot be sure how the memory was accessed through the function parameter)
						me_calls = self.config['ptr_config']['me_calls']
						if mStr in me_calls:
							# Our member was passed to a function; we conclude ambiguously
							record_count_tuple[0] = None
							record_count_tuple[2] = me_calls[mStr]
							record_count_tuple[3] = 'function'
							return record_count_tuple
						# Maybe it's a function call through the pointer?
						me_refcalls = self.config['ptr_config']['me_refcalls']
						if mStr in me_refcalls:
							# Our member was passed to a function; we conclude ambiguously
							record_count_tuple[0] = None
							record_count_tuple[2] = me_refcalls[mStr]
							record_count_tuple[3] = 'functionptr'
							return record_count_tuple
						# Our pointer member is not used in any dereference expression with offset > 0
						# Also it's not used at the right-hand side of any assignment expression
						# Finally it's not been passed as an argument to any function
						# Let's then assume that we point to a single element of a given type
						record_count_tuple = [1,None,None,'','derived']

			return record_count_tuple


	def get_global_element_count(self,ghash,ptr_in_array=False):

		# Normally we cannot know whether the global pointer points to a single element or an array of elements (or other types)
		# Try to conclude that from information in config file, otherwise we will try to detect it at runtime
		# When the detection fails we will assume there's a single element pointed there (default value)
		record_count_tuple = [1,None,None,'','default']
		# [0] record_count (If this is None then the dereference expression gives us ambiguous results; more info in extra field)
		# [1] record_count_expr (This is the code expression that yields the record count (exclusively used if not None))
		# [2] record_count_extra
		# [3] record_count_extra_kind (either 'deref', 'assign', 'function', 'functionptr' or 'nested')
		# [4] record_count_kind (either 'direct', 'derived' or 'default')
		haveCount = False
		if 'base_config' in self.config:
			# First check if this information is given to us directly
			if 'custom_global_element_count_map' in self.config['base_config']:
				ecM = self.config['base_config']['custom_global_element_count_map']
				if ghash in ecM:
					haveCount = True
					element_count_nfo = ecM[ghash]
					if isinstance(element_count_nfo,int):
						record_count_tuple[0] = element_count_nfo
					else:
						record_count_tuple[1] = (self._type_offset_calculate(element_count_nfo,OFFSET_KIND_CONCRETE),self._type_offset_calculate(element_count_nfo,OFFSET_KIND_SYMBOLIC))
					record_count_tuple[4] = 'direct'
		if ptr_in_array:
			return record_count_tuple
		if not haveCount:
			# Ok, so try to conclude this information from precomputed data
			if 'ptr_config' in self.config:
				# First check if in dereference expression this global is never used with offset > 0 (or with any variables used in the offset expression)
				#  or we don't have dereference information for this global (meaning it was never used in dereference expressions)
				deref_offset = 0
				if 'global_deref_map' in self.config['ptr_config'] and 'global_assign_list' in self.config['ptr_config'] and 'g_calls' in self.config['ptr_config'] and 'g_refcalls' in self.config['ptr_config']:
					deref_map = self.config['ptr_config']['global_deref_map']
					if ghash in deref_map:
						dL = deref_map[ghash]
						deref_offset = sum([x[0]+x[1] for x in dL])
					if deref_offset>0:
						# The conclusion gives us ambiguous results (either we use the member with non-zero offset at dereference expresion or other variables are involved)
						record_count_tuple[0] = None
						record_count_tuple[2] = dL
						record_count_tuple[3] = 'deref'
						return record_count_tuple
					# Now check if this member is not used in the right-hand side of any assignment expression
					#  (otherwise we wouldn't be sure if the assigned value is not used at some other dereference expression somewhere else)
					assign_list = self.config['ptr_config']['global_assign_list']
					if ghash in assign_list:
						# Our member is on the right hand side of some assignment expression; we conclude ambiguously
						record_count_tuple[0] = None
						record_count_tuple[2] = assign_list[ghash]
						record_count_tuple[3] = 'assign'
						return record_count_tuple
					# Finally check if this member has not been passed to any function
					#  (if it has then we cannot be sure how the memory was accessed through the function parameter)
					g_calls = self.config['ptr_config']['g_calls']
					if ghash in g_calls:
						# Our member was passed to a function; we conclude ambiguously
						record_count_tuple[0] = None
						record_count_tuple[2] = g_calls[ghash]
						record_count_tuple[3] = 'function'
						return record_count_tuple
					# Maybe it's a function call through the pointer?
					g_refcalls = self.config['ptr_config']['g_refcalls']
					if ghash in g_refcalls:
						# Our member was passed to a function; we conclude ambiguously
						record_count_tuple[0] = None
						record_count_tuple[2] = g_refcalls[ghash]
						record_count_tuple[3] = 'functionptr'
						return record_count_tuple
					# Our global pointer is not used in any dereference expression with offset > 0
					# Also it's not used at the right-hand side of any assignment expression
					# Finally it's not been passed as an argument to any function
					# Let's then assume that we point to a single element of a given type
					record_count_tuple = [1,None,None,'','derived']

		return record_count_tuple

	def construct_element_count_expression(self,record_count_tuple,refname,mStr,refoffset,refsize,ptrLevel,ptr_in_array):
		if record_count_tuple[1] is not None:
			# Count expression given by a user
			extra_msg = "/* User provided the following expression as a count expression: '%s' */\n"%(record_count_tuple[1][1])
			return (record_count_tuple[1][0],extra_msg)
		else:
			size_in_bytes = max(1, refsize//8)
			if not ptr_in_array:
				detect_element_count_expr = "\n  AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(%s,%d,%d)/%d"%(ptrNestedRefName(refname,ptrLevel),refoffset//8,size_in_bytes,size_in_bytes)
			else:
				detect_element_count_expr = "\n  FLATTEN_DETECT_OBJECT_SIZE(%s,%d)/%d"%(ptrNestedRefName(refname,1),size_in_bytes,size_in_bytes)
			if record_count_tuple[0] is not None:
				if record_count_tuple[4]=='direct':
					# Count given by a user
					extra_msg = "/* User provided the following value as a count expression: %d */\n"%(record_count_tuple[0])
					return (str(record_count_tuple[0]),extra_msg)
				elif record_count_tuple[4]=='derived':
					# We concluded that we point to a single element of an array
					extra_msg = "/* We've concluded that this pointer ('%s') is not used in any dereference expression with offset > 0.\n\
Also it's not used at the right-hand side of any assignment expression.\n\
Finally it's not been passed as an argument to any function.\n\
We then assume that this pointer is pointing to a single element of a given type */\n"%(mStr)
					return (str(record_count_tuple[0]),extra_msg)
				else:
					# We don't have information about the number of elements the pointer points to
					# Try to detect the object size pointed to by this pointer and conclude the number
					#  of elements based on that
					# When it fails adhere to the simple default of single element
					detect_extra_msg = "/* We couldn't find the number of elements this pointer ('%s') is pointing to (also no direct information in config file exists).\n\
   We'll try to detect the number of elements based on the object size pointed to by this pointer (assuming it's on the heap).\n\
   When it fails we'll default to a single element pointed to by it */\n"%(mStr)
					return (detect_element_count_expr,detect_extra_msg)
			else:
				if record_count_tuple[3]=='deref':
					ambiguous_exprs = list()
					for dT in record_count_tuple[2]:
						if dT[0]+dT[1]>0:
							aexpr = "     "+dT[2]
							if dT[0]>0:
								aexpr+="  | offset %d"%(dT[0])
							if dT[1]>0:
								aexpr+="  | %d variables in offset expression"%(dT[1])
							ambiguous_exprs.append(aexpr)
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Member '{0}' was used in {1} dereference expressions and the ambiguous expressions were as follows:\n{2}\n".format(
  			"%s [%s]"%(refname,mStr),
  			len(record_count_tuple[2]),
  			"\n".join(ambiguous_exprs)
  	)
				elif record_count_tuple[3]=='assign':
					ambiguous_exprs = list()
					for expr in record_count_tuple[2]:
						ambiguous_exprs.append("     "+expr)
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Member '{0}' was used on the right-hand side of the following assignment expressions:\n{1}\n".format(
  			"%s [%s]"%(refname,mStr),
  			"\n".join(ambiguous_exprs)
  	)
				elif record_count_tuple[3]=='function':
					ambiguous_exprs = list()
					for eT in record_count_tuple[2]:
						ambiguous_exprs.append("     "+"%s{ ... %s( arg$%d ) ... } -> %s"%(
							self.ftdb.funcs.entry_by_id(eT[0]).name,
							self.ftdb.funcs.entry_by_id(eT[1]).name,
							eT[2],
							eT[3]
						))
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Member '{0}' was passed as a function argument in the following expressions:\n{1}\n".format(
  			"%s [%s]"%(refname,mStr),
  			"\n".join(ambiguous_exprs)
  	)
				elif record_count_tuple[3]=='functionptr':
					ambiguous_exprs = list()
					for eT in record_count_tuple[2]:
						ambiguous_exprs.append("     "+"%s{ ... *F( arg$%d ) ... } -> %s"%(
							self.ftdb.funcs.entry_by_id(eT[0]).name,
							# TODO: print information about dereferenced function */
							eT[2],
							eT[3]
						))
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Member '{0}' was passed as a function argument in the following expressions:\n{1}\n".format(
  			"%s [%s]"%(refname,mStr),
  			"\n".join(ambiguous_exprs)
  	)
				elif record_count_tuple[3]=='direct':
					msg = "/* User specified to force to detect the object size for the member '{0}'. Additional information provided by the user was:\n   {1}\n".format(mStr,record_count_tuple[2])
				else:
					msg = "/* Couldn't conclude the number of elements pointer points to as this was a nested pointer at higher level than 0\n"
				msg += "   We will try to detect the array size at runtime. When it fails we will dump a single element pointed to by this pointer (default)\n */\n"
				return (detect_element_count_expr,msg)

	def construct_global_element_count_expression(self,record_count_tuple,gv,PTE,ptrname,ptrLevel):

		if record_count_tuple[1] is not None:
			# Count expression given by user
			extra_msg = "/* User provided the following expression as a count expression: '%s' */\n"%(record_count_tuple[1][1])
			return (record_count_tuple[1][0],extra_msg)
		else:
			size_in_bytes = max(1, PTE.size // 8)
			detect_element_count_expr = "\n  FLATTEN_DETECT_OBJECT_SIZE(%s,%s)/%s"%(ptrname,size_in_bytes,size_in_bytes)
			if record_count_tuple[0] is not None:
				if record_count_tuple[4]=='direct':
					# Count given by a user
					extra_msg = "/* User provided the following value as a count expression: %d */\n"%(record_count_tuple[0])
					return (str(record_count_tuple[0]),extra_msg)
				elif record_count_tuple[4]=='derived':
					# We concluded that we point to a single element of an array
					extra_msg = "/* We've concluded that this global pointer is not used in any dereference expression with offset > 0.\n\
Also it's not used at the right-hand side of any assignment expression.\n\
Finally it's not been passed as an argument to any function.\n\
We then assume that this pointer is pointing to a single element of a given type */\n"
					return (str(record_count_tuple[0]),extra_msg)
				else:
					# We don't have information about the number of elements the pointer points to
					# Try to detect the object size pointed to by this pointer and conclude the number
					#  of elements based on that
					# When it fails adhere to the simple default of single element
					detect_extra_msg = "/* We couldn't find the number of elements this pointer is pointing to (also no direct information in config file exists).\n\
   We'll try to detect the number of elements based on the object size pointed to by this pointer (assuming it's on the heap).\n\
   When it fails we'll default to a single element pointed to by it */\n"
					return (detect_element_count_expr,detect_extra_msg)
			else:
				if record_count_tuple[3]=='deref':
					ambiguous_exprs = list()
					for dT in record_count_tuple[2]:
						if dT[0]+dT[1]>0:
							aexpr = "     "+dT[2]
							if dT[0]>0:
								aexpr+="  | offset %d"%(dT[0])
							if dT[1]>0:
								aexpr+="  | %d variables in offset expression"%(dT[1])
							ambiguous_exprs.append(aexpr)
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Global '{0}' was used in {1} dereference expressions and the ambiguous expressions were as follows:\n{2}\n".format(
  			gv.name,
  			len(record_count_tuple[2]),
  			"\n".join(ambiguous_exprs)
  	)
				elif record_count_tuple[3]=='assign':
					ambiguous_exprs = list()
					for expr in record_count_tuple[2]:
						ambiguous_exprs.append("     "+expr)
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Global '{0}' was used on the right-hand side of the following assignment expressions:\n{1}\n".format(
  			gv.name,
  			"\n".join(ambiguous_exprs)
  	)
				elif record_count_tuple[3]=='function':
					ambiguous_exprs = list()
					for eT in record_count_tuple[2]:
						ambiguous_exprs.append("     "+"%s{ ... %s( arg$%d ) ... } -> %s"%(
							self.ftdb.funcs.entry_by_id(eT[0]).name,
							self.ftdb.funcs.entry_by_id(eT[1]).name,
							eT[2],
							eT[3]
						))
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Global '{0}' was passed as a function argument in the following expressions:\n{1}\n".format(
  			gv.name,
  			"\n".join(ambiguous_exprs)
  	)
				elif record_count_tuple[3]=='functionptr':
					ambiguous_exprs = list()
					for eT in record_count_tuple[2]:
						ambiguous_exprs.append("     "+"%s{ ... *F( arg$%d ) ... } -> %s"%(
							self.ftdb.funcs.entry_by_id(eT[0]).name,
							# TODO: print information about dereferenced function */
							eT[2],
							eT[3]
						))
					msg = "/* Couldn't conclude unambiguously the number of elements pointer points to.\n\
   Global '{0}' was passed as a function argument in the following expressions:\n{1}\n".format(
  			gv.name,
  			"\n".join(ambiguous_exprs)
  	)
				else:
					msg = "/* Couldn't conclude the number of elements pointer points to as this was a nested pointer at higher level than 0.\n"
				msg += "   We will try to detect the array size at runtime. When it fails we will dump a single element pointed to by this pointer (default)\n */\n"
				return (detect_element_count_expr,msg)

	def construct_PTE_extra_msg(self,pteEXT,mStr,refname):

		ptenfo = None
		if pteEXT[2]=='container_of':
			ptenfo = (
							 		"'container_of' expression(s)",
									pteEXT[3] if pteEXT[0]>=0 else "\n".join(["E: %s -> '%s' @ %d"%(x['expr'],x['tps'],x['offset']) for x in pteEXT[3]])
							 )
		if pteEXT[2]=='pvoid':
			ptenfo = (
									"pointer to void analysis",
									"\n".join(["     %s"%(x) for x in pteEXT[3]]) if pteEXT[0]>=0 else
									"\n".join( [ "E: %s -> '%s'"%(expr,self.ftdb.types[int(TID)].hash) for TID,expr in
										list(itertools.chain.from_iterable([(k,e) for e in V] for k,V in pteEXT[3].items())) ] )
							 )
		if pteEXT[2]=='custom' or pteEXT[2]=='custom_string':
			ptenfo = (
									"custom information from config file",
									pteEXT[3]
							 )

		if pteEXT[0]<0:
			if pteEXT[2]=='pvoid' and len(pteEXT[3])==1:
				# Looks like void* is not actually a pointer
				pteEXTmsg = "/* It was detected that the member '{0}' of type 'void*' is not actually a pointer but the type with '{1}' hash.\n\
The ambiguous entry is as follows:\n\
{2}\n\
*/\n".format(
	"%s [%s]"%(refname,mStr),
	self.ftdb.types[int(list(pteEXT[3].keys())[0])].hash,
	ptenfo[1]
)
			else:
				# Ambiguity
				pteEXTmsg = "/* It was detected that the member '{0}' points ambiguously to a number of distinct types. We tried to conclude that using {1}.\n\
The ambiguous entries are as follows:\n\
{2}\n\
*/\n".format(
	"%s [%s]"%(refname,mStr),
	ptenfo[0],
	ptenfo[1]
)
		else:
			if pteEXT[2]!='string':
				# The pointer points to other type than the original type
				tp_chain_msg = ""
				if len(pteEXT)>4:
					tp_chain_msg = "   It was further detected that the type the member points to was additionally embedded into more enclosing types accessed using \
the 'container_of' invocation chain.\n   The invocation chain was as follows:\n{0}\n".format(
				   		"\n".join(["     {0}@{1}: {2} -> {3} : {4} @ {5}".format(
						            x[0].split("____")[1],
						            x[0].split("____")[2],
						            x[1]['tpargs'] if 'tpargs' in x[1] else x[1]['tpvars'] if 'tpvars' in x[1] else '',
						            x[1]['tps'],
						            x[1]['offset'],
						            x[1]['expr']
				        ) for x in pteEXT[4]])
	)

				pteEXTmsg = "/* It was detected that the member\n\
 '{0}'\n\
points to (possibly) other type than specified in the member type specification.\n\
Type hash of the new pointee type is\n\
 '{1}'\n\
with offset {4} and we concluded that using {2}.\n\
The expression(s)/custom info we concluded it from was:\n\
 {3}\n\
{5} */\n".format(
 		"%s [%s]"%(refname,mStr),
 		self.ftdb.types[pteEXT[0]].hash,
 		ptenfo[0],
 		ptenfo[1],
 		pteEXT[1] if isinstance(pteEXT[1], int) else "'%s'"%(pteEXT[1][1]),
 		tp_chain_msg
 	)
			else:
	 			# We have a c-string member
	 			pteEXTmsg = "/* It was detected that the member\n\
'{0}'\n\
 is a c-string (null terminated char array).\n\
 The call expression(s) that we concluded it from were:\n\
{1}\n\
*/\n".format(
  	"%s [%s]"%(refname,mStr),
	"\n".join(["     %s"%(x) for x in pteEXT[3]])
  )
		return pteEXTmsg

	def real_pointee_type(self,mStr,dStr,refname,PTE,ptr_in_array=False):

		havePte = False
		PTEExt = None
		if 'base_config' in self.config:
			if self.custom_ptr_map is not None:
				cT = None
				if "@"+mStr in self.custom_ptr_map:
					# We have custom information for single refnames only
					if len(refname.split("."))<=1:
						cT = self.custom_ptr_map["@"+mStr]
				if cT is None and "#"+dStr in self.custom_ptr_map:
					cT = self.custom_ptr_map["#"+dStr]
				if cT is None and mStr in self.custom_ptr_map:
					cT = self.custom_ptr_map[mStr]
				if cT is not None:
					havePte = True
					# Our config file tells us exactly to which type this pointer points to
					tpstr = cT["typestring"]
					if tpstr!='cstring':
						if ":" in tpstr:
							prefix,tag = tpstr.split(":")
							if prefix=='s':
								Tp = self._find_record_type_by_tag(tag)
							elif prefix=='t':
								Tp = self._find_typedef_type_by_name(tag)
							elif prefix=='e':
								Tp = self._find_enum_type_by_tag(tag)
						else:
							Tp = self._find_builtin_type_by_name(tpstr)
					offval = 0
					if "offset" in cT:
						offval = cT['offset']
						if not isinstance(offval,int):
							offval = (self._type_offset_calculate(offval,OFFSET_KIND_CONCRETE),self._type_offset_calculate(offval,OFFSET_KIND_SYMBOLIC))
					PTEExt = (Tp.id if tpstr!='cstring' else self.char_type.id,offval,'custom' if tpstr!='cstring' else 'custom_string',cT['info'])
					PTE=Tp if tpstr!='cstring' else self.char_type
			if 'custom_string_members' in self.config['base_config']:
				custom_string_members = self.config['base_config']['custom_string_members']
				if not havePte and mStr in custom_string_members:
					unfo = custom_string_members[mStr]
					havePte = True
					# Our config file tells us this member points to a null-terminated c-string
					PTEExt = (self.char_type.id,0,'custom_string',unfo)
					PTE = self.char_type

		if ptr_in_array:
			return PTE,PTEExt

		if not havePte and 'ptr_config' in self.config:

			if 'container_of_map' in self.config['ptr_config']:
				container_of_map = self.config['ptr_config']['container_of_map']
				if mStr in container_of_map:
					havePte = True
					# This member was used in the 'container_of' macro
					cL = container_of_map[mStr]
					if len(cL)==1:
						PTEExt = (cL[0]['tpid'],cL[0]['offset'],'container_of',cL[0]['expr'])
						PTE = self.ftdb.types[cL[0]['tpid']]
					else:
						PTEExt = (-1,0,'container_of',cL)

			if 'string_members' in self.config['ptr_config']:
				string_members = self.config['ptr_config']['string_members']
				if not havePte and mStr in string_members:
					mL = string_members[mStr]
					havePte = True
					# This member really points to a null-terminated c-string
					PTEExt = (self.char_type.id,0,'string',mL)
					PTE = self.char_type

			if 'pvoid_map' in self.config['ptr_config']:
				pvoid_map = self.config['ptr_config']['pvoid_map']
				if not havePte and mStr in pvoid_map:
					havePte = True
					# This member was used as a different type than 'void*'
					vM = pvoid_map[mStr]
					if len(vM)==1:
						tp = self.ftdb.types[int(list(vM.keys())[0])]
						if tp.classname=='pointer':
							PTEExt = (tp.refs[0],0,'pvoid',list(set(list(vM.values())[0])))
							PTE = self.ftdb.types[tp.refs[0]]
						else:
							PTEExt = (-1,0,'pvoid',vM)
					else:
						PTEExt = (-1,0,'pvoid',vM)

			if (PTEExt is None and (PTE.classname=="record" or PTE.classname=="record_forward" or (PTE.classname=="typedef" and self.walkTPD(PTE).classname=="record"))) or\
				(PTEExt is not None and PTEExt[2]!='custom' and PTEExt[2]!='string'):
				# Now check if our pointer member points to inside of an even larger type
				# Do this by walking the 'container_of_(l/p)arm_map' to check whether any argument
				#  passed to the 'container_of' invoking function (or 'container_of' on local variable)
				#  had the type our pointer points to
				# If so recompute the offset of our pointer inside the larger type
				if 'container_of_parm_map' in self.config['ptr_config'] and 'container_of_local_map' in self.config['ptr_config']:
					cpM = self.config['ptr_config']['container_of_parm_map']
					clM = self.config['ptr_config']['container_of_local_map']
					tp_chain = list()
					if PTEExt is None:
						cPTE = PTE.id
					else:
						cPTE = PTEExt[0]
					while True:
						nPTE = None
						for fkey,cinfo in cpM.items():
							if len(cinfo)>1:
								# Omit ambiguous entries
								continue
							tpargid = self.ftdb.types.entry_by_id(cinfo[0]['tpargid'])
							if tpargid.classname=='pointer' and tpargid.refs[0]==cPTE:
								# We look for exactly one match
								if nPTE is not None:
									nPTE = None
									break
								nPTE = (fkey,cinfo[0])
						else:
							if nPTE is None:
								for fkey,cinfo in clM.items():
									if len(cinfo)>1:
										# Omit ambiguous entries
										continue
									tpvarid = self.ftdb.types.entry_by_id(cinfo[0]['tpvarid'])
									if tpvarid.classname=='pointer' and tpvarid.refs[0]==cPTE:
										# We look for exactly one match
										if nPTE is not None:
											nPTE = None
											break
										nPTE = (fkey,cinfo[0])
						if nPTE:
							# We've found unambiguous entry, save it a look further until no more entries are found
							tp_chain.append(nPTE)
							cPTE = nPTE[1]['tpid']
						else:
							break
					if len(tp_chain)>0:
						if PTEExt is None:
							ext_kind = 'container_of'
							ext_msg = 'N/A'
						else:
							ext_kind = PTEExt[2]
							ext_msg = PTEExt[3]
						PTEExt = (tp_chain[-1][1]['tpid'],sum([x[1]['offset'] for x in tp_chain]),ext_kind,ext_msg,tp_chain)
						PTE = self.ftdb.types[tp_chain[-1][1]['tpid']]

		return PTE,PTEExt

	# out -
	# ptrT - type of the structure member being processed
	# pteT - type the structure member pointer points to
	# pteEXT -
	# poffset - offset in the pteT records type
	# mStr -
	# refname - member pointer refname
	# refoffset - member pointer offset
	# TRT - the underlying record type for which the harness is generated
	# tab -
	# TPDptrT - if structure member is a typedef this is the original typedef type otherwise it's None
	# TPDpteT - if structure member pointer points to a typedef this is the original typedef type otherwise it's None
	# ptrLevel -
	def generate_flatten_pointer(self,out,ptrT,pteT,pteEXT,mStr,dStr,refname,refoffset,TRT,tab,TPDptrT=None,TPDpteT=None,ptrLevel=0,ptr_in_array=False):
		if ptrLevel<=0:
			if pteEXT is not None and len(pteEXT)>4:
				# 'container_of' chain - assume single pointed element
				record_count_tuple = [1,None,None,'direct','']
			else:
				record_count_tuple = self.get_element_count(mStr,dStr,ptr_in_array)
		else:
			# Pointer at the higher level of nesting is ambiguous (cannot extract information from dereference expressions about its usage at this point)
			record_count_tuple = [None,None,None,'nested','']
		element_count_expr,element_count_extra_msg = self.construct_element_count_expression(record_count_tuple,refname,mStr,refoffset,pteT.size,ptrLevel,ptr_in_array)
		safe=record_count_tuple[1] is not None or record_count_tuple[0] is not None

		pteEXTmsg = ""
		if pteEXT is not None:
			pteEXTmsg = self.construct_PTE_extra_msg(pteEXT,mStr,refname)

		if pteT.classname=="attributed" and "__attribute__((noderef))" in pteT.attrcore:
			out.write(indent("/* Member '%s' points to __user memory */"%(refname),tab)+"\n")
			self.user_memory_pointer_members.append((TPDptrT,TRT,refname))
			self.user_count+=1
			return None
		if pteT.classname=="record" or pteT.classname=="record_forward":
			# pointer to struct
			self.pointer_to_struct_count+=1
			return self.generate_flatten_record(
					out,
					pteT,
					pteEXT,
					pteEXTmsg,
					ptrNestedRefName(refname,ptrLevel),
					refoffset,
					tab,
					element_count_expr,
					element_count_extra_msg,
					TPDpteT,
					ptrLevel>0 or ptr_in_array,
					ptr_in_array,
					safe
			)+"*"
		elif pteT.classname=="incomplete_array" or pteT.classname=="const_array":
			# Pointer to array
			out.write(indent("/* TODO: implement flattening member '%s' (too complicated; I'm not that smart yet) */\n  /* Member type: %s */\n"%(refname,ptrT.hash),tab)+"\n")
			self.complex_members.append((TPDptrT,TRT,refname))
			self.simple = False
			return None
		elif pteT.classname=="pointer":
			if ptr_in_array:
				out.write(indent("/* TODO: implement flattening member '%s' (too complicated; I'm not that smart yet) */\n  /* Member type: %s */\n"%(refname,ptrT.hash),tab)+"\n")
				self.complex_members.append((TPDptrT,TRT,refname))
				self.simple = False
				return None
			# We have pointer to pointer
			PTE = self.ftdb.types[pteT.refs[0]]
			TPDE = None
			if PTE.classname=="typedef":
				TPDE = PTE
				PTE = self.walkTPD(PTE)
			ptrout = io.StringIO()
			# We assume that the nested pointer points to the type specified in its type specification (we don't have detailed member information at this level)
			ptrtp = self.generate_flatten_pointer(ptrout,pteT,PTE,None,mStr,dStr,refname,refoffset,TRT,tab,TPDpteT,TPDE,ptrLevel+1)
			if ptrtp is None or ptrtp=="":
				# We have multi-level pointers to function or pointers to incomplete arrays (strange things like that); ask the user to write this flattening recipe
				return None
			out.write(RecipeGenerator.template_flatten_pointer_recipe.format(
				ptrtp,
				refname,
				refoffset//8,
				element_count_expr,
				ptrNestedRefName(refname,ptrLevel+1),
				ptrNestedRefName(refname,ptrLevel,True,refoffset//8),
				self.safeInfo(safe),
				indent(ptrout.getvalue().rstrip(),tab+1),
				prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  ")
			)+"\n")
			self.simple = False
			return ptrtp+"*"
		elif pteT.classname=="enum" or pteT.classname=="enum_forward":
			# pointer to enum
			if pteT.str=="":
				anonenum_type_name = self.get_anonenum_typename(pteT)
				self.anon_typedefs.append((pteT.id,anonenum_type_name))
				if ptrLevel<=0 and not ptr_in_array:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_member_recipe.format(
						anonenum_type_name,
						ptrNestedRefName(refname,ptrLevel),
						element_count_expr,
						pteT.size//8,
						refoffset//8,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
					),tab)+"\n")
				else:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(
						anonenum_type_name,
						pteT.size//8,
						ptrNestedRefName(refname,ptrLevel) if not ptr_in_array else ptrNestedRefName(refname,1),
						element_count_expr,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
					),tab)+"\n")
				return anonenum_type_name+"*"
			else:
				if ptrLevel<=0 and not ptr_in_array:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_member_recipe.format(
						"enum %s"%(pteT.str),
						ptrNestedRefName(refname,ptrLevel),
						element_count_expr,
						pteT.size//8,
						refoffset//8,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
					),tab)+"\n")
				else:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(
						"enum %s"%(pteT.str),
						pteT.size//8,
						ptrNestedRefName(refname,ptrLevel) if not ptr_in_array else ptrNestedRefName(refname,1),
						element_count_expr,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
					),tab)+"\n")
			self.simple = safe is True
			self.enum_pointers.append((TPDptrT,TRT,refname))
			return "enum %s*"%(pteT.str)
		elif pteT.classname=="function":
			# pointer to function
			if ptrLevel<=0 and not ptr_in_array:
				out.write(indent(RecipeGenerator.template_flatten_fptr_member_recipe.format(
					ptrNestedRefName(refname,ptrLevel),
					refoffset//8
				),tab)+"\n")
			else:
				out.write(indent(RecipeGenerator.template_flatten_fptr_pointer_recipe.format(
					ptrNestedRefName(refname,ptrLevel) if not ptr_in_array else ptrNestedRefName(refname,1),
				),tab)+"\n")
			return "void*"
		elif pteT.classname=="builtin" and pteT.str=="void":
			# void* - we couldn't find the real type this void* points to (either due to ambiguity or lack of information)
			#  Try to detect the object size pointed to by void* (unless we have direct information in config file)
			#  When it fails dump 1 byte of memory pointed to by it
			if pteEXT is None or pteEXT[0]>=0:
				pteEXTmsg = "/* We couldn't find the real type this void* member '%s' <%s> points to (also no direct information in config file exists). */\n"%(refname,mStr)
			pvd_element_count_expr = "\n  AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(%s,%d)"%(ptrNestedRefName(refname,ptrLevel),refoffset//8)
			detect_msg = "%s\
   /* We'll try to detect the object size pointed to by void* member (assuming it's on the heap).\n\
   When it fails we'll dump 1 byte of memory pointed to by it */\n"%(pteEXTmsg)
			if record_count_tuple[4]=='direct':
				if record_count_tuple[1] is not None:
					pvd_element_count_expr = record_count_tuple[1]
					detect_msg = ""
				elif record_count_tuple[0] is not None:
					pvd_element_count_expr = str(record_count_tuple[0])
					detect_msg = ""
			if ptrLevel<=0 and not ptr_in_array:
				out.write(indent(RecipeGenerator.template_flatten_type_array_member_recipe.format(
					"unsigned char",
					ptrNestedRefName(refname,ptrLevel),
					pvd_element_count_expr,
					refoffset//8,
					self.safeInfo(False),
					detect_msg
				),tab)+"\n")
			else:
				out.write(indent(RecipeGenerator.template_flatten_type_array_pointer_recipe.format(
					"unsigned char",
					ptrNestedRefName(refname,ptrLevel) if not ptr_in_array else ptrNestedRefName(refname,1),
					pvd_element_count_expr,
					self.safeInfo(False),
					detect_msg
				),tab)+"\n")
			self.simple = False
			self.void_pointers.append((TPDptrT,TRT,refname))
			return "unsigned char*"
		else:
			# Pointer to built-in
			# This might still be a C string
			have_c_string = False
			if pteT.classname=="builtin" and "char" in pteT.str:
				if pteEXT is not None and (pteEXT[2]=='string' or pteEXT[2]=='custom_string'):
					# char* - treat it as if it was a C string
					have_c_string = True
					if ptrLevel<=0 and not ptr_in_array:
						out.write(indent(RecipeGenerator.template_flatten_string_member_recipe.format(
							ptrNestedRefName(refname,ptrLevel),
							refoffset//8,
							self.safeInfo(True),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,''] if u!=""]),"  ")
						),tab)+"\n")
					else:
						out.write(indent(RecipeGenerator.template_flatten_string_pointer_recipe.format(
							ptrNestedRefName(refname,ptrLevel) if not ptr_in_array else ptrNestedRefName(refname,1),
							self.safeInfo(True),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,''] if u!=""]),"  ")
						),tab)+"\n")
					self.char_pointers.append((TPDptrT,TRT,refname))
					return "char*"
			if not have_c_string:
				# Ok, treat it as a pointer to ordinary built-in
				if ptrLevel<=0 and not ptr_in_array:
					out.write(indent(RecipeGenerator.template_flatten_type_array_member_recipe.format(
						pteT.str,
						ptrNestedRefName(refname,ptrLevel),
						element_count_expr,
						refoffset//8,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  ")
					),tab)+"\n")
				else:
					out.write(indent(RecipeGenerator.template_flatten_type_array_pointer_recipe.format(
						pteT.str,
						ptrNestedRefName(refname,ptrLevel) if not ptr_in_array else ptrNestedRefName(refname,1),
						element_count_expr,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  ")
					),tab)+"\n")
				self.simple = safe is True
				self.builtin_pointers.append((TPDptrT,TRT,refname))
				return pteT.str+"*"

	def generate_flatten_record_trigger(self,out,T,TPD,refname,element_count_expr,element_count_extra_msg,ptrLevel,handle_flexible_size=False,tab=0):
		if TPD:
			__type_size = TPD.size//8
			if handle_flexible_size and TPD.name in self.RTRMap and self.RTRMap[TPD.name].have_flexible_member:
				__type_size = "__FLEX_OBJSIZE__(%s)"%(refname)
			recipe = indent(RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
				TPD.name,
				__type_size,
				refname,
				element_count_expr if ptrLevel==1 else str(1),
				element_count_extra_msg if ptrLevel==1 else ""
			),tab)
			out.write(recipe+"\n")
			return TPD.name
		if T.str=="":
			anonstruct_type_name = self.get_anonstruct_typename(T)
			__type_size = T.size//8
			if handle_flexible_size and anonstruct_type_name in self.TRMap and self.TRMap[anonstruct_type_name].have_flexible_member:
				__type_size = "__FLEX_OBJSIZE__(%s)"%(refname)
			recipe = indent(RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
				anonstruct_type_name,
				__type_size,
				refname,
				element_count_expr if ptrLevel==1 else str(1),
				element_count_extra_msg if ptrLevel==1 else ""
			),tab)
			out.write(recipe+"\n")
			return anonstruct_type_name

		if T.classname=="record_forward":
			RL = [x for x in self.ftdb.types if x.classname=="record" and x.str == T.str]
			if len(RL) <= 0:
				return None
			T = RL[0]

		__type_size = T.size//8
		if handle_flexible_size and T.str in self.RRMap and self.RRMap[T.str].have_flexible_member:
			__type_size = "__FLEX_OBJSIZE__(%s)"%(refname)
		recipe = indent(RecipeGenerator.template_flatten_struct_array_pointer_self_contained.format(
			"STRUCT" if T.isunion is False else "UNION",
			T.str,
			__type_size,
			refname,
			element_count_expr if ptrLevel==1 else str(1),
			element_count_extra_msg if ptrLevel==1 else ""
		),tab)
		out.write(recipe+"\n")
		return "struct %s"%(T.str)

	def generate_flatten_pointer_trigger(self,out,T,TPD,gv,handle_flexible_size=False,tab=0,ptrLevel=0,arrsize=1,ptr_in_array=False):

		if ptrLevel==1:
			record_count_tuple = self.get_global_element_count(gv.hash,ptr_in_array)
			element_count_expr,element_count_extra_msg = self.construct_global_element_count_expression(record_count_tuple,gv,T,ptrNestedRefName(gv.name,ptrLevel),ptrLevel)

		if T.classname=="attributed" and "__attribute__((noderef))" in T.attrcore:
			# Global variable points to user memory
			return None
		if T.classname=="record" or T.classname=="record_forward":
			# pointer to struct
			rtp = self.generate_flatten_record_trigger(
				out,
				T,
				TPD,
				ptrNestedRefName(gv.name,ptrLevel),
				element_count_expr if ptrLevel==1 else str(1),
				element_count_extra_msg if ptrLevel==1 else "",
				ptrLevel,
				handle_flexible_size
			)
			if rtp is None:
				return None
			else:
				return rtp+"*"

		elif T.classname=="incomplete_array" or T.classname=="const_array":
			out.write(indent("/* TODO: implement flattening trigger for global variable '%s' */"%(gv.name),tab)+"\n")
			return None
		elif T.classname=="pointer":
			PTE = self.ftdb.types[T.refs[0]]
			TPDE = None
			if PTE.classname=="typedef":
				TPDE = PTE
				PTE = self.walkTPD(PTE)
			ptrout = io.StringIO()
			ptrtp = self.generate_flatten_pointer_trigger(ptrout,PTE,TPDE,gv,handle_flexible_size,tab+1,ptrLevel+1,arrsize,ptr_in_array)
			if ptrtp is None or ptrtp=="":
				# We have unresolved record forward types or multi-level pointers to function or pointers to incomplete arrays (strange things like that)
				# Ask the user to fix this flattening recipe
				out.write(indent("/* TODO: unable to create flattening trigger for global variable '%s' */"%(gv.name),tab)+"\n")
				return None
			else:
				out.write(RecipeGenerator.template_flatten_pointer_array_recipe.format(
					ptrtp,
					ptrNestedRefName(gv.name,ptrLevel+1),
					ptrNestedRefNameOrRoot(gv.name,ptrLevel),
					str(arrsize),
					indent(ptrout.getvalue().rstrip(),tab+1)
				)+"\n")
				return ptrtp+"*"
		elif T.classname=="enum" or T.classname=="enum_forward":
			# pointer to enum
			if TPD:
				recipe = indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(
					TPD.name,
					T.size//8,
					ptrNestedRefName(gv.name,ptrLevel),
					element_count_expr if ptrLevel==1 else str(1),
					"",
					element_count_extra_msg if ptrLevel==1 else ""
				),tab)+"\n"
				out.write(recipe+"\n")
				return TPD.name+"*"
			else:
				if T.str=="":
					anonenum_type_name = self.get_anonenum_typename(T)
					recipe = indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(
						anonenum_type_name,
						T.size//8,
						ptrNestedRefName(gv.name,ptrLevel),
						element_count_expr if ptrLevel==1 else str(1),
						"",
						element_count_extra_msg if ptrLevel==1 else ""
					),tab)+"\n"
					out.write(recipe+"\n")
					return anonenum_type_name+"*"
				else:
					recipe = indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(
						"enum %s"%(T.str),
						T.size//8,
						ptrNestedRefName(gv.name,ptrLevel),
						element_count_expr if ptrLevel==1 else str(1),
						"",
						element_count_extra_msg if ptrLevel==1 else ""
					),tab)+"\n"
					out.write(recipe+"\n")
					return "enum %s*"%(T.str)
		elif T.classname=="builtin" and T.str=="char":
			# char* - treat it as if it was a C string
			recipe = indent(RecipeGenerator.template_flatten_string_pointer_recipe.format(
				ptrNestedRefName(gv.name,ptrLevel),"",""),tab)+"\n"
			out.write(recipe+"\n")
			return "char*"
		elif T.classname=="builtin" and T.str=="void":
			# void*
			recipe = indent(RecipeGenerator.template_flatten_type_array_pointer_recipe.format(
				"unsigned char",
				ptrNestedRefName(gv.name,ptrLevel),
				element_count_expr if ptrLevel==1 else str(1),
				"",
				element_count_extra_msg if ptrLevel==1 else ""
			),tab)+"\n"
			out.write(recipe+"\n")
			return "unsigned char*"
		elif T.classname=="function":
			# pointer to function
			recipe = indent(RecipeGenerator.template_flatten_fptr_pointer_recipe.format(ptrNestedRefName(gv.name,ptrLevel)),tab)+"\n"
			out.write(recipe+"\n")
			return "void*"
		else:
			# pointer to builtin
			recipe = indent(RecipeGenerator.template_flatten_type_array_pointer_recipe.format(
				T.str,
				ptrNestedRefName(gv.name,ptrLevel),
				element_count_expr if ptrLevel==1 else str(1),
				"",
				element_count_extra_msg if ptrLevel==1 else ""
			),tab)+"\n"
			out.write(recipe+"\n")
			return T.str+"*"


	def generate_flatten_trigger(self,gv,out,additional_deps,handle_flexible_size=False):
		TID = gv.type
		gvname = gv.name
		T = self.ftdb.types[TID]
		TPD = None
		if T.classname=="typedef":
			TPD = T
			T = self.walkTPD(T)
		resolved_record_forward = None
		if T.classname=="record_forward":
			rTs = [x for x in self.ftdb.types if x.classname=="record" and x.str==T.str]
			if len(rTs)>0:
				resolved_record_forward = rTs[0]
		if T.size<=0 and T.classname=="record":
			# Pointer to structure of size 0 (no need to serialize anything)
			return None
		elif T.size<=0 and T.classname=="record_forward" and resolved_record_forward is not None and resolved_record_forward.size<=0:
			# Pointer to structure of size 0 through record forward (no need to serialize anything)
			return None
		else:
			if resolved_record_forward:
				T = resolved_record_forward
			if T.classname=="builtin":
				trigger = RecipeGenerator.template_flatten_type_array_pointer_recipe.format(T.str,"__root_ptr",str(1),"","")
				out.write(trigger+"\n")
				return T.str+"*"
			elif T.classname=="enum":
				if TPD:
					trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(TPD.name,T.size//8,"__root_ptr",str(1),"","")
					out.write(trigger+"\n")
					return TPD.name+"*"
				else:
					if T.str=="":
						anonenum_type_name = self.get_anonenum_typename(T)
						trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(anonenum_type_name,T.size//8,"__root_ptr",str(1),"","")
						out.write(trigger+"\n")
						return anonenum_type_name+"*"
					else:
						trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format("enum %s"%(T.str),T.size//8,"__root_ptr",str(1),"","")
						out.write(trigger+"\n")
						return "enum %s*"%(T.str)
			elif T.classname=="pointer":
				ptrtp = self.generate_flatten_pointer_trigger(out,T,TPD,gv,handle_flexible_size)
				return ptrtp
			elif T.classname=="record":
				recipe_out = ""
				if T.str=='list_head':
					if 'listhead_config' in self.config:
						lh_config = self.config['listhead_config']
						if gv.hash not in lh_config['disable_head_variables']:
							try_harder = False
							have_lh_head = False
							if gv.hash in lh_config['head_variables']:
								extra_info = "It was detected that the global variable '{0}' is a head of a list".format(
									"%s [%d][%s]"%(gv.name,gv.id,gv.hash),
								)
								# We have a 'list_head' variable which actually is a head of a list
								if gv.hash in lh_config['resolve_variables']:
									extra_info += "\nWe also have a member resolution information in the config file"
									rnfo = lh_config['resolve_variables'][gv.hash][0]
									if rnfo[3]<0:
										# We have resolved to the record_forward; try to find a proper record definition for that forward
										containerT_L = [x for x in self.ftdb.types if x.classname=='record' and x.str==rnfo[2]]
										if len(containerT_L)==1:
											extra_info += "\nWe have resolved this 'list_head' variable to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
												'struct %s'%(containerT_L[0].str),
												containerT_L[0].size,
												rnfo[1]
											)
											offset = rnfo[1]
											containerT = containerT_L[0]
											container_str = rnfo[2]
											container_size = containerT_L[0].size
											have_lh_head = True
										else:
											extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record variable. The problem was:\n"
											if len(containerT_L)>1:
												extra_info += "  Multiple record types for struct tag '%s' resolved to record forward"%(rnfo[2])
											if len(containerT_L)==0:
												extra_info += "  Couldn't find container record type for struct tag '%s' resolved to record forward"%(rnfo[2])
											try_harder = True
									else:
										# We have resolved this 'list_head' variable define a list of 'containerT' elements at offset 'offset'
										offset = rnfo[1]
										containerT = self.ftdb.types[rnfo[3]]
										container_str = containerT.str
										container_size = containerT.size
										have_lh_head = True
										extra_info += "\nWe have resolved this 'list_head' variable to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
											'struct %s'%(containerT.str) if containerT.classname=='record' else containerT.name,
											containerT.size//8,
											rnfo[1]
										)
								else:
									extra_info += "\nUnfortunately no resolution information was found in the config file"
									try_harder = True
							else:
								# We didn't detect that the 'list_head' variable is an actual head of a list
								extra_info = "We didn't detect that the variable '{0}' is a head of a list".format(
									"%s [%d][%s]"%(gv.name,gv.id,gv.hash),
								)
								try_harder = True
							# If we miss detecting some list head variables (or couldn't resolve them) we can always add them by hand to the 'additional_head_variables' map
							if try_harder:
								if gv.hash in lh_config['additional_head_variables']:
									extra_info += "\nIt was specified through the config file that the variable '{0}' is a head of a list".format(
										"%s [%d][%s]"%(gv.name,gv.id,gv.hash),
									)
									rnfo = lh_config['additional_head_variables'][gv.hash]
									extra_info += "\nThe exact info received from the user config was:\n"
									extra_info += json.dumps(extra_info,indent=4)
									# We have a 'list_head' variable indicated by the user provided information
									offset = rnfo['offset']
									container_str = rnfo['tag']
									containerT_L = [x for x in self.ftdb.types if x.classname=='record' and x.str==container_str]
									if len(containerT_L)==1:
										extra_info += "\nWe have resolved this 'list_head' variable to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
											'struct %s'%(containerT_L[0].str),
											containerT_L[0].size,
											offset
										)
										containerT = containerT_L[0]
										container_size = containerT_L[0].size
										have_lh_head = True
									else:
										if len(containerT_L)>1:
											if 'hash' in rnfo:
												if self.ftdb.types.contains_hash(rnfo['hash']):
													containerT = self.ftdb.types.entry_by_hash(rnfo['hash'])
													if containerT.classname=='record':
														container_size = containerT.size
														have_lh_head = True
														extra_info += "\nWe have resolved this 'list_head' variable to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
															'struct %s'%(containerT.str),
															containerT.size,
															offset
														)
													else:
														extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record variable. The problem was:\n"
														extra_info += "  User provided container type with hash '%s' is not a record type"%(rnfo['hash'])
														recipe_out += "/* INFO: %s */\n"%(extra_info)
												else:
													extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record variable. The problem was:\n"
													extra_info += "  Couldn't find container record type with type hash '%s' provided by the user"%(rnfo['hash'])
													recipe_out += "/* INFO: %s */\n"%(extra_info)
											else:
												extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record variable. The problem was:\n"
												extra_info += "  Multiple container record types detected for struct tag '%s' provided by the user\n"%(container_str)
												extra_info += "Try to disambiguate providing record type hash using the 'hash' property"
												recipe_out += "/* INFO: %s */\n"%(extra_info)
										if len(containerT_L)==0:
											extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record variable. The problem was:\n"
											extra_info += "  Couldn't find container record type for struct tag '%s' provided by the user"%(container_str)
											recipe_out += "/* INFO: %s */\n"%(extra_info)
								else:
									recipe_out += "/* INFO: %s */\n"%(extra_info)
							if have_lh_head:
								# Generate the list head recipe
								__container_size = container_size//8
								if handle_flexible_size and container_str in self.RRMap and self.RRMap[container_str].have_flexible_member:
									__container_size = "__FLEX_OBJSIZE__(__entry)"
								recipe = indent(RecipeGenerator.template_flatten_list_head_struct_member_recipe.format(
									T.size//8,
									"__root_ptr",
									container_str,
									offset,
									__container_size,
									"/* %s */\n"%(extra_info)
								),2)
								recipe_out += recipe+"\n"
								out.write(recipe_out)
								additional_deps.append((containerT.id,container_str))
								return "struct list_head*"
				if TPD:
					__type_size = T.size//8
					if handle_flexible_size and TPD.name in self.RTRMap and self.RTRMap[TPD.name].have_flexible_member:
						__type_size = "__FLEX_OBJSIZE__(__root_ptr)"
					trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
						TPD.name,
						__type_size,
						"__root_ptr",
						str(1),
						""
					)
					recipe_out += trigger+"\n"
					out.write(recipe_out)
					return "%s*"%(TPD.name)
				else:
					if T.str=="":
						anonstruct_type_name = self.get_anonstruct_typename(T)
						__type_size = T.size//8
						if handle_flexible_size and anonstruct_type_name in self.TRMap and self.TRMap[anonstruct_type_name].have_flexible_member:
							__type_size = "__FLEX_OBJSIZE__(__root_ptr)"
						trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
							anonstruct_type_name,
							__type_size,
							"__root_ptr",
							str(1),
							""
						)
						recipe_out += trigger+"\n"
						out.write(recipe_out)
						return "%s*"%(anonstruct_type_name)
					else:
						__type_size = T.size//8
						if handle_flexible_size and T.str in self.RRMap and self.RRMap[T.str].have_flexible_member:
							__type_size = "__FLEX_OBJSIZE__(__root_ptr)"
						trigger = RecipeGenerator.template_flatten_struct_array_pointer_self_contained.format(
									"STRUCT" if T.isunion is False else "UNION",
									T.str,
									__type_size,
									"__root_ptr",
									str(1),
									""
								)
						recipe_out += trigger+"\n"
						out.write(recipe_out)
						return "%s %s*"%("struct" if T.isunion is False else "union",T.str)
			elif T.classname=="incomplete_array":
				return None
			elif T.classname=="const_array":
				if T.size<=0:
					return None
				el_count,AT,ATPD,dN = self.resolve_multidimentional_array_type(T)
				if AT.classname=="builtin":
					trigger = RecipeGenerator.template_flatten_type_array_pointer_recipe.format(AT.str,"__root_ptr",str(el_count),"","")
					out.write(trigger+"\n")
					return AT.str+"[...]"
				elif AT.classname=="enum":
					if ATPD:
						trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(ATPD.name,AT.size//8,"__root_ptr",str(el_count),"","")
						out.write(trigger+"\n")
						return ATPD.name+"[...]"
					else:
						if AT.str=="":
							anonenum_type_name = self.get_anonenum_typename(AT)
							trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(anonenum_type_name,AT.size//8,"__root_ptr",str(el_count),"","")
							out.write(trigger+"\n")
							return anonenum_type_name+"[...]"
						else:
							trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format("enum %s"%(AT.str),AT.size//8,"__root_ptr",str(el_count),"","")
							out.write(trigger+"\n")
							return "enum %s[...]"%(AT.str)
				elif AT.classname=="record":
					if ATPD:
						trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
							ATPD.name,
							AT.size//8,
							"__root_ptr",
							str(el_count),
							""
						)
						out.write(trigger+"\n")
						additional_deps.append((ATPD.id,ATPD.name))
						return "%s[...]"%(ATPD.name)
					else:
						if AT.str=="":
							anonstruct_type_name = self.get_anonstruct_typename(AT)
							trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
								anonstruct_type_name,
								AT.size//8,
								"__root_ptr",
								str(el_count),
								""
							)
							out.write(trigger+"\n")
							additional_deps.append((AT.id,AT.str))
							return "%s[...]"%(anonstruct_type_name)
						else:
							try:
								trigger = RecipeGenerator.template_flatten_struct_array_pointer_self_contained.format(
									"STRUCT" if AT.isunion is False else "UNION",
									AT.str,
									AT.size//8,
									"__root_ptr",
									str(el_count),
									""
								)
							except Exception as e:
								print(json.dumps(T.json(),indent=4))
								print(json.dumps(AT.json(),indent=4))
								print(gvname)
								raise e
							out.write(trigger+"\n")
							additional_deps.append((AT.id,AT.str))
							return "%s %s[...]"%("struct" if AT.isunion is False else "union",AT.str)
				elif AT.classname=="pointer":
					ptrtp = self.generate_flatten_pointer_trigger(out,AT,ATPD,gv,handle_flexible_size,0,0,el_count,True)
					return ptrtp
				else:
					print(f"EE- Unsupported harness - {AT.id}; {AT.classname}")
					return None
			else:
				# What else could that be?
				return None

	"""
	TID - id of the struct type (might be record forward) or typedef which eventually collapses to struct type
	"""
	def generate_flatten_harness(self,TID,typename=None):
		T = self.ftdb.types[TID]
		if self.debug:
			print("g_harness %d[%s:%s] {%s}"%(TID,T.classname,T.str,typename))
		self.struct_deps = set([])
		self.anon_typedefs = list()
		self.record_typedefs = set()
		out = io.StringIO()
		self.simple = True
		TPD = None
		if T.classname=="typedef":
			if T.name in self.ignore_struct_types:
				self.ignore_count+=1
				self.resolve_struct_type_location(T.id,self.includes)
				return self.struct_deps
			TPD = self.walkTPD(T)
			if TPD.classname=="record_forward":
				try:
					TRT = [x for x in self.ftdb.types if x.classname=="record" and x.str==TPD.str][0]
				except Exception as e:
					# Here we can have a pointer to struct type which is not defined but given only through pointer to record forward (and therefore never used)
					self.warnings.append("/* Missing definition for 'struct %s' (most likely never used) */\n"%(TPD.str))
					self.gen_count+=1
					self.structs_done.append((TPD.str,""))
					self.structs_done_match.add((TPD.str,TPD.isunion))
					self.structs_missing.add((TPD["str"],TPD.isunion))
					return set([])
			else:
				TRT = TPD
		elif T.classname == "record" or T.classname == "record_forward":
			if T.str!="":
				if T.str in self.ignore_structs:
					self.ignore_count+=1
					include,loc = self.resolve_struct_location(T)
					if include:
						self.includes.add(include)
					return self.struct_deps
			else:
				if typename in self.ignore_struct_types:
					self.ignore_count+=1
					return self.struct_deps
				if typename=="":
					typename = self.get_anonstruct_typename(T)
					self.anon_typedefs.append((T.id,typename))
			if T.classname=="record_forward":
				try:
					TRT = [x for x in self.ftdb.types if x.classname=="record" and x.str==T.str][0]
				except Exception as e:
					# Here we can have a pointer to struct type which is not defined but given only through pointer to record forward (and therefore never used)
					self.warnings.append("/* Missing definition for 'struct %s' (most likely never used) */\n"%(T.str))
					self.gen_count+=1
					self.structs_done.append((T.str,""))
					self.structs_done_match.add((T.str,T.isunion))
					self.structs_missing.add((T.str,T.isunion))
					return set([])
			else:
				TRT = T
		if T.classname not in ['record', 'record_forward', 'typedef'] or TRT.classname not in ['record', 'record_forward']:
			# Ignore all others
			print(f"WW- Ignored non-struct harness - ID: {T.id}; class: {T.classname}; name: {T.str}")
			self.gen_count += 1
			self.structs_done.append((T.str, ""))
			self.structs_done_match.add((T.str,T.isunion))
			self.structs_missing.add((T.str,T.isunion))
			results = set()
			for ref in T.refs:
				type = self.ftdb.types[ref]
				if self.isTypeConst(type):
					type = self.typeToNonConst(type)
				results.add((type.id, type.str))
			return results
		# TRT - the underlying record type for which the harness is generated
		# TRTTPD - if the underlying type is a typedef this is this typedef type
		TRTTPD = None
		if T.classname=='typedef':
			TRTTPD = T
		do_recipes = True
		if TRTTPD is not None:
			Ts = "t:%s"%(TRTTPD.name)
		else:
			if TRT.str!="":
				Ts = "s:%s"%(TRT.str)
			else:
				Ts = "a:%d"%(TRT.id)
		if TPD:
			if T.name in RecipeGenerator.FLATTEN_STRUCT_TYPE_BLACKLIST:
				out.write("/* Recipes for struct type %s have been blacklisted */\n"%(T.name))
				to_fix = False
				do_recipes = False
				self.struct_types_blacklisted.add((T.name,TPD.isunion))
		else:
			if TRT.str!="" and TRT.str in RecipeGenerator.FLATTEN_STRUCT_BLACKLIST:
				out.write("/* Recipes for struct %s have been blacklisted */\n"%(TRT.str))
				to_fix = False
				do_recipes = False
				self.structs_blacklisted.add((TRT.str,TRT.isunion))
		have_flexible_member = False

		origin_typestring = Ts
		custom_include_list = list()
		if do_recipes:
			try:
				real_refs = list()
				ignore_count=0
				mVTree = IntervalTree()
				# As of the current quirk of dbjson when there's anonymous record inside a structure followed by a name we will have two entries in "refs"
				#  but only single entry in "memberoffsets"
				#	struct X { ... };       // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
				#	struct X { ... } w;     // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
				#	struct { ... };         // "__!anonrecord__" as a normal member (present in decls)
				#	struct { ... } w;       // ignore "__!anonrecord__" from refs/refnames/usedrefs (present in decls)
				#  summary: ignore all "__!recorddecl__" from decls and "__!anonrecord__" if there's the same refs entry that follows
				for i in range(len(TRT.refnames)-TRT.attrnum):
					if i in TRT.decls and ( TRT.refnames[i]!="__!anonrecord__" or (i+1<len(TRT.refs) and
							isAnonRecordDependent(self.ftdb.types[TRT.refs[i]],self.ftdb.types[TRT.refs[i+1]],self.ftdb))):
						ignore_count+=1
						continue

					erfnLst = []
					if TRT.refnames[i]!='__!anonrecord__':
						erfnLst.append(TRT.refnames[i])
					real_refs.append( (Ts,Ts,TRT,TRTTPD,TRT.refs[i],TRT.refnames[i],TRT.usedrefs[i],TRT.memberoffsets[i-ignore_count],[],[],[],[],False) )
			except Exception as e:
				print(json.dumps(TRT.json(),indent=4))
				raise e
			## Structure member can be another structure hence its members leak into the parent structure type while flattening
			to_fix = False
			have_member_ptr = False
			if self.debug:
				print ("# struct %s"%(TRT.str))
			proc_members = list()
			while len(real_refs)>0:
				# Ts: type string
				# dTs: direct type string for a given member
				# eT: enclosing record type for a given member in the chain (encloses anonymous and anchor members)
				# eTPD: if the enclosing record type was given through the typedef this is the original typedef type
				# mID: member_type ID
				# mName: member_name
				# mURef: member_usedref
				# mOff: member_offset
				# mOffLst: list of member offsets in the member chain of enclosed structure types (that allows to compute the final offset for nested member)
				# rfnLst: list of member names in the member chain of enclosed structure types
				# allowSpecLst: list of allowed access specification in the member chain of enclosed structure types
				# erfnLst: refname list of members chain in the outermost enclosing type (for anonymous records and anchor types)
				# anchorMember: if this is True we have a member who is an anchor and its internal members were already processed
				#  (you can do some additional processing for recipe generation)
				Ts,dTs,eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,anchorMember = real_refs.pop(0)
				refname = ".".join(rfnLst+[mName])
				erfn = ".".join(erfnLst+[mName])
				moffset = sum(mOffLst+[mOff])
				mStr = "s:%s:%s"%(eT.str,erfn) if eT.str!='' else "t:%s:%s"%(eTPD.name,erfn) if eTPD is not None else "%s:%s"%(Ts,erfn)
				eStr = "s:%s"%(eT.str) if eT.str!='' else "t:%s"%(eTPD.name) if eTPD is not None else "%s:%s"%(Ts,erfn)
				fStr = "%s:%s"%(origin_typestring,refname)
				dStr = "%s:%s"%(dTs,mName)
				refaccess = True
				if len(erfnLst)>0:
					refbase = ".".join(erfnLst)
					if Ts in self.allowed_members and refbase not in self.allowed_members.get(Ts, set()):
						refaccess = False
				else:
					if Ts in self.allowed_members and mName not in self.allowed_members.get(Ts, set()):
						refaccess = False

				self.member_count+=1
				# RT - type of the structure member being processed
				# TPD - if structure member is a typedef this is the original typedef type otherwise it's None
				RT = self.ftdb.types[mID]
				if self.debug:
					print("%d: %s [%s]"%(mID,mName,RT.classname))
				TPD = None
				if RT.classname=="typedef":
					TPD = RT
					RT = self.walkTPD(RT)

				# Check if we have custom recipe for this member
				if RT.classname!="record":
					custom_recipe = None
					if "@"+mStr in self.custom_recipe_member_map:
						# We have recipe for single refnames only
						if len(refname.split("."))<=1:
							custom_recipe = self.custom_recipe_member_map["@"+mStr]
					if custom_recipe is None and mStr in self.custom_recipe_member_map:
						custom_recipe = self.custom_recipe_member_map[mStr]
					if custom_recipe is not None:
						s = f"/* Custom recipe for member '{refname}' */\n{{\n{extra_newline(prepend_non_empty_lines(custom_recipe[0],'  '))}}}\n"
						proc_members.append((s,"custom",custom_recipe[1]))
						self.members_with_custom_recipes.append(mStr)
						continue

				# Check if we ignore this refname
				if "ignore_refnames" in self.config["base_config"] and origin_typestring in self.config["base_config"]["ignore_refnames"]:
					ignored_refnames = self.config["base_config"]["ignore_refnames"][origin_typestring]
					if refname in ignored_refnames:
						proc_members.append(("/* member '%s' ['%s'] was ignored by the user */\n"%(refname,mStr),None))
						continue

				# If some additional processing in recipe generation is needed for anchor type this is the place to go
				# For example:
				# If we have 'struct list_head list' member then:
				# We would've already processed 'list.next' and 'list.prev' and now we have the anchor 'list' member to handle
				if anchorMember is True:
					anchor_out = ""
					# Handle 'struct list_head'
					if RT.str=='list_head':
						# Check if we have a 'list_head' member which actually is a head of a list
						if 'listhead_config' in self.config:
							lh_config = self.config['listhead_config']
							# 'disable_head_members' allows us to treat the 'list_head' member as normal member even if it was detected as a head of a list
							if mStr not in lh_config['disable_head_members']:
								try_harder = False
								have_lh_head = False
								if mStr in lh_config['head_members']:
									extra_info = "It was detected that the member '{0}' is a head of a list".format(
										"%s [%s]"%(refname,mStr),
									)
									# We have a 'list_head' member which actually is a head of a list
									if mStr in lh_config['resolve_members']:
										extra_info += "\nWe also have a member resolution information in the config file"
										rnfo = lh_config['resolve_members'][mStr][0]
										if rnfo[3] is None or rnfo[3]<0:
											# We have resolved to the record_forward; try to find a proper record definition for that forward
											containerT_L = [x for x in self.ftdb.types if x.classname=='record' and x.str==rnfo[2]]
											if len(containerT_L)==1:
												extra_info += "\nWe have resolved this 'list_head' member to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
													'struct %s'%(containerT_L[0].str),
													containerT_L[0].size,
													rnfo[1]
												)
												offset = rnfo[1]
												containerT = containerT_L[0]
												container_str = rnfo[2]
												container_size = containerT_L[0].size
												have_lh_head = True
											else:
												extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record member. The problem was:\n"
												if len(containerT_L)>1:
													extra_info += "  Multiple record types for struct tag '%s' resolved to record forward"%(rnfo[2])
												if len(containerT_L)==0:
													extra_info += "  Couldn't find container record type for struct tag '%s' resolved to record forward"%(rnfo[2])
												try_harder = True
										else:
											# We have resolved this 'list_head' member define a list of 'containerT' elements at offset 'offset'
											offset = rnfo[1]
											containerT = self.ftdb.types[rnfo[3]]
											container_str = containerT.str
											container_size = containerT.size
											have_lh_head = True
											extra_info += "\nWe have resolved this 'list_head' member to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
												'struct %s'%(containerT.str) if containerT.classname=='record' else containerT.name,
												containerT.size,
												rnfo[1]
											)
									else:
										extra_info += "\nUnfortunately no resolution information was found in the config file"
										try_harder = True
								else:
									# We didn't detect that the 'list_head' member is an actual head of a list
									extra_info = "We didn't detect that the member '{0}' is a head of a list".format(
										"%s [%s]"%(refname,mStr),
									)
									try_harder = True
								# If we miss detecting some list head members (or couldn't resolve them) we can always add them by hand to the 'additional_head_members' map
								if try_harder:
									if mStr in lh_config['additional_head_members']:
										extra_info += "\nIt was specified through the config file that the member '{0}' is a head of a list".format(
											"%s [%s]"%(refname,mStr),
										)
										rnfo = lh_config['additional_head_members'][mStr]
										extra_info += "\nThe exact info received from the user config was:\n"
										extra_info += json.dumps(extra_info,indent=4)
										# We have a 'list_head' member indicated by the user provided information
										offset = rnfo['offset']
										container_str = rnfo['tag']
										containerT_L = [x for x in self.ftdb.types if x.classname=='record' and x.str==container_str]
										if len(containerT_L)==1:
											extra_info += "\nWe have resolved this 'list_head' member to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
												'struct %s'%(containerT_L[0].str),
												containerT_L[0].size//8,
												offset
											)
											containerT = containerT_L[0]
											container_size = containerT_L[0].size
											have_lh_head = True
										else:
											if len(containerT_L)>1:
												if 'hash' in rnfo:
													if self.ftdb.types.contains_hash(rnfo['hash']):
														containerT = self.ftdb.types.entry_by_hash(rnfo['hash'])
														if containerT.classname=='record':
															container_size = containerT.size
															have_lh_head = True
															extra_info += "\nWe have resolved this 'list_head' member to define a list of '{0}' elements (of size {1}) each having its 'list_head' anchor at the offset {2}".format(
																'struct %s'%(containerT.str),
																containerT.size,
																offset
															)
														else:
															extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record member. The problem was:\n"
															extra_info += "  User provided container type with hash '%s' is not a record type"%(rnfo['hash'])
															anchor_out += "/* INFO: %s */\n"%(extra_info)
													else:
														extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record member. The problem was:\n"
														extra_info += "  Couldn't find container record type with type hash '%s' provided by the user"%(rnfo['hash'])
														anchor_out += "/* INFO: %s */\n"%(extra_info)
												else:
													extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record member. The problem was:\n"
													extra_info += "  Multiple container record types detected for struct tag '%s' provided by the user\n"%(container_str)
													extra_info += "Try to disambiguate providing record type hash using the 'hash' property"
													anchor_out += "/* INFO: %s */\n"%(extra_info)
											if len(containerT_L)==0:
												extra_info += "\nUnfortunately we were further unable to unambiguously resolve this record member. The problem was:\n"
												extra_info += "  Couldn't find container record type for struct tag '%s' provided by the user"%(container_str)
												anchor_out += "/* INFO: %s */\n"%(extra_info)
									else:
										anchor_out += "/* INFO: %s */\n"%(extra_info)
								if have_lh_head:
									# Generate the list head recipe
									recipe = indent(RecipeGenerator.template_aggregate_flatten_list_head_struct_member_recipe.format(
										RT.size//8,
										mName,
										moffset//8,
										(moffset+RT.memberoffsets[0])//8,
										(moffset+RT.memberoffsets[1])//8,
										container_str,
										offset,
										container_size//8,
										"/* %s */\n"%(extra_info)
									),2)
									anchor_out += recipe+"\n"
									proc_members.append((anchor_out,'list_head'))
									self.struct_deps.add((containerT.id,container_str))
									self.struct_deps.add((RT.id,RT.str))
					else:
						# Any other classes here?
						pass
					continue

				# Handle member record type
				if RT.classname=="record":
					RTstr = "t:%s"%(TPD.name) if TPD is not None else "s:%s"%(RT.str) if RT.str!="" else "a:%d"%(RT.id)
					internal_real_refs = list()
					ignore_count=0
					for i in range(len(RT.refnames)-RT.attrnum):
						if i in RT.decls and ( RT.refnames[i]!="__!anonrecord__" or (i+1<len(RT.refs) and
								isAnonRecordDependent(self.ftdb.types[RT.refs[i]],self.ftdb.types[RT.refs[i+1]],self.ftdb))):
							ignore_count+=1
							continue
						else:
							member_list = list()
							emember_list = list()
							allowspec_list = list()
							if mName=="__!anonrecord__":
								eTs,eRT,eRTTPD = Ts,eT,eTPD
							else: # mName!="__!anonrecord__"
								if RT.str in self.anchor_list:
									eTs,eRT,eRTTPD = Ts,eT,eTPD
									emember_list.append(mName)
								else:
									eTs,eRT,eRTTPD = "t:%s"%(TPD.name) if TPD is not None else "s:%s"%(RT.str),RT,TPD
									erfnLst.clear()
								member_list.append(mName)
								allowspec_list.append(refaccess)
							internal_real_refs.append( (eTs,RTstr,eRT,eRTTPD,RT.refs[i],RT.refnames[i],RT.usedrefs[i],RT.memberoffsets[i-ignore_count],
								mOffLst+[mOff],rfnLst+member_list,allowSpecLst+allowspec_list,erfnLst+emember_list,False) )
					internal_real_refs.append( (Ts,Ts,eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,True) )
					real_refs = internal_real_refs+real_refs
					continue

				# Check whether fields in this structure haven't been restricted by config file
				if not (all(allowSpecLst) and refaccess is True):
					proc_members.append(("/* flattening member '%s' was restricted by a config file */\n"%(refname),None))
					continue

				if self.debug:
					tpstr = "struct %s"%(TRT.str) if TRT.str!='' else "%s"%(TRTTPD.name)
					etpstr = "struct %s"%(eT.str) if eT.str!='' else "%s"%(eTPD.name)
					print ("@ %s:%s [%s:%s] ***  [%s:%s] @ %d [%s]"%(tpstr,refname,RT.classname,RT.str,etpstr,erfn,moffset,mStr))

				# Check if the member was not used in the call graph of specified functions
				if 'OT_info' in self.config and 'used_full_members' in self.config['OT_info']:
					MU = set(self.config['OT_info']['used_full_members'])
					if fStr not in MU:
						proc_members.append(("/* member '%s' was not used [config] */\n"%(refname),None))
						continue
				else:
					# If we don't have the call graph usage information fallback to the entire call graph tree
					if mURef<0:
						proc_members.append(("/* member '%s' was not used [call graph] */\n"%(refname),None))
						continue

				proc_members.append((eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,refname,erfn,moffset,mStr,eStr,dStr,refaccess))

				moffEnd = moffset
				if RT.size<=0:
					if RT.classname=='incomplete_array':
						moffEnd+=TRT.size
				else:
					moffEnd+=RT.size
				if moffEnd>moffset:
					mVTree[moffset:moffEnd] = mStr
			# while len(real_refs)>0:

			mi = -1
			outv = list()
			proc_members_to_process_num = len([x for x in proc_members if len(x)>2])
			for item in proc_members:
				if len(item)==2 or len(item)==3:
					# We have precomputed member information already
					if item[1] is not None:
						# We have data from anchor member to process (or custom recipe)
						if item[1]=='list_head':
							outv = outv[:-2]+[item[0]]
						elif item[1]=='custom':
							outv.append(item[0])
							custom_include_list+=item[2]
							self.simple = False
					else:
						# Simply pass the precomputed member information through
						outv.append(item[0])
					continue
				else:
					eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,refname,erfn,moffset,mStr,eStr,dStr,refaccess = item

				mi+=1
				RT = self.ftdb.types[mID]
				TPD = None
				if RT.classname=="typedef":
					TPD = RT
					RT = self.walkTPD(RT)

				iout = io.StringIO()
				def handle_overlapping_members():
					if 'OT_info' in self.config and 'overlapping_members' in self.config['OT_info']:
						if mStr in self.config['OT_info']['overlapping_members']:
							# This member overlaps with some other member(s)
							ovnfo = self.config['OT_info']['overlapping_members'][mStr]
							if ovnfo['use'] is True:
								return True
							elif ovnfo['ignore'] is True:
								# Skip this union member
								return False
							else:
								ovLst = ovnfo['overlap_list']
								iout.write("/* member '%s' overlaps with %d other members */\n"%(refname,len(ovLst)-1))
								iout.write("/* List of overlapping members:\n")
								iout.write("\n".join([" * %s@%d[%d]"%(x[0],x[1]//8,x[2]//8) for x in ovLst])+" */\n")
								iout.write("/* Please provide custom recipe or indicate used member in config file */\n")
								self.ptr_in_union.append((TPD,TRT,refname))
								self.simple = False
								return False
					return True

				if RT.classname=="enum" or RT.classname=="builtin":
					# No need to do anything
					pass
				elif RT.classname=="pointer":
					self.member_recipe_count+=1
					PTEExt = None
					# None if PTE points to the original type
					# [0] pointee_TID (-1 if there was ambiguity in the result (PTE is not replaced))
					# [1] offset
					# [2] kind ('container_of', 'pvoid', 'string', 'custom' or 'custom_string')
					# [3] extra
					#		for 'container_of' this is the container_of expression; in case of ambiguity this is the full container_of_map entry list
					#		for 'pvoid' this is a list of 'void*' cast expressions; in case of ambiguity this is full pvoid_map entry list
					#		for 'string' this is a list of call expressions passed to the c-string parameters (no ambiguity possible)
					#		for 'custom' this is the custom info from config file (no ambiguity)
					#		for 'custom_string' this is the custom info from config file (no ambiguity)
					# [4] more extra
					#       for 'pvoid' this is 'container_of_parm_map' element information of 'container_of' calling functions in the surrounding type chain

					# Handle overlapping members
					if not handle_overlapping_members():
						continue

					# PTE - type the structure member pointer points to
					# TPDE - if structure member pointer points to a typedef this is the original typedef type otherwise it's None
					PTE = self.ftdb.types[RT.refs[0]]
					TT,TTPD = self.resolve_record_type(PTE.id)
					if self.debug:
						if TT:
							TTstr = "struct %s"%(TT.str)
						else:
							TTstr = PTE.hash
						print ("struct %s (%s)[%s]"%(self.ftdb.types[eT.id].str,erfn,TTstr))

					# Check if the member pointer points to a different type than specified in the structure
					#  (either through the use of 'container_of' macro or source type casting constructs)
					#  (or we point to the type directly through the config file)
					PTE,PTEExt = self.real_pointee_type(mStr,dStr,refname,PTE)

					# Now try to generate some recipes
					TPDE = None
					if PTE.classname=="typedef":
						TPDE = PTE
						PTE = self.walkTPD(PTE)
					resolved_record_forward = None
					if PTE.classname=="record_forward":
						rTs = [x for x in self.ftdb.types if x.classname=="record" and x.str==PTE.str]
						if len(rTs)>0:
							resolved_record_forward = rTs[0]
					if PTE.size<=0 and PTE.classname=="record":
						iout.write("/* member '%s' points to a structure of size 0 */\n"%(refname))
					elif PTE.size<=0 and PTE.classname=="record_forward" and resolved_record_forward is not None and resolved_record_forward.size<=0:
						iout.write("/* member '%s' points to a structure of size 0 (through record forward) */\n"%(refname))
					elif PTE.classname=="record_forward" and resolved_record_forward is None:
						iout.write("/* member '%s' points to unresolved record forward '%s' (most likely never used) */\n"%(refname,PTE.str))
					else:
						have_member_ptr = True
						if resolved_record_forward:
							PTE = resolved_record_forward
						if self.generate_flatten_pointer(iout,RT,PTE,PTEExt,mStr,dStr,refname,moffset,TRT,0,TPD,TPDE,0) is None:
							to_fix = True
							self.complex_pointer_members.append((TPD,TRT,refname))
				# RT.classname=="pointer"
				elif RT.classname=="incomplete_array" or RT.classname=="const_array":
					self.member_recipe_count+=1
					sz,AT,TPDAT,dN = self.resolve_multidimentional_array_type(RT)
					# We have an (multidimensional) array of type AT
					if AT.classname=="record" or AT.classname=="record_forward":
						if AT.classname=="record_forward":
							AT = [x for x in self.ftdb.types if x.classname=="record" and x.str==AT.str][0]
						if RT.classname=="const_array" and sz>0:
							if not TPDAT:
								if AT.str=="":
									anonstruct_type_name = self.get_anonstruct_typename(AT)
									self.anon_typedefs.append((AT.id,anonstruct_type_name))
									iout.write(indent(RecipeGenerator.template_flatten_struct_type_array_storage_recipe.format(
										sz,
										anonstruct_type_name,
										refname,
										moffset//8,
										self.safeInfo(False),
										AT.size//8
									),0)+"\n")
									self.struct_deps.add((AT.id,anonstruct_type_name))
								else:
									if AT.isunion is False:
										iout.write(indent(RecipeGenerator.template_flatten_struct_array_storage_recipe.format(
											sz,
											AT.str,
											refname,
											moffset//8,
											self.safeInfo(False),
											AT.size//8
										),0)+"\n")
									else:
										iout.write(indent(RecipeGenerator.template_flatten_union_array_storage_recipe.format(
											sz,
											AT.str,
											refname,
											moffset//8,
											self.safeInfo(False),
											AT.size//8
										),0)+"\n")
									self.struct_deps.add((AT.id,AT.str))
							else:
								iout.write(indent(RecipeGenerator.template_flatten_struct_type_array_storage_recipe.format(
									sz,
									TPDAT.name,
									refname,
									moffset//8,
									self.safeInfo(False),
									TPDAT.size//8
								),0)+"\n")
								self.struct_deps.add((TPDAT.id,TPDAT.name))
								self.record_typedefs.add((TPDAT.name,AT.str,AT.id))
						else:
							# const array of size 0 or incomplete array; if it's the last member in the record generate recipe for flexible array member
							if (mi+1>=proc_members_to_process_num):
								if not TPDAT:
									if AT.str=="":
										anonstruct_type_name = self.get_anonstruct_typename(AT)
										self.anon_typedefs.append((AT.id,anonstruct_type_name))
										iout.write(indent(RecipeGenerator.template_flatten_struct_type_flexible_recipe.format(
											anonstruct_type_name,
											AT.size//8,
											refname,
											moffset//8,
											self.safeInfo(False)
										),0)+"\n")
										self.struct_deps.add((AT.id,anonstruct_type_name))
										have_flexible_member = True
									else:
										if AT.isunion is False:
											iout.write(indent(RecipeGenerator.template_flatten_struct_flexible_recipe.format(
												AT.str,
												AT.size//8,
												refname,
												moffset//8,
												self.safeInfo(False)
											),0)+"\n")
										else:
											iout.write(indent(RecipeGenerator.template_flatten_union_flexible_recipe.format(
												AT.str,
												AT.size//8,
												refname,
												moffset//8,
												self.safeInfo(False)
											),0)+"\n")
										self.struct_deps.add((AT.id,AT.str))
										have_flexible_member = True
								else:
									iout.write(indent(RecipeGenerator.template_flatten_struct_type_flexible_recipe.format(
										TPDAT.name,
										AT.size//8,
										refname,
										moffset//8,
										self.safeInfo(False)
									),0)+"\n")
									self.struct_deps.add((TPDAT.id,TPDAT.name))
									self.record_typedefs.add((TPDAT.name,AT.str,AT.id))
									have_flexible_member = True
								self.flexible_array_members.append((TPD,TRT,refname))
							else:
								iout.write("/* TODO: member '%s' is a const/incomplete array of size 0; looks like flexible array member but it's not a last member in the record (what is it then?) */\n"%(refname))
								self.complex_members.append((TPD,TRT,refname))
							self.simple = False
					elif AT.classname=="enum" or AT.classname=="enum_forward" or AT.classname=="builtin":
						# Need to handle flexible array member
						if sz<=0:
							tpname = AT.str
							if AT.classname=="enum" or AT.classname=="enum_forward":
								if AT.str=="":
									tpname = self.get_anonenum_typename(AT)
									self.anon_typedefs.append((AT.id,tpname))
								else:
									tpname = "enum %s"%(AT.str)
							if (mi+1>=proc_members_to_process_num):
								iout.write(indent(RecipeGenerator.template_flatten_type_array_flexible_recipe.format(
									tpname,
									AT.size//8,
									refname,
									moffset//8,
									self.safeInfo(False)
								),0)+"\n")
								have_flexible_member = True
							else:
								iout.write("/* TODO: member '%s' is a const/incomplete array of size 0; looks like flexible array member but it's not a last member in the record (what is it then?) */\n"%(refname))
								self.complex_members.append((TPD,TRT,refname))
					elif AT.classname=="pointer":
							# We have an array of pointers
							# Generally it's the same as normal pointer, just we might have many of them
							# We assume all pointers in array point to the same kind of things (otherwise custom recipe is needed)
							# We also only consider custom pointer information from config file (as the data for pointer members is only valid for the plain pointers case)
							if not handle_overlapping_members():
								continue
							PTE = self.ftdb.types[AT.refs[0]]
							PTE,PTEExt = self.real_pointee_type(mStr,dStr,refname,PTE,True)
							TPDE = None
							if PTE.classname=="typedef":
								TPDE = PTE
								PTE = self.walkTPD(PTE)
							resolved_record_forward = None
							if PTE.classname=="record_forward":
								rTs = [x for x in self.ftdb.types if x.classname=="record" and x.str==PTE.str]
								if len(rTs)>0:
									resolved_record_forward = rTs[0]
							if PTE.size<=0 and PTE.classname=="record":
								iout.write("/* member '%s' points to multiple structures of size 0 */\n"%(refname))
							elif PTE.size<=0 and PTE.classname=="record_forward" and resolved_record_forward is not None and resolved_record_forward.size<=0:
								iout.write("/* member '%s' points to multiple structures of size 0 (through record forward) */\n"%(refname))
							elif PTE.classname=="record_forward" and resolved_record_forward is None:
								iout.write("/* member '%s' points to multiple unresolved record forwards '%s' (most likely never used) */\n"%(refname,PTE.str))
							else:
								have_member_ptr = True
								if resolved_record_forward:
									PTE = resolved_record_forward
							ptrout = io.StringIO()
							ptrtp = self.generate_flatten_pointer(ptrout,AT,PTE,PTEExt,mStr,dStr,refname,moffset,TRT,0,TPDAT,TPDE,0,True)
							if ptrtp is None or ptrtp=="":
								to_fix = True
								self.complex_pointer_members.append((TPD,TRT,refname))
							else:
								if RT.classname=="const_array" and sz>0:
									r = RecipeGenerator.template_flatten_pointer_storage_recipe.format(
										ptrtp,
										ptrNestedRefName(refname,1),
										ptrNestedRefName(refname,0,True,moffset//8,True),
										sz,
										self.safeInfo(False),
										indent(ptrout.getvalue().rstrip(),1),
										""
									)+"\n"
									iout.write(r)
								else:
									# Flexible array of pointers (really?)
									if (mi+1>=proc_members_to_process_num):
										r = RecipeGenerator.template_flatten_pointer_array_flexible_recipe.format(
											ptrtp,
											AT.size//8,
											moffset//8,
											refname,
											ptrNestedRefName(refname,1),
											ptrNestedRefName(refname,0,True,moffset//8,True),
											indent(ptrout.getvalue().rstrip(),1),
											"",
											self.safeInfo(False)
										)+"\n"
										iout.write(r)
									else:
										iout.write("/* TODO: member '%s' is a const/incomplete array of size 0; looks like flexible array member but it's not a last member in the record (what is it then?) */\n"%(refname))
										self.complex_members.append((TPD,TRT,refname))
							self.simple = False
					else:
						# Something else
						# Keep this program simple and let the user fix it
						iout.write("/* TODO: implement flattening member '%s' (too complicated; I'm not that smart yet) */\n  /* Member type: %s */\n"%(refname,RT.hash))
						self.complex_members.append((TPD,TRT,refname))
						self.simple = False
				member_disp_match = "/* ------------------------------ \n%s\n    [%s]\n ------------------------------ */\n"%("\n".join([x for x in eT.defstring.split("\n") if mName in x]),refname)
				outv.append(member_disp_match+iout.getvalue())
			# for (...) in proc_members
			out.write('\n'.join([x for x in outv if x.strip()!=""]))
		# if do_recipes:
		to_check = False
		check_union = False
		if not self.simple:
			to_check = True
			if TRT.isunion is True and have_member_ptr:
				# We've had at least one pointer in the union; verify the internal union recipes
				check_union = True

		# We enter here in all cases except that when we have a complex structure to process and only_simple flag is passed
		#  i.e. we ignore structures which requires internal flattening recipes to provide
		if T.classname=="record" or T.classname=="record_forward":
			if T.str!="":
				if T.str not in set([u[0] for u in self.structs_done_match]):
					include,loc = self.resolve_struct_location(T)
					if include is not None:
						self.includes.add(include)
						if have_flexible_member:
							assert TRT.isunion is False, "ERROR: Flexible array members in union?"
							recipe_str = RecipeGenerator.template_flatten_define_struct_flexible_recipe.format(
									T.str,
									indent(out.getvalue().strip()),
									"/* Type definition:\n%s */\n"%(TRT.defstring)
							)
						else:
							recipe_str = RecipeGenerator.template_flatten_struct_recipe.format(
									"STRUCT" if TRT.isunion is False else "UNION",
									T.str,
									TRT.size//8,
									indent(out.getvalue().strip()),
									"/* Type definition:\n%s */\n"%(TRT.defstring)
							)
						self.record_recipes.append(RecordRecipe(T,TRT,recipe_str,include,loc,custom_include_list,self.simple,to_check,check_union,to_fix,have_flexible_member))
					else:
						self.unresolved_struct_includes.append((T.str,loc))
						if have_flexible_member:
							assert TRT.isunion is False, "ERROR: Flexible array members in union?"
							recipe_str = RecipeGenerator.template_flatten_define_struct_flexible_recipe.format(
									T.str,
									indent(out.getvalue().strip()),
									"/* Type definition:\n%s */\n"%(TRT.defstring)
							)
						else:
							recipe_str = RecipeGenerator.template_flatten_struct_recipe.format(
									"STRUCT" if TRT.isunion is False else "UNION",
									T.str,
									TRT.size//8,
									indent(out.getvalue().strip()),
									"/* Type definition:\n%s */\n"%(TRT.defstring)
							)
						self.record_recipes.append(RecordRecipe(T,TRT,recipe_str,None,loc,custom_include_list,self.simple,to_check,check_union,to_fix,have_flexible_member))
					self.structs_done.append((T.str,loc))
					self.structs_done_match.add((T.str,T.isunion))
					self.gen_count+=1
			else:
				if typename not in self.struct_types_done_match:
					if have_flexible_member:
						recipe_str = RecipeGenerator.template_flatten_define_struct_type_flexible_recipe.format(
								typename,
								indent(out.getvalue().strip()),
								"/* Type definition:\n%s */\n"%(TRT.defstring)
						)
					else:
						recipe_str = RecipeGenerator.template_flatten_struct_type_recipe.format(
								typename,
								TRT.size//8,
								indent(out.getvalue().strip()),
								"/* Type definition:\n%s */\n"%(TRT.defstring)
						)
					self.typename_recipes.append(TypenameRecipe(typename,TRT,recipe_str,custom_include_list,self.simple,to_check,check_union,to_fix,have_flexible_member))
					self.struct_types_done.append((typename,""))
					self.struct_types_done_match.add(typename)
					self.gen_count+=1
		else:
			if T.name not in self.struct_types_done_match:
				new_includes = RG.resolve_struct_type_location(T.id,self.includes)
				if not new_includes:
					if have_flexible_member:
						recipe_str = RecipeGenerator.template_flatten_define_struct_type_flexible_recipe.format(
								T.name,
								indent(out.getvalue().strip()),
								"/* Type definition:\n%s */\n"%(TRT.defstring)
						)
					else:
						recipe_str = RecipeGenerator.template_flatten_struct_type_recipe.format(
								T.name,
								TRT.size//8,
								indent(out.getvalue().strip()),
								"/* Type definition:\n%s */\n"%(TRT.defstring)
						)
					self.record_type_recipes.append(RecordTypeRecipe(T,TRT,recipe_str,None,custom_include_list,self.simple,to_check,check_union,to_fix,have_flexible_member))
					self.unresolved_struct_type_includes.append((T.name,T.location,T.id))
				else:
					if have_flexible_member:
						recipe_str = RecipeGenerator.template_flatten_define_struct_type_flexible_recipe.format(
								T.name,
								indent(out.getvalue().strip()),
								"/* Type definition:\n%s */\n"%(TRT.defstring)
						)
					else:
						recipe_str = RecipeGenerator.template_flatten_struct_type_recipe.format(
								T.name,
								TRT.size//8,
								indent(out.getvalue().strip()),
								"/* Type definition:\n%s */\n"%(TRT.defstring)
						)
					self.record_type_recipes.append(RecordTypeRecipe(T,TRT,recipe_str,new_includes,custom_include_list,self.simple,to_check,check_union,to_fix,have_flexible_member))
				self.struct_types_done.append((T.name,T.location,T.id))
				self.struct_types_done_match.add(T.name)
				self.record_typedefs.add((T.name,TRT.str,TRT.id))
				self.gen_count+=1
		return self.struct_deps

	def resolve_struct_location(self,T):
		if T.classname=="record_forward":
			RT = [x for x in self.ftdb.types if x.classname=="record" and x.str==T.str]
			if len(RT)<=0:
				return None,None
			loc = RT[0].location
		else:
			loc = T.location
		return self.get_include_file(":".join(loc.split(":")[:-2])),loc

	def get_include_file(self,loc):
		if not os.path.isabs(loc):
			loc = os.path.normpath(loc)
		for idir in self.include_dirs:
			if loc.startswith(idir):
				return loc[len(idir):].lstrip("/")
		return None

	"""
	Walk all typedefs and add include file where this typedef was defined
	Also add include for the final struct type this typedef actually defined
	"""
	def resolve_struct_type_location(self,TID,includes):
		T = self.ftdb.types[TID]
		include = self.get_include_file(":".join(T.location.split(":")[:-2]))
		new_includes = set()
		if include:
			new_includes.add(include)
		else:
			return None
		if T.classname=="typedef":
			inclues|=new_includes
			ni = self.resolve_struct_type_location(T.refs[0],includes)
			if ni:
				new_includes|=ni
				return new_includes
			else:
				return None
		inclues|=new_includes
		return new_includes

	def compute_recipe_maps(self):
		self.RRMap = {}
		for RR in RG.record_recipes:
			if RR.RT.str in self.RRMap:
				print ("WARNING: Multiple record recipes for structure '%s'"%(RR.RT.str))
			self.RRMap[RR.RT.str] = RR
		self.TRMap = {}
		for TR in RG.typename_recipes:
			if TR.typename in self.TRMap:
				print ("WARNING: Multiple typename recipes for typename '%s'"%(TR.typename))
			self.TRMap[TR.typename] = TR
		self.RTRMap = {}
		for RTR in RG.record_type_recipes:
			if RTR.TPD.name in self.RTRMap:
				print ("WARNING: Multiple record type recipes for typedef '%s'"%(RTR.TPD.name))
			self.RTRMap[RTR.TPD.name] = RTR

	def compute_argument_triggers(self,func,func_args_to_dump,additional_deps):

		arg_updated_type = False
		rLst = list()
		for arg in func_args_to_dump:
			# (0:res.id, 1:res.str if res.classname == 'record' else res.name), 2:res.size // 8, 3:res.classname, 4:offset)
			if isinstance(arg,tuple):
				arg = [arg]
			if len(arg[0])>5:
				arg_updated_type = arg[0][5]
			narg = list(arg[0][:5])+[arg[0][0],arg[0][2],"struct %s"%(arg[0][0]) if arg[0][3]=='record' else arg[0][0]] # += [5:original type string,6:original typesize,7:full original type string]
			argStr = ("____%s____%d"%(func,narg[1]-1))
			extra_info = ""
			if not arg_updated_type:
				if "ptr_config" in self.config and "container_of_parm_map" in self.config["ptr_config"] and argStr in self.config["ptr_config"]["container_of_parm_map"]:
					cpM = self.config['ptr_config']['container_of_parm_map']
					e = cpM[argStr][0]
					tp_chain = list()
					cPTE = e["tpid"]
					if 'container_of_local_map' in self.config['ptr_config']:
						clM = self.config['ptr_config']['container_of_local_map']
						# Check if the argument further undergone the 'container_of' pattern
						while True:
							nPTE = None
							for fkey,cinfo in cpM.items():
								if len(cinfo)>1:
									# Omit ambiguous entries
									continue
								tpargid = self.ftdb.types.entry_by_id(cinfo[0]['tpargid'])
								if tpargid.classname=='pointer' and tpargid.refs[0]==cPTE:
									# We look for exactly one match
									if nPTE is not None:
										nPTE = None
										break
									nPTE = (fkey,cinfo[0])
							else:
								if nPTE is None:
									for fkey,cinfo in clM.items():
										if len(cinfo)>1:
											# Omit ambiguous entries
											continue
										tpvarid = self.ftdb.types.entry_by_id(cinfo[0]['tpvarid'])
										if tpvarid.classname=='pointer' and tpvarid.refs[0]==cPTE:
											# We look for exactly one match
											if nPTE is not None:
												nPTE = None
												break
											nPTE = (fkey,cinfo[0])
							if nPTE:
								# We've found unambiguous entry, save it a look further until no more entries are found
								tp_chain.append(nPTE)
								cPTE = nPTE[1]['tpid']
							else:
								break
					tp = self.ftdb.types.entry_by_id(e["tpid"])
					tp_offset = e["offset"]
					extra_info += "/* It was detected that the function argument no. {0} of the original type '{1}' is a part of a larger type '{2}' at offset {3}. We concluded that from the 'container_of' expression at the following location:\n  {4}".format(
						narg[1],
						narg[7],
						"struct %s"%(tp.str) if tp.classname == 'record' else tp.name,
						tp_offset,
						e["expr"]
					)
					if "call_id" in e:
						extra_info += "\n   The conclusion was made based on a call deeper down in the call graph. The first function called was '{0}' */".format(
							self.ftdb.funcs.entry_by_id(e["call_id"]).name,
						)
					else:
						extra_info += " */"
					if len(tp_chain)>0:
						tp = self.ftdb.types.entry_by_id(tp_chain[-1][1]['tpid'])
						tp_offset += sum([x[1]['offset'] for x in tp_chain])
						extra_info += "\n/* It was further detected that the type the function argument no. {0} points to was additionally embedded into more enclosing types accessed using \
the 'container_of' invocation chain.\n   The invocation chain was as follows:\n{1} */".format(
								narg[1],
					   		"\n".join(["     {0}@{1}: {2} -> {3} : {4} @ {5}".format(
						            x[0].split("____")[1],
						            x[0].split("____")[2],
						            x[1]['tpargs'] if 'tpargs' in x[1] else x[1]['tpvars'] if 'tpvars' in x[1] else '',
						            x[1]['tps'],
						            x[1]['offset'],
						            x[1]['expr']
				        ) for x in tp_chain])
	)
					narg[2] = tp.size//8
					narg[3] = tp.classname
					narg[4] = tp_offset
					narg[5] = tp.str if tp.classname == 'record' else tp.name
					additional_deps.append((tp.id,narg[5]))
				else:
					if narg[3]=='record':
						RT = RG._find_record_type_by_tag(narg[5])
						additional_deps.append((RT.id,narg[5]))
					else:
						TPD = RG._find_typedef_type_by_name(narg[5])
						additional_deps.append((TPD.id,narg[5]))
			if len(arg)>1:
				extra_info += "\n/* It was detected that the config file specified {1} additional triggers for the function argument no. {0}. Additional triggers are reflected in the recipe */".format(
					narg[1],
					len(arg)-1
				)
			extra_triggers = ""
			if len(arg)>1:
				for extra_arg in arg[1:]:
					extra_triggers+="\n\t\t\t\t\tFLATTEN_STRUCT_{3}SHIFTED_SELF_CONTAINED({0}, {1}, target, {2});".format(
						extra_arg[0],
						extra_arg[2],
						extra_arg[4],
						"TYPE_" if extra_arg[3]=='typedef' else ""
					)

			rLst.append((narg,extra_info,extra_triggers))

		return rLst

####################################
# Program Entry point
####################################
def main():
	global RG

	parser = argparse.ArgumentParser(description="Automated generator of KFLAT flattening recipes")
	parser.add_argument("struct", help="struct type for which kflat recipes will be generated", nargs='*')

	parser.add_argument("-v", dest="verbose", action="store_true", help="print verbose (debug) information")
	parser.add_argument("-n", dest="dry_run", action="store_true", help="Show records to generate recipes for and exit")
	parser.add_argument("-d", dest="database", action="store", help="function/type JSON database file", type=str, default='db.json')
	parser.add_argument("-g", dest="global_database", action="store", help="global function/type JSON database file", type=str, required=False)
	parser.add_argument("-o", dest="output", action="store", help="output directory", type=str, default='recipe_gen')
	parser.add_argument("-c", dest="config", action="store", help="script layout config", type=str)
	parser.add_argument("-f", dest="func", action="store", help="", type=str, required=True)
	parser.add_argument("-m", dest="common", action="store", help="path to the file that provides additional common code to be included in generated recipes", type=str)

	parser.add_argument("--recipe-id", action="store", type=str, help="Recipe target")
	parser.add_argument("--module-name", action="store", type=str, help="Name of the module to be generated")
	parser.add_argument("--globals-list", action="store", type=str, help="File with list of hashes of globals that should be flattened")
	parser.add_argument("--ignore-structs", action="store", help="Do not generate descriptions for the following structs (delimited by ',')")

	# TODO: Consider removing include dirs
	parser.add_argument("--include-dirs", action="store", help="Include directory for header files with structure definitions (delimited by ':')")
	args = parser.parse_args()

	RG = RecipeGenerator(args)
	if args.config:
		RG.parse_structures_config(args.config, args.func)

	if not args.recipe_id:
		args.recipe_id = RG.gen_recipe_id()

	if len(args.struct) == 1 and args.struct[0] == 'AUTO':
		args.struct = RG.gen_args_list(args.func)

	deps_done = set([])
	anon_typedefs = list()
	record_typedefs = set()

	# Parse input structures lists
	func_args_to_dump, globals_to_dump, deps = RG.parse_arguments(args.struct, args.globals_list, args.func)
	if len(deps) == 0:
		print(f'EE- No structures to generate recipes for')
		exit(1)
	# First pass of generating global triggers just to catch additional dependencies
	additional_deps = list()
	for glob in globals_to_dump:
		out = io.StringIO()
		gv = RG.ftdb.globals[glob[5]]
		RG.generate_flatten_trigger(gv, out, additional_deps)

	# Now look for additional dependencies or argument triggers
	argList = RG.compute_argument_triggers(args.func,func_args_to_dump,additional_deps)
	deps|=set(additional_deps)

	print(f"--- Generating recipes for {len(deps)} structures ...")

	if args.dry_run:
		for x in deps:
			print ("%s:%s"%('s' if RG.ftdb.types[x[0]].classname=='record' else 't',x[1]))
		sys.exit(0)

	gen_count = 0
	while len(deps-deps_done)>0:
		T,typename = deps.pop()
		if (T,typename) not in deps_done:
			deps |= RG.generate_flatten_harness(T,typename)
			gen_count+=1
			deps_done.add((T,typename))
			anon_typedefs+=RG.anon_typedefs
			record_typedefs|=RG.record_typedefs

	print ("--- Generated flattening descriptions for %d types:\n"
			"\t[%d record recipes, %d record type recipes, %d typename recipes]\n"
			"\t(%d to check) (%d to fix) (%d missing)\n"
			"\t(%d members, %d members with recipes, %d members not safe,\n\t%d members not used, %d members points to user memory)"%(
	len(RG.record_recipes)+len(RG.typename_recipes)+len(RG.record_type_recipes),
	len(RG.record_recipes),len(RG.record_type_recipes),len(RG.typename_recipes),
	len([x for x in RG.record_recipes+RG.typename_recipes+RG.record_type_recipes if x.to_check is True]),
	len([x for x in RG.record_recipes+RG.typename_recipes+RG.record_type_recipes if x.to_fix is True]),len(RG.structs_missing),
	RG.member_count,RG.member_recipe_count,RG.not_safe_count,RG.not_used_count,RG.user_count))

	# Create maps to quickly access the generated recipes information for a given structure
	RG.compute_recipe_maps()

	# Check if we want to replace any existing recipe with its custom version
	for dep_str in RG.custom_recipe_map:
		prefix,tag = dep_str.split(":")
		R = None
		if prefix=='s':
			if tag in RG.RRMap:
				R = RG.RRMap[tag]
		else:
			if not re.match("^anonstruct_type_\d+_t$",tag):
				if tag in RG.RTRMap:
					R = RG.RTRMap[tag]
			else:
				if tag in RG.TRMap:
					R = RG.TRMap[tag]
		if R is not None:
			recipe = RG.custom_recipe_map[dep_str]
			R.recipe = recipe[0]
			R.simple = False
			R.to_check = False
			R.check_union = False
			R.to_fix = False
			R.custom_recipe = True
			R.custom_include_list = recipe[1]

	# For each additional dependency from used custom member recipes that doesn't have generated recipe we need to take it from custom recipes
	additional_custom_recipe_deps_to_include = set()
	for mStr in RG.members_with_custom_recipes:
		additional_custom_recipe_deps_to_include|=RG.resolve_additional_custom_recipe_deps(":".join(mStr.split(":")[:2]))
	for dep_str in additional_custom_recipe_deps_to_include:
		prefix,tag = dep_str.split(":")
		if prefix=='s':
			if tag not in RG.RRMap:
				if dep_str not in RG.custom_recipe_map:
					print(f"EE- Missing custom recipe for struct '{dep_str}'")
					exit(1)
				recipe = RG.custom_recipe_map[dep_str]
				RT,TPD = RG._find_record_type_by_typestring(dep_str,RG.gftdb)
				RG.record_recipes.append(RecordRecipe(RT,RT,recipe[0],None,RT.location,recipe[1],False,False,False,False,RG._has_flexible_member(RT,RG.gftdb),True))
				RG.structs_done_match.add((RT.str,RT.isunion))
		else:
			if tag not in RG.RTRMap:
				if dep_str not in RG.custom_recipe_map:
					print(f"EE- Missing custom recipe for struct type'{dep_str}'")
					exit(1)
				recipe = RG.custom_recipe_map[dep_str]
				RT,TPD = RG._find_record_type_by_typestring(dep_str,RG.gftdb)
				RG.record_type_recipes.append(RecordTypeRecipe(TPD,RT,recipe[0],None,RT.location,recipe[1],False,False,False,False,RG._has_flexible_member(RT,RG.gftdb),True))
				RG.record_typedefs.add((TPD.name,RT.str,RT.id))

	# Now do a second pass, this time insert proper size detection when generating trigger for structure types containing flexible array member
	globals_handler_stream = io.StringIO()
	globals_prehandler_stream = io.StringIO()
	globals_variables_stream = io.StringIO()
	additional_deps = list()
	for i, glob in enumerate(globals_to_dump):
		out = io.StringIO()
		gv = RG.ftdb.globals[glob[5]]
		RG.generate_flatten_trigger(gv, out, additional_deps, True)
		var_name = glob[2]
		if glob[7] not in ['', 'vmlinux'] :
			var_name = glob[7].replace('.ko', '').replace('-', '_') + ':' + var_name
		var_hash = glob[2] + '_' + hashlib.sha1(f'{var_name}_{i}'.encode()).hexdigest()[:8]

		glob_addr = "addr"
		output_template = RecipeGenerator.template_output_global_handler
		if gv.name in RG.config['per_cpu_variables']['per_cpu_direct_variables']:
			glob_addr = 'this_cpu_ptr(addr)'
		elif gv.name in RG.config['per_cpu_variables']['per_cpu_indirect_variables']:
			output_template = RecipeGenerator.template_output_per_cpu_global_handler

		# Generate
		globals_handler_stream.write(output_template.format(
			var_name, glob[6], glob[4], "\n".join(["\t\t\t"+x for x in out.getvalue().strip().split("\n")]), var_hash, glob_addr, gv.defstring, gv.hash
		))
		validate_inmem_code = ""
		if RG.ftdb.types[gv.type].classname=='builtin':
			validate_inmem_code = "\n"+prepend_non_empty_lines(RecipeGenerator.template_validate_inmem_code.format(
				var_name, var_hash, RG.ftdb.types[gv.type].size//8
			),"\t")
		globals_prehandler_stream.write(RecipeGenerator.template_output_global_pre_handler.format(
			var_name, var_hash, validate_inmem_code
		))
		globals_variables_stream.write(RecipeGenerator.template_output_global_variable.format(
			var_name, var_hash
		))

	def print_TT_member(TT,rlogf):
		if TT[0] is not None:
			rlogf.write("  %s -> %s\n"%(TT[0].name,TT[2]))
		else:
			rlogf.write("  struct %s -> %s\n"%(TT[1].str,TT[2]))

	def unique_types(TL):
		s = set()
		for TT in TL:
			if TT[0] is not None:
				s.add(TT[0].name)
			else:
				s.add("struct %s"%(TT[1].str))
		return len(s)

	rlogf = open(".recipes.log","w")
	rlogf.write( "# Blacklisted structs: %d\n"%(len(RG.structs_blacklisted)) )
	rlogf.write( "# Blacklisted struct types: %d\n"%(len(RG.struct_types_blacklisted)) )
	rlogf.write( "# Pointers in union: %d [%d unique]\n"%(len(RG.ptr_in_union),unique_types(RG.ptr_in_union)) )
	for TT in RG.ptr_in_union:
		print_TT_member(TT,rlogf)
	rlogf.write( "# Flexible array members: %d [%d unique]\n"%(len(RG.flexible_array_members),unique_types(RG.flexible_array_members)) )
	for TT in RG.flexible_array_members:
		print_TT_member(TT,rlogf)
	rlogf.write( "# Incomplete array storage members: %d [%d unique]\n"%(len(RG.incomplete_array_member_storage),unique_types(RG.incomplete_array_member_storage)) )
	for TT in RG.incomplete_array_member_storage:
		print_TT_member(TT,rlogf)
	rlogf.write( "# Pointers to user memory: %d\n"%(len(RG.user_memory_pointer_members)) )
	rlogf.write( "# Pointers to structs: %d\n"%(RG.pointer_to_struct_count) )
	rlogf.write( "# Verified pointers to structs: %d\n"%(RG.verified_pointer_to_struct_count) )
	rlogf.write( "# Complex members to write manually: %d [%d unique]\n"%(len(RG.complex_members),unique_types(RG.complex_members)) )
	for TT in RG.complex_members:
		print_TT_member(TT,rlogf)
	rlogf.write( "# Complex pointer members to write manually: %d [%d unique]\n"%(len(RG.complex_pointer_members),unique_types(RG.complex_pointer_members)) )
	for TT in RG.complex_pointer_members:
		print_TT_member(TT,rlogf)
	rlogf.write( "# Pointers to enums: %d [%d unique]\n"%(len(RG.enum_pointers),unique_types(RG.enum_pointers)) )
	for TT in RG.enum_pointers:
		print_TT_member(TT,rlogf)
	rlogf.write( "# Pointers to char (strings): %d [%d unique]\n"%(len(RG.char_pointers),unique_types(RG.char_pointers)) )
	for TT in RG.char_pointers:
		print_TT_member(TT,rlogf)
	rlogf.write("# Pointers to void: %d [%d unique] [%d resolved, %d ambiguous, %d not resolved]"%(len(RG.void_pointers),unique_types(RG.void_pointers),len(RG.void_pointers_resolved),
		len(RG.void_pointers_resolved_ambiguous),len(RG.void_pointers_not_resolved)))
	for TT in RG.void_pointers:
		print_TT_member(TT,rlogf)
	rlogf.write( "# Pointers to builtin: %d [%d unique]\n"%(len(RG.builtin_pointers),unique_types(RG.builtin_pointers)) )
	for TT in RG.builtin_pointers:
		print_TT_member(TT,rlogf)
	rlogf.close()
	print("--- Recipes generation stats are available in .recipes.log file")

	struct_forward_stream = io.StringIO()
	struct_type_forward_stream = io.StringIO()
	anonrecord_forward_stream = io.StringIO()
	recipe_declare_stream = io.StringIO()
	recipe_stream = io.StringIO()
	recipe_register_stream = io.StringIO()
	recipe_handlers_stream = io.StringIO()

	def get_struct_or_union(isunion):
		return "union" if isunion else "struct"

	struct_forward_stream.write("%s\n"%("\n".join(["%s %s;"%(get_struct_or_union(x[1]),x[0]) for x in set(RG.structs_done_match) - set(RG.structs_missing)])))
	recipe_declare_stream.write("%s\n"%("\n".join(["FUNCTION_DECLARE_FLATTEN_%s(%s);"%(get_struct_or_union(x[1]).upper(),x[0]) for x in set(RG.structs_done_match) - set(RG.structs_missing)])))

	record_typedef_s = set()
	record_typedef_declare_s = set()
	record_typedefs_list = list()
	for TPD,RT,RTid in record_typedefs:
		if TPD not in RecipeGenerator.struct_type_blacklist:
			if RT=="":
				RT = RG.get_anonstruct_typename(RG.ftdb.types[RTid])
			if TPD not in record_typedef_s:
				struct_type_forward_stream.write("struct %s;\n"%(RT))
				struct_type_forward_stream.write("typedef struct %s %s;\n"%(RT,TPD))
				record_typedef_s.add(TPD)
		if TPD not in record_typedef_declare_s:
			recipe_declare_stream.write("FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(%s);\n"%(TPD))
			record_typedefs_list.append(TPD)
			record_typedef_declare_s.add(TPD)

	anon_typedef_s = set()
	anon_typedef_declare_s = set()
	for _id,name in anon_typedefs:
		if name not in anon_typedef_s:
			anonrecord_forward_stream.write("struct %s;\n"%(name[:-2]))
			anonrecord_forward_stream.write("typedef struct %s %s;\n"%(name[:-2],name))
			anon_typedef_s.add(name)
		if name not in anon_typedef_declare_s:
			recipe_declare_stream.write("FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(%s);\n"%(name))
			anon_typedef_declare_s.add(name)


	objs = list()
	objs.append("kflat_recipes_main.o")

	drmap = {}
	recipe_stream.write("/* ---------- Record recipes [%d] ---------- */\n\n"%(len(RG.record_recipes)))
	RS = [x for x in RG.record_recipes if x.simple is True]
	RC = [x for x in RG.record_recipes if x.simple is not True]
	print("--- Record recipes (simple): %d"%(len(RS)))
	print("--- Record recipes (not simple): %d"%(len(RC)))
	for RR in RS:
		recipe_stream.write("%s\n"%(str(RR)))
		if "simple_recipes" in drmap:
			drmap["simple_recipes"].append(("%s\n"%(str(RR)),[]))
		else:
			drmap["simple_recipes"] = [("%s\n"%(str(RR)),[])]
			objs.append("simple_recipes.o")
	for RR in RC:
		recipe_stream.write("%s\n"%(str(RR)))
		vl = os.path.normpath(RR.loc.split()[0].strip("'").split(":")[0])
		dr=os.path.dirname(vl)
		drc = dr.split("/")
		if len(dr) == 0:
			drpath = vl.replace('.', '_')
		elif len(drc) == 1:
			drpath = drc[0]
		else:
			if "/".join(drc[:2])=="include/linux" and len(drc)>2:
				drpath = "__".join(drc[:3])
			else:
				drpath = "__".join(drc[:2])
		if drpath in drmap:
			drmap[drpath].append(("%s\n"%(str(RR)),RR.get_custom_include_list()))
		else:
			drmap[drpath]=[("%s\n"%(str(RR)),RR.get_custom_include_list())]
			objs.append("%s.o"%(drpath))

	recipe_stream.write("/* ---------- Record type recipes [%d] ---------- */\n\n"%(len(RG.record_type_recipes)))
	RS = [x for x in RG.record_type_recipes if x.simple is True]
	RC = [x for x in RG.record_type_recipes if x.simple is not True]
	print("--- Record type recipes (simple): %d"%(len(RS)))
	print("--- Record type recipes (not simple): %d"%(len(RC)))
	for RR in RS:
		recipe_stream.write("%s\n"%(str(RR)))
		if "simple_recipes" in drmap:
			drmap["simple_recipes"].append(("%s\n"%(str(RR)),[]))
		else:
			drmap["simple_recipes"] = [("%s\n"%(str(RR)),[])]
			objs.append("simple_recipes.o")
	for RR in RC:
		recipe_stream.write("%s\n"%(str(RR)))
		if "record_type_recipes" in drmap:
			drmap["record_type_recipes"].append(("%s\n"%(str(RR)),RR.get_custom_include_list()))
		else:
			drmap["record_type_recipes"] = [("%s\n"%(str(RR)),RR.get_custom_include_list())]
			objs.append("record_type_recipes.o")

	recipe_stream.write("/* ---------- Typename recipes [%d] ---------- */\n\n"%(len(RG.typename_recipes)))
	RS = [x for x in RG.typename_recipes if x.simple is True]
	RC = [x for x in RG.typename_recipes if x.simple is not True]
	print("--- Typename recipes (simple): %d"%(len(RS)))
	print("--- Typename recipes (not simple): %d"%(len(RC)))
	for RR in RS:
		recipe_stream.write("%s\n"%(str(RR)))
		if "simple_recipes" in drmap:
			drmap["simple_recipes"].append(("%s\n"%(str(RR)),[]))
		else:
			drmap["simple_recipes"] = [("%s\n"%(str(RR)),[])]
			objs.append("simple_recipes.o")
	for RR in RC:
		recipe_stream.write("%s\n"%(str(RR)))
		if "typename_recipes" in drmap:
			drmap["typename_recipes"].append(("%s\n"%(str(RR)),RR.get_custom_include_list()))
		else:
			drmap["typename_recipes"] = [("%s\n"%(str(RR)),RR.get_custom_include_list())]
			objs.append("typename_recipes.o")

	func_args_stream = io.StringIO()
	record_type_list = list(set(RG.structs_done_match) - set(RG.structs_missing))

	for narg,extra_info,extra_triggers in argList:
		for tp in record_type_list:
			if narg[0]==tp[0] and narg[3]=='record':
					# 0 - full type of argument
					# 1 - position of argument
					# 2 - size of argument
					# 3 - argument shift
					# 4 - real type string of the argument (after the possible shift)
					# 5 - size of the real type
					# 6 - additional information (if any)
					# 7 - additional triggers specification
				off = narg[4]
				if isinstance(off,int):
					off = "%d"%(-int(off))
				func_args_stream.write(RecipeGenerator.template_output_struct_arg_handler.format(
					narg[7],
					narg[1],
					narg[6],
					off,
					narg[5],
					narg[2],
					"\n".join(["\t\t"+x for x in extra_info.split("\n")]),
					extra_triggers
				))
		for tp in record_typedefs_list:
			if narg[0]==tp and narg[3]=='typedef':
				off = narg[4]
				if isinstance(off,int):
					off = "%d"%(-int(off))
				func_args_stream.write(RecipeGenerator.template_output_struct_type_arg_handler.format(
					narg[7],
					narg[1],
					narg[6],
					off,
					narg[5],
					narg[2],
					"\n".join(["\t\t"+x for x in extra_info.split("\n")]),
					extra_triggers
				))

	recipe_register_stream.write(f"KFLAT_RECIPE_EX(\"{args.recipe_id if args.recipe_id else args.func}\", handler_{args.func}, prehandler_globals_search),\n")
	recipe_handlers_stream.write(
		RecipeGenerator.template_output_recipe_handler.format(args.func, func_args_stream.getvalue().strip(),
			globals_handler_stream.getvalue().strip()))

	if not os.path.exists(args.output):
		os.makedirs(args.output)

	common_code = ""
	if args.common:
		with open(args.common,"r") as f:
			common_code+=f.read().strip()

	with open(os.path.join(args.output,"common.h"),"w") as f:
		f.write(RecipeGenerator.template_common_recipes%(
			struct_forward_stream.getvalue().strip(),
			struct_type_forward_stream.getvalue().strip(),
			anonrecord_forward_stream.getvalue().strip(),
			recipe_declare_stream.getvalue().strip(),
			common_code
		))

	with open(os.path.join(args.output,"CMakeLists.txt"),"w") as f:
		f.write(RecipeGenerator.template_cmake_recipes.format(
				args.module_name if args.module_name else args.func,
				" ".join(objs))
			)

	for k,rTL in drmap.items():
		with open(os.path.join(args.output,"%s.c"%(k)),"w") as f:
			custom_includes = "/* Include list from custom recipes goes here */\n" +\
				"\n".join(["#include %s"%(x) for x in list(set(list(itertools.chain.from_iterable([r[1] for r in rTL]))))])+"\n\n"
			f.write(RecipeGenerator.template_output_recipes_trigger_source%(custom_includes,"\n".join(["%s\n"%(r[0]) for r in rTL])))

	with open(os.path.join(args.output,"kflat_recipes_main.c"),"w") as f:
		f.write(RecipeGenerator.template_output_recipes_source%(
			globals_variables_stream.getvalue().strip(),
			globals_prehandler_stream.getvalue().strip(),
			recipe_handlers_stream.getvalue().strip(),
			recipe_register_stream.getvalue().strip(),
			args.func))



if __name__ == "__main__":
	main()
