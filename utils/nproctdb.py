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
# Global helpers
##################################
def indent(s, n=1):
	return "\n".join([" " * n * RecipeGenerator.TABSIZE + x for x in s.split("\n")])

def ptrNestedRefName(refname, ptrLevel, nestedPtr=False, refoffset=0):
	if ptrLevel > 0:
		return "__" + "_".join(refname.split(".")) + "_" + str(ptrLevel)
	elif not nestedPtr:
		return refname
	return "/*ATTR(%s)*/ OFFATTR(void**,%d)" % (refname, refoffset)

def ptrNestedRefNameOrRoot(refname, ptrLevel, nestedPtr=False, refoffset=0):
	if ptrLevel > 0:
		return "__" + "_".join(refname.split(".")) + "_" + str(ptrLevel)
	return "__root_ptr"

def isAnonRecordDependent(RT, depT) -> bool:
	if RT.id == depT.id:
		return True
	elif (depT.classname == "const_array" or depT.classname == "incomplete_array") and depT.refs[0] == RT.id:
		# struct { u16 index; u16 dist;} near[0];
		return True
	elif depT.classname == "pointer" and depT.refs[0] == RT.id:
		return True
	return False

def prepend_non_empty_lines(s,v):
	return "\n".join([v+x if len(x)>0 else x for x in s.split("\n")])

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
	def __init__(self,recipe,simple,to_check,check_union,to_fix,have_flexible_member):
		self.recipe = recipe
		self.simple = simple
		self.to_check = to_check
		self.check_union = check_union
		self.to_fix = to_fix
		self.have_flexible_member = have_flexible_member

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

class RecordRecipe(RecipeBase):
	# Flatten struct recipe
	def __init__(self,T,RT,recipe,include,loc,simple,to_check,check_union,to_fix,have_flexible_member):
		super(RecordRecipe, self).__init__(recipe,simple,to_check,check_union,to_fix,have_flexible_member)
		self.RT = RT
		self.include = include # Can be None
		self.loc = loc
	def __str__(self):
		s = super(RecordRecipe, self).__attrs__()
		s+=self.recipe+"\n"
		return s

class TypenameRecipe(RecipeBase):
	# Flatten struct_type recipe with auto-generated typename
	def __init__(self,typename,RT,recipe,simple,to_check,check_union,to_fix,have_flexible_member):
		super(TypenameRecipe, self).__init__(recipe,simple,to_check,check_union,to_fix,have_flexible_member)
		self.typename = typename
		self.RT = RT
	def __str__(self):
		s = super(TypenameRecipe, self).__attrs__()
		s+=self.recipe+"\n"
		return s

class RecordTypeRecipe(RecipeBase):
	# Flatten struct_type recipe
	def __init__(self,TPD,RT,recipe,includes,simple,to_check,check_union,to_fix,have_flexible_member):
		super(RecordTypeRecipe, self).__init__(recipe,simple,to_check,check_union,to_fix,have_flexible_member)
		self.TPD = TPD
		self.RT = RT
		self.includes = includes # Can be None
	def __str__(self):
		s = super(RecordTypeRecipe, self).__attrs__()
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
	template_flatten_struct_pointer_recipe = "{6}FLATTEN_{0}_ARRAY_SELF_CONTAINED({1},{2},{3},{4}); {5}"
	
	# 0 - typename
	# 1 - typesize
	# 2 - refname
	# 3 - record count
	# 4 - safe info
	# 5 - extra message
	template_flatten_struct_type_pointer_recipe = "{5}FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED({0},{1},{2},{3}); {4}"
	

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

%s
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

	# 0 - name of global variable inc. kenerl module
	# 1 - unique hash of global variable
	template_output_global_pre_handler = """
	{1} = flatten_global_address_by_name("{0}");"""

	# 0 - name of global variable inc. kernel module
	# 1 - name of global var
	# 2 - size of global var
	# 3 - flattening commands
	# 4 - unique hash of global variable
	# 5 - pointer to be flattened
	template_output_global_handler = """
	// Dump global {0}
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

	# Well, some of the struct types below are pulled in when <linux/module.h> and <linux/kflat.h> headers are included in the generated module source file
	# So either blacklisting the below or extracting required symbols from both headers above
	struct_type_blacklist = set([
		"kgid_t",
		"kuid_t",
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
		"seqcount_raw_spinlock_t"])

	## Arguments
	##  - Linux kernel version
	##  - list of object files for the interface module
	##  - Linux kernel version

	template_kbuild_recipes = """# SPDX-License-Identifier: GPL-2.0

{0}-objs := \\
{1}

ccflags-y := -Wno-undefined-internal -Wno-visibility -Wno-gcc-compat -Wno-unused-variable -I${{PWD}}/include/

obj-m = {0}.o
LINUXINCLUDE := ${{LINUXINCLUDE}}
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
			module = ''
			if len(result.mids) == 0:
				print(f"WW- Global '{name}' belongs to the unknown module (.mids is empty)")
			elif len(result.mids) > 1:
				print(f'WW- Global \'{name}\' has multiple entries in .mids section. '
					'Let the God decide which one will be used')
			else:
				module = self.ftdb.modules[result.mids[0]].split('/')[-1]

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

		def trig_info_offset_calculate(offset):
			if isinstance(offset,int):
				return str(offset)
			sizeof_pattern = re.compile("@\{[st]\:[\w]+\}")
			m = sizeof_pattern.search(offset)
			while m:
				dep, size, classname = _find_RI_for_func(m.group()[2:-1].split(":")[1])
				offset = offset[:m.span()[0]] + f'((size_t){size})' + offset[m.span()[0] + m.span()[1]-m.span()[0]:]
				m = sizeof_pattern.search(offset)
			return offset

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
					if fn in trigger_info_map:
						if trig_info_update(trig_info) and trig_info_with_update(trigger_info_map[fn]) is not None:
							print (f'EE- Duplicated update information in trigger_list[config] regarding function \'{fn}\'')
							exit(1)
						trigger_info_map[fn].append(trig_info)
					else:
						trigger_info_map[fn] = [trig_info]

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
						func_args_to_dump.append((trig_info["arg_type"].split(":")[1], int(pos), size, classname, trig_info_offset_calculate(trig_info["offset"]),True))
						deps.add(dep)
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
							func_args_to_dump[-1].append((trig_info["arg_type"].split(":")[1], int(pos), size, classname, trig_info_offset_calculate(trig_info["offset"]),True))
							deps.add(dep)

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

	def parse_structures_config(self, name: str) -> None:

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

	def walkTPD(self,TPD):
		T = self.ftdb.types[TPD.refs[0]]
		if T.classname=="typedef":
			return self.walkTPD(T)
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

	def generate_flatten_record(self,out,rT,pteEXT,pteEXTmsg,refname,refoffset,tab,element_count_expr,element_count_extra_msg,TPDrT=None,nestedPtr=False,safe=False):
		PTEoff = 0
		if pteEXT is not None and pteEXT[0]>=0:
			PTEoff=-pteEXT[1]
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
						refname,
						element_count_expr,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
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
							refname,
							element_count_expr,
							self.safeInfo(safe),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
						),tab)
				out.write(recipe+"\n")
				self.struct_deps.add((rT.id,anonstruct_type_name))
				return anonstruct_type_name
			else:
				if not nestedPtr:
					assert rT.isunion is False or PTEoff==0, "Invalid shift size != 0 for union member"
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
							refname,
							element_count_expr,
							self.safeInfo(safe),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
						),tab)
				if rT.classname=="record_forward":
					if len([x for x in self.ftdb.types if x.classname=="record" and x.str==rT.str])<=0:
						recipe = "/* MISSING STRUCT: %s */"%(rT.str)
				out.write(recipe+"\n")
				self.struct_deps.add((rT.id,rT.str))
				return "struct %s"%(rT.str)

	def get_element_count(self,mStr):

			# Normally we cannot know whether the pointer points to a single struct or an array of structs (or other types)
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
				if 'custom_element_count_map' in self.config['base_config']:
					ecM = self.config['base_config']['custom_element_count_map']
					if mStr in ecM:
						haveCount = True
						element_count_nfo = ecM[mStr]
						# We should have either 'count' or 'size_expr' attributes
						if 'count' in element_count_nfo:
							record_count_tuple[0] = element_count_nfo['count']
						if 'size_expr' in element_count_nfo:
							record_count_tuple[1] = element_count_nfo['size_expr']
						record_count_tuple[4] = 'direct'
			if not haveCount:
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
						extra_msg = "/* We've concluded that this pointer is not used in any dereference expression with offset > 0.\n\
Also it's not used at the right-hand side of any assignment expression.\n\
Finally it's not been passed as an argument to any function.\n\
We then assume that this pointer is pointing to a single element of a given type */\n"
						record_count_tuple = [1,None,None,'','derived']

			return record_count_tuple


	def get_global_element_count(self,ghash):

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
					# We should have either 'count' or 'size_expr' attributes
					if 'count' in element_count_nfo:
						record_count_tuple[0] = element_count_nfo['count']
					if 'size_expr' in element_count_nfo:
						record_count_tuple[1] = element_count_nfo['size_expr']
					record_count_tuple[4] = 'direct'
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
					extra_msg = "/* We've concluded that this global pointer is not used in any dereference expression with offset > 0.\n\
Also it's not used at the right-hand side of any assignment expression.\n\
Finally it's not been passed as an argument to any function.\n\
We then assume that this pointer is pointing to a single element of a given type */\n"
					record_count_tuple = [1,None,None,'','derived']

		return record_count_tuple

	def construct_element_count_expression(self,record_count_tuple,refname,mStr,refoffset,refsize,ptrLevel):
		if record_count_tuple[1] is not None:
			return (record_count_tuple[1],'')
		else:
			detect_element_count_expr = "\n  AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(%s,%d,%d)/%s"%(ptrNestedRefName(refname,ptrLevel),refoffset//8,refsize//8,refsize//8)
			if record_count_tuple[0] is not None:
				if record_count_tuple[4]!='default':
					return (str(record_count_tuple[0]),'')
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
				else:
					msg = "/* Couldn't conclude the number of elements pointer points to as this was a nested pointer at higher level than 0\n"
				msg += "   We will try to detect the array size at runtime. When it fails we will dump a single element pointed to by this pointer (default)\n */\n"
				return (detect_element_count_expr,msg)

	def construct_global_element_count_expression(self,record_count_tuple,gv,PTE,ptrname,ptrLevel):

		if record_count_tuple[1] is not None:
			return (record_count_tuple[1],'')
		else:
			detect_element_count_expr = "\n  FLATTEN_DETECT_OBJECT_SIZE(%s,%s)/%s"%(ptrname,PTE.size//8,PTE.size//8)
			if record_count_tuple[0] is not None:
				if record_count_tuple[4]!='default':
					return (str(record_count_tuple[0]),'')
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
					msg = "/* Couldn't conclude the number of elements pointer points to as this was a nested pointer at higher level than 0\n"
				msg += "   We will try to detect the array size at runtime. When it fails we will dump a single element pointed to by this pointer (default)\n */\n"
				return (detect_element_count_expr,msg)

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
	def generate_flatten_pointer(self,out,ptrT,pteT,pteEXT,mStr,refname,refoffset,TRT,tab,TPDptrT=None,TPDpteT=None,ptrLevel=0):
		if ptrLevel<=0:
			if pteEXT is not None and len(pteEXT)>4:
				# 'container_of' chain - assume single pointed element
				record_count_tuple = [1,None,None,'direct','']
			else:
				record_count_tuple = self.get_element_count(mStr)
		else:
			# Pointer at the higher level of nesting is ambiguous (cannot extract information from dereference expressions about its usage at this point)
			record_count_tuple = [None,None,None,'nested','']
		element_count_expr,element_count_extra_msg = self.construct_element_count_expression(record_count_tuple,refname,mStr,refoffset,pteT.size,ptrLevel)
		safe=record_count_tuple[1] is not None or record_count_tuple[0] is not None

		pteEXTmsg = ""
		if pteEXT is not None:
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
			if pteEXT[2]=='custom':
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
   points to the other type than specified in the member type specification.\n\
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
	 		pteEXT[1],
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
					ptrLevel>0,
					safe
			)+"*"
		elif pteT.classname=="incomplete_array" or pteT.classname=="const_array":
			# Pointer to array
			out.write(indent("/* TODO: implement flattening member '%s' */"%(refname),tab)+"\n")
			self.complex_members.append((TPDptrT,TRT,refname))
			self.simple = False
			return None
		elif pteT.classname=="pointer":
			# We have pointer to pointer
			PTE = self.ftdb.types[pteT.refs[0]]
			TPDE = None
			if PTE.classname=="typedef":
				TPDE = PTE
				PTE = self.walkTPD(PTE)
			ptrout = io.StringIO()
			# We assume that the nested pointer points to the type specified in its type specification (we don't have detailed member information at this level)
			ptrtp = self.generate_flatten_pointer(ptrout,pteT,PTE,None,mStr,refname,refoffset,TRT,tab,TPDpteT,TPDE,ptrLevel+1)
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
			if ptrtp is None or ptrtp=="":
				# We have multi-level pointers to function or pointers to incomplete arrays (strange things like that); ask the user to write this flattening recipe
				return None
			return ptrtp+"*"
		elif pteT.classname=="enum" or pteT.classname=="enum_forward":
			# pointer to enum
			if pteT.str=="":
				anonenum_type_name = self.get_anonenum_typename(pteT)
				self.anon_typedefs.append((pteT.id,anonenum_type_name))
				if ptrLevel<=0:
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
						ptrNestedRefName(refname,ptrLevel),
						element_count_expr,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
					),tab)+"\n")
				return anonenum_type_name+"*"
			else:
				if ptrLevel<=0:
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
						ptrNestedRefName(refname,ptrLevel),
						element_count_expr,
						self.safeInfo(safe),
						prepend_non_empty_lines("".join([u for u in [pteEXTmsg,element_count_extra_msg] if u!=""]),"  "),
					),tab)+"\n")
			self.simple = safe is True
			self.enum_pointers.append((TPDptrT,TRT,refname))
			return "enum %s*"%(pteT.str)
		elif pteT.classname=="function":
			# pointer to function
			if ptrLevel<=0:
				out.write(indent(RecipeGenerator.template_flatten_fptr_member_recipe.format(
					ptrNestedRefName(refname,ptrLevel),
					refoffset//8
				),tab)+"\n")
			else:
				out.write(indent(RecipeGenerator.template_flatten_fptr_pointer_recipe.format(
					ptrNestedRefName(refname,ptrLevel)
				),tab)+"\n")
			return "void*"
		elif pteT.classname=="builtin" and pteT.str=="void":
			# void* - we couldn't find the real type this void* points to
			#  Try to detect the object size pointed to by void* (unless we have direct information in config file)
			#  When it fails dump 1 byte of memory pointed to by it
			pvd_element_count_expr = "\n  AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(%s,%d)"%(ptrNestedRefName(refname,ptrLevel),refoffset//8)
			detect_msg = "/* We couldn't find the real type this void* member points to (also no direct information in config file exists).\n\
   We'll try to detect the object size pointed to by void* member (assuming it's on the heap).\n\
   When it fails we'll dump 1 byte of memory pointed to by it */\n"
			if record_count_tuple[4]=='direct':
				if record_count_tuple[1] is not None:
					pvd_element_count_expr = record_count_tuple[1]
					detect_msg = ""
				elif record_count_tuple[0] is not None:
					pvd_element_count_expr = str(record_count_tuple[0])
					detect_msg = ""
			if ptrLevel<=0:
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
					ptrNestedRefName(refname,ptrLevel),
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
				if pteEXT is not None and pteEXT[2]=='string':
					# char* - treat it as if it was a C string
					have_c_string = True
					if ptrLevel<=0:
						out.write(indent(RecipeGenerator.template_flatten_string_member_recipe.format(
							ptrNestedRefName(refname,ptrLevel),
							refoffset//8,
							self.safeInfo(True),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,''] if u!=""]),"  ")
						),tab)+"\n")
					else:
						out.write(indent(RecipeGenerator.template_flatten_string_pointer_recipe.format(
							ptrNestedRefName(refname,ptrLevel),
							self.safeInfo(True),
							prepend_non_empty_lines("".join([u for u in [pteEXTmsg,''] if u!=""]),"  ")
						),tab)+"\n")
					self.char_pointers.append((TPDptrT,TRT,refname))
					return "char*"
			if not have_c_string:
				# Ok, treat it as a pointer to ordinary built-in
				if ptrLevel<=0:
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
						ptrNestedRefName(refname,ptrLevel),
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

	def generate_flatten_pointer_trigger(self,out,T,TPD,gv,handle_flexible_size=False,tab=0,ptrLevel=0,arrsize=1):

		if ptrLevel==1:
			record_count_tuple = self.get_global_element_count(gv.hash)
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
			ptrtp = self.generate_flatten_pointer_trigger(ptrout,PTE,TPDE,gv,handle_flexible_size,tab+1,ptrLevel+1)
			out.write(RecipeGenerator.template_flatten_pointer_array_recipe.format(
				ptrtp,
				ptrNestedRefName(gv.name,ptrLevel+1),
				ptrNestedRefNameOrRoot(gv.name,ptrLevel),
				str(arrsize),
				indent(ptrout.getvalue().rstrip(),tab+1)
			)+"\n")
			if ptrtp is None or ptrtp=="":
				# We have multi-level pointers to function or pointers to incomplete arrays (strange things like that); ask the user to fix this flattening recipe
				return None
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
				AT = self.ftdb.types[T.refs[0]]
				ATPD = None
				if AT.classname=="typedef":
					ATPD = AT
					AT = self.walkTPD(AT)
				if AT.classname=="builtin":
					trigger = RecipeGenerator.template_flatten_type_array_pointer_recipe.format(AT.str,"__root_ptr",str(T.size//AT.size),"","")
					out.write(trigger+"\n")
					return AT.str+"*"
				elif AT.classname=="enum":
					if ATPD:
						trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(ATPD.name,AT.size//8,"__root_ptr",str(T.size//AT.size),"","")
						out.write(trigger+"\n")
						return ATPD.name+"*"
					else:
						if AT.str=="":
							anonenum_type_name = self.get_anonenum_typename(AT)
							trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format(anonenum_type_name,AT.size//8,"__root_ptr",str(T.size//AT.size),"","")
							out.write(trigger+"\n")
							return anonenum_type_name+"*"
						else:
							trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe.format("enum %s"%(AT.str),AT.size//8,"__root_ptr",str(T.size//AT.size),"","")
							out.write(trigger+"\n")
							return "enum %s*"%(AT.str)
				elif AT.classname=="pointer":
					ptrtp = self.generate_flatten_pointer_trigger(out,AT,ATPD,gv,handle_flexible_size,0,0,T.size//AT.size)
					return ptrtp
				elif AT.classname=="record":
					if ATPD:
						trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
							ATPD.name,
							AT.size//8,
							"__root_ptr",
							str(T.size/AT.size),
							""
						)
						out.write(trigger+"\n")
						return "%s*"%(ATPD.name)
					else:
						if AT.str=="":
							anonstruct_type_name = self.get_anonstruct_typename(AT)
							trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
								anonstruct_type_name,
								AT.size//8,
								"__root_ptr",
								str(T.size//AT.size),
								""
							)
							out.write(trigger+"\n")
							return "%s*"%(anonstruct_type_name)
						else:
							try:
								trigger = RecipeGenerator.template_flatten_struct_array_pointer_self_contained.format(
									"STRUCT" if AT.isunion is False else "UNION",
									AT.str,
									AT.size//8,
									"__root_ptr",
									str(T.size//AT.size),
									""
								)
							except Exception as e:
								print(json.dumps(T.json(),indent=4))
								print(json.dumps(AT.json(),indent=4))
								print(gvname)
								raise e
							out.write(trigger+"\n")
							return "%s %s*"%("struct" if AT.isunion is False else "union",AT.str)
				elif AT.classname=="const_array":
					# pointer to 2 dimensional array (TODO: think of better way to do this than making another nested level of code)
					AAT = self.ftdb.types[AT.refs[0]]
					AATPD = None
					if AAT.classname=="typedef":
						AATPD = AAT
						AAT = self.walkTPD(AAT)
					if AAT.classname=="builtin":
						trigger = RecipeGenerator.template_flatten_type_array_pointer_recipe.format(AAT.str,"__root_ptr",str(T.size//AAT.size),"","")
						out.write(trigger+"\n")
						return AT.str+"*[]"
					elif AAT.classname=="record":
						if AATPD:
							trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
								AATPD.name,
								AAT.size//8,
								"__root_ptr",
								str(T.size/AAT.size),
								""
							)
							out.write(trigger+"\n")
							return "%s*"%(AATPD.name)
						else:
							if AAT.str=="":
								anonstruct_type_name = self.get_anonstruct_typename(AAT)
								trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained.format(
									anonstruct_type_name,
									AAT.size//8,
									"__root_ptr",
									str(T.size//AAT.size),
									""
								)
								out.write(trigger+"\n")
								return "%s*"%(anonstruct_type_name)
							else:
								try:
									trigger = RecipeGenerator.template_flatten_struct_array_pointer_self_contained.format(
										"STRUCT" if AAT.isunion is False else "UNION",
										AAT.str,
										AAT.size//8,
										"__root_ptr",
										str(T.size//AAT.size),
										""
									)
								except Exception as e:
									print(json.dumps(T.json(),indent=4))
									print(json.dumps(AAT.json(),indent=4))
									print(gvname)
									raise e
								out.write(trigger+"\n")
								return "%s %s*"%("struct" if AAT.isunion is False else "union",AAT.str)
					else:
						out.write("/* TODO: implement flatten trigger for type '{0}' */\n".format(T.hash))
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
							isAnonRecordDependent(self.ftdb.types[TRT.refs[i]],self.ftdb.types[TRT.refs[i+1]]))):
						ignore_count+=1
						continue
					
					erfnLst = []
					if TRT.refnames[i]!='__!anonrecord__':
						erfnLst.append(TRT.refnames[i])
					real_refs.append( (Ts,TRT,TRTTPD,TRT.refs[i],TRT.refnames[i],TRT.usedrefs[i],TRT.memberoffsets[i-ignore_count],[],[],[],[],False) )
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
				Ts,eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,anchorMember = real_refs.pop(0)
				refname = ".".join(rfnLst+[mName])
				erfn = ".".join(erfnLst+[mName])
				moffset = sum(mOffLst+[mOff])
				mStr = "s:%s:%s"%(eT.str,erfn) if eT.str!='' else "t:%s:%s"%(eTPD.name,erfn) if eTPD is not None else "%s:%s"%(Ts,erfn)
				eStr = "s:%s"%(eT.str) if eT.str!='' else "t:%s"%(eTPD.name) if eTPD is not None else "%s:%s"%(Ts,erfn)
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
					internal_real_refs = list()
					ignore_count=0
					for i in range(len(RT.refnames)-RT.attrnum):
						if i in RT.decls and ( RT.refnames[i]!="__!anonrecord__" or (i+1<len(RT.refs) and 
								isAnonRecordDependent(self.ftdb.types[RT.refs[i]],self.ftdb.types[RT.refs[i+1]]))):
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
							internal_real_refs.append( (eTs,eRT,eRTTPD,RT.refs[i],RT.refnames[i],RT.usedrefs[i],RT.memberoffsets[i-ignore_count],
								mOffLst+[mOff],rfnLst+member_list,allowSpecLst+allowspec_list,erfnLst+emember_list,False) )
					internal_real_refs.append( (Ts,eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,True) )
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
				if 'OT_info' in self.config and 'used_members' in self.config['OT_info']:
					MU = set(self.config['OT_info']['used_members'])
					if mStr not in MU:
						proc_members.append(("/* member '%s' was not used [config] */\n"%(refname),None))
						continue
				else:
					# If we don't have the call graph usage information fallback to the entire call graph tree
					if mURef<0:
						proc_members.append(("/* member '%s' was not used [call graph] */\n"%(refname),None))
						continue

				proc_members.append((eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,refname,erfn,moffset,mStr,eStr,refaccess))

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
				if len(item)==2:
					# We have precomputed member information already
					if item[1] is not None:
						# We have data from anchor member to process
						if item[1]=='list_head':
							outv = outv[:-2]+[item[0]]
					else:
						# Simply pass the precomputed member information through
						outv.append(item[0])
					continue
				else:
					eT,eTPD,mID,mName,mURef,mOff,mOffLst,rfnLst,allowSpecLst,erfnLst,refname,erfn,moffset,mStr,eStr,refaccess = item
				
				mi+=1
				RT = self.ftdb.types[mID]
				TPD = None
				if RT.classname=="typedef":
					TPD = RT
					RT = self.walkTPD(RT)
				
				iout = io.StringIO()
				if RT.classname=="enum" or RT.classname=="builtin":
					# No need to do anything
					pass
				elif RT.classname=="pointer":
					self.member_recipe_count+=1
					PTEExt = None
					# None if PTE points to the original type
					# [0] pointee_TID (-1 if there was ambiguity in the result (PTE is not replaced))
					# [1] offset
					# [2] kind ('container_of', 'pvoid', 'string' or 'custom')
					# [3] extra
					#		for 'container_of' this is the container_of expression; in case of ambiguity this is the full container_of_map entry list
					#		for 'pvoid' this is a list of 'void*' cast expressions; in case of ambiguity this is full pvoid_map entry list
					#		for 'string' this is a list of call expressions passed to the c-string parameters (no ambiguity possible)
					#		for 'custom' this is the custom info from config file (no ambiguity)
					# [4] more extra
					#       for 'pvoid' this is 'container_of_parm_map' element information of 'container_of' calling functions in the surrounding type chain

					# Handle overlapping members
					if 'OT_info' in self.config and 'overlapping_members' in self.config['OT_info']:
						if mStr in self.config['OT_info']['overlapping_members']:
							# This member overlaps with some other member(s)
							ovnfo = self.config['OT_info']['overlapping_members'][mStr]
							if ovnfo['use'] is True:
								pass
							elif ovnfo['ignore'] is True:
								# Skip this union member
								continue
							else:
								ovLst = ovnfo['overlap_list']
								iout.write("/* member '%s' overlaps with %d other members */\n"%(refname,len(ovLst)-1))
								iout.write("/* List of overlapping members:\n")
								iout.write("\n".join([" * %s@%d[%d]"%(x[0],x[1]//8,x[2]//8) for x in ovLst])+" */\n")
								iout.write("/* Please provide custom recipe or indicate used member in config file */\n")
								self.ptr_in_union.append((TPD,TRT,refname))
								self.simple = False
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
					havePte = False
					if 'base_config' in self.config:
						if 'custom_ptr_map' in self.config['base_config']:
							custom_ptr_map = self.config['base_config']['custom_ptr_map']
							if mStr in custom_ptr_map:
								havePte = True
								# Our config file tells us exactly to which type this pointer points to
								cT = custom_ptr_map[mStr]
								PTEExt = (cT['tpid'],cT['offset'],'custom',cT['info'])
								PTE=self.ftdb.types[cT['tpid']]

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
						if self.generate_flatten_pointer(iout,RT,PTE,PTEExt,mStr,refname,moffset,TRT,0,TPD,TPDE,0) is None:
							to_fix = True
							self.complex_pointer_members.append((TPD,TRT,refname))
				# RT.classname=="pointer"
				elif RT.classname=="incomplete_array" or RT.classname=="const_array":
					self.member_recipe_count+=1
					AT = self.ftdb.types[RT.refs[0]]
					TPDAT = None
					if AT.classname=="typedef":
						TPDAT = AT
						AT = self.walkTPD(AT)
					# We have an array of type AT
					if AT.classname=="record" or AT.classname=="record_forward":
						if AT.classname=="record_forward":
							AT = [x for x in self.ftdb.types if x.classname=="record" and x.str==AT.str][0]
						try:
							sz = RT.size//AT.size
						except Exception as e:
							# Here we can have a constant array of size 0 (cause the underlying type is empty struct of size 0)
							sz = 0
						if RT.classname=="const_array" or sz==0:
							if sz>0:
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
								# const/incomplete array of size 0; if it's the last member in the record generate recipe for flexible array member
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
						else:
							iout.write("/* TODO: implement flattening member '%s' (save internal structure storage for incomplete array?) */\n"%(refname))
							self.incomplete_array_member_storage.append((TPD,TRT,refname))
							self.simple = False
					elif AT.classname=="enum" or AT.classname=="enum_forward" or AT.classname=="builtin":
						# Still no need to do anything
						pass
					else:
						# Something else
						# Keep this program simple and let the user fix it
						iout.write("/* TODO: implement flattening member '%s' (too complicated; I'm not that smart yet) */\n"%(refname))
						self.complex_members.append((TPD,TRT,refname))
						self.simple = False
				outv.append(iout.getvalue())
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
						self.record_recipes.append(RecordRecipe(T,TRT,recipe_str,include,loc,self.simple,to_check,check_union,to_fix,have_flexible_member))
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
						self.record_recipes.append(RecordRecipe(T,TRT,recipe_str,None,loc,self.simple,to_check,check_union,to_fix,have_flexible_member))
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
					self.typename_recipes.append(TypenameRecipe(typename,TRT,recipe_str,self.simple,to_check,check_union,to_fix,have_flexible_member))
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
					self.record_type_recipes.append(RecordTypeRecipe(T,TRT,recipe_str,None,self.simple,to_check,check_union,to_fix,have_flexible_member))
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
					self.record_type_recipes.append(RecordTypeRecipe(T,TRT,recipe_str,new_includes,self.simple,to_check,check_union,to_fix,have_flexible_member))
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
	parser.add_argument("-o", dest="output", action="store", help="output directory", type=str, default='recipe_gen')
	parser.add_argument("-c", dest="config", action="store", help="script layout config", type=str)
	parser.add_argument("-f", dest="func", action="store", help="", type=str)
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
		RG.parse_structures_config(args.config)

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
		if gv.name in RG.config['per_cpu_variables']:
			glob_addr = 'this_cpu_ptr(addr)'

		# Generate code
		globals_handler_stream.write(RecipeGenerator.template_output_global_handler.format(
			var_name, glob[6], glob[4], "\n".join(["\t\t\t"+x for x in out.getvalue().strip().split("\n")]), var_hash, glob_addr
		))
		globals_prehandler_stream.write(RecipeGenerator.template_output_global_pre_handler.format(
			var_name, var_hash
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
			drmap["simple_recipes"].append("%s\n"%(str(RR)))
		else:
			drmap["simple_recipes"] = ["%s\n"%(str(RR))]
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
			drmap[drpath].append("%s\n"%(str(RR)))
		else:
			drmap[drpath]=["%s\n"%(str(RR))]
			objs.append("%s.o"%(drpath))

	recipe_stream.write("/* ---------- Record type recipes [%d] ---------- */\n\n"%(len(RG.record_type_recipes)))
	RS = [x for x in RG.record_type_recipes if x.simple is True]
	RC = [x for x in RG.record_type_recipes if x.simple is not True]
	print("--- Record type recipes (simple): %d"%(len(RS)))
	print("--- Record type recipes (not simple): %d"%(len(RC)))
	for RR in RS:
		recipe_stream.write("%s\n"%(str(RR)))
		if "simple_recipes" in drmap:
			drmap["simple_recipes"].append("%s\n"%(str(RR)))
		else:
			drmap["simple_recipes"] = ["%s\n"%(str(RR))]
			objs.append("simple_recipes.o")
	for RR in RC:
		recipe_stream.write("%s\n"%(str(RR)))
		if "record_type_recipes" in drmap:
			drmap["record_type_recipes"].append("%s\n"%(str(RR)))
		else:
			drmap["record_type_recipes"] = ["%s\n"%(str(RR))]
			objs.append("record_type_recipes.o")

	recipe_stream.write("/* ---------- Typename recipes [%d] ---------- */\n\n"%(len(RG.typename_recipes)))
	RS = [x for x in RG.typename_recipes if x.simple is True]
	RC = [x for x in RG.typename_recipes if x.simple is not True]
	print("--- Typename recipes (simple): %d"%(len(RS)))
	print("--- Typename recipes (not simple): %d"%(len(RC)))
	for RR in RS:
		recipe_stream.write("%s\n"%(str(RR)))
		if "simple_recipes" in drmap:
			drmap["simple_recipes"].append("%s\n"%(str(RR)))
		else:
			drmap["simple_recipes"] = ["%s\n"%(str(RR))]
			objs.append("simple_recipes.o")
	for RR in RC:
		recipe_stream.write("%s\n"%(str(RR)))
		if "typename_recipes" in drmap:
			drmap["typename_recipes"].append("%s\n"%(str(RR)))
		else:
			drmap["typename_recipes"] = ["%s\n"%(str(RR))]
			objs.append("typename_recipes.o")

	func_args_stream = io.StringIO()
	record_type_list = list(set(RG.structs_done_match) - set(RG.structs_missing))
	arg_updated_type = False
	for arg in func_args_to_dump:
		# (0:res.id, 1:res.str if res.classname == 'record' else res.name), 2:res.size // 8, 3:res.classname, 4:offset)
		if isinstance(arg,tuple):
			arg = [arg]
		if len(arg[0])>5:
			arg_updated_type = arg[0][5]
		narg = list(arg[0][:5])+[arg[0][0],arg[0][2],"struct %s"%(arg[0][0]) if arg[0][3]=='record' else arg[0][0]] # += [5:original type string,6:original typesize,7:full original type string]
		argStr = ("____%s____%d"%(args.func,narg[1]-1))
		extra_info = ""
		if not arg_updated_type and "ptr_config" in RG.config and "container_of_parm_map" in RG.config["ptr_config"]:
			if argStr in RG.config["ptr_config"]["container_of_parm_map"]:
				e = RG.config["ptr_config"]["container_of_parm_map"][argStr][0]
				tp = RG.ftdb.types.entry_by_id(e["tpid"])
				narg[2] = tp.size//8
				narg[3] = tp.classname
				narg[4] = e["offset"]
				narg[5] = tp.str if tp.classname == 'record' else tp.name
				extra_info += "/* It was detected that the function argument no. {0} of the original type '{1}' is a part of a larger type '{2}' at offset {3}. We concluded that from the 'container_of' expression at the following location:\n  {4}".format(
					narg[1],
					narg[7],
					"struct %s"%(narg[5]) if tp.classname == 'record' else narg[5],
					narg[4],
					e["expr"]
				)
				if "call_id" in e:
					extra_info += "\n   The conclusion was made based on a call deeper down in the call graph. The first function called was '{0}' */".format(
						RG.ftdb.funcs.entry_by_id(e["call_id"]).name,
					)
				else:
					extra_info += " */"
		if len(arg)>1:
			extra_info += "\n/* It was detected that the config file specified {1} additional triggers for the function argument no. {0}. Additional triggers are reflected in the recipe */".format(
				narg[1],
				len(arg)-1
			)
		extra_triggers = ""
		if len(arg)>1:
			for extra_arg in arg[1:]:
				extra_triggers+="\n\t\t\t\tFLATTEN_STRUCT_{3}SHIFTED_SELF_CONTAINED({0}, {1}, target, {2});".format(
					extra_arg[0],
					extra_arg[2],
					extra_arg[4],
					"TYPE_" if extra_arg[3]=='typedef' else ""
				)
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

	with open(os.path.join(args.output,"Kbuild"),"w") as f:
		f.write(RecipeGenerator.template_kbuild_recipes.format(
				args.module_name if args.module_name else args.func,
				" \\\n".join(["    %s"%(x) for x in objs]))
			)

	for k,rL in drmap.items():
		with open(os.path.join(args.output,"%s.c"%(k)),"w") as f:
			f.write(RecipeGenerator.template_output_recipes_trigger_source%("\n".join(["%s\n"%(r) for r in rL])))

	with open(os.path.join(args.output,"kflat_recipes_main.c"),"w") as f:
		f.write(RecipeGenerator.template_output_recipes_source%(
			globals_variables_stream.getvalue().strip(),
			globals_prehandler_stream.getvalue().strip(),
			recipe_handlers_stream.getvalue().strip(),
			recipe_register_stream.getvalue().strip(),
			args.func))



if __name__ == "__main__":
	main()
