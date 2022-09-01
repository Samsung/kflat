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

import ndfind

try:
	import libftdb
except ImportError:
	sys.exit("Failed to import libftdb module. Make sure your PYTHONPATH"
			 " env is pointing to the output directory of CAS repo")

__authors__ = "Bartosz Zator, Pawel Wieczorek @ Samsung R&D Poland - Mobile Security Group"


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

def unionMemberInfo(inUnion):
	return "   /* VERIFY union member */" if inUnion else ""


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
	def __init__(self,recipe,simple,to_check,check_union,to_fix):
		self.recipe = recipe
		self.simple = simple
		self.to_check = to_check
		self.check_union = check_union
		self.to_fix = to_fix

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
	def __init__(self,T,RT,recipe,include,loc,simple,to_check,check_union,to_fix):
		super(RecordRecipe, self).__init__(recipe,simple,to_check,check_union,to_fix)
		self.RT = RT
		self.include = include # Can be None
		self.loc = loc
	def __str__(self):
		s = super(RecordRecipe, self).__attrs__()
		s+=self.recipe+"\n"
		return s

class TypenameRecipe(RecipeBase):
	# Flatten struct_type recipe with auto-generated typename
	def __init__(self,typename,RT,recipe,simple,to_check,check_union,to_fix):
		super(TypenameRecipe, self).__init__(recipe,simple,to_check,check_union,to_fix)
		self.typename = typename
		self.RT = RT
	def __str__(self):
		s = super(TypenameRecipe, self).__attrs__()
		s+=self.recipe+"\n"
		return s

class RecordTypeRecipe(RecipeBase):
	# Flatten struct_type recipe
	def __init__(self,TPD,RT,recipe,includes,simple,to_check,check_union,to_fix):
		super(RecordTypeRecipe, self).__init__(recipe,simple,to_check,check_union,to_fix)
		self.TPD = TPD
		self.RT = RT
		self.includes = includes # Can be None
	def __str__(self):
		s = super(RecordTypeRecipe, self).__attrs__()
		s+=self.recipe+"\n"
		return s

class RecipeGenerator(object):

	template_flatten_struct_recipe = """FUNCTION_DEFINE_FLATTEN_%s_ITER_SELF_CONTAINED(%s,%d,
%s
);"""

	template_flatten_struct_type_recipe = """FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED(%s,%d,
%s
);"""

	template_container_of_replacement_member_recipe = "  /* Original member pointee type replaced by the type detected from the following 'container_of' invocations:\n%s  */\n"
	template_flatten_struct_member_recipe = "  /* AGGREGATE_FLATTEN_STRUCT_ARRAY(%s,%s,%s); */\n%sAGGREGATE_FLATTEN_%s_ARRAY_ITER_SELF_CONTAINED_SHIFTED(%s,%d,%s,%d,%s,%d); %s%s"
	template_flatten_struct_type_member_recipe = "  /* AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(%s,%s,%s); */\n%sAGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED_SHIFTED(%s,%d,%s,%d,%s,%d); %s%s"
	template_flatten_struct_pointer_recipe = "FLATTEN_%s_ARRAY_ITER_SELF_CONTAINED(%s,%d,%s,%s); %s%s"
	template_flatten_struct_type_pointer_recipe = "FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(%s,%d,%s,%s); %s%s"
	template_flatten_type_array_member_recipe = "  /* AGGREGATE_FLATTEN_TYPE_ARRAY(%s,%s,%s); */\nAGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(%s,%s,%d,%s); %s%s"
	template_flatten_compound_type_array_member_recipe = "  /* AGGREGATE_FLATTEN_TYPE_ARRAY(%s,%s,%s); */\nAGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(%s,%d,%s,%d,%s); %s%s"
	template_flatten_type_array_pointer_recipe = "FLATTEN_TYPE_ARRAY(%s,%s,%s); %s%s"
	template_flatten_compound_type_array_pointer_recipe = "FLATTEN_COMPOUND_TYPE_ARRAY(%s,%d,%s,%s); %s%s"
	template_flatten_string_member_recipe = "  /* AGGREGATE_FLATTEN_STRING(%s); */\nAGGREGATE_FLATTEN_STRING_SELF_CONTAINED(%s,%s); %s%s"
	template_flatten_string_pointer_recipe = "FLATTEN_STRING(%s); %s%s"
	template_flatten_fptr_member_recipe = "  /* AGGREGATE_FLATTEN_FUNCTION_POINTER(%s); */\nAGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(%s,%s);%s"
	template_flatten_fptr_pointer_recipe = "FLATTEN_FUNCTION_POINTER(%s);%s"
	template_flatten_pointer_recipe = """AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(%s,%s,%s,%s);\nFOR_POINTER(%s,%s,%s,%s%s
%s
);"""
	template_flatten_pointer_array_recipe = """FOREACH_POINTER(%s,%s,%s,%s,
%s
);"""
	template_flatten_struct_array_storage_recipe = """{for (int __i=0; __i<%d; ++__i) {
    const struct %s* __p = /* ATTR(%s) */ (const struct %s*)(OFFADDR(unsigned char,%d)+%d*__i);
      /* AGGREGATE_FLATTEN_STRUCT_STORAGE(%s,__p); */
    AGGREGATE_FLATTEN_STRUCT_STORAGE_ITER(%s,__p); %s%s
}}"""
	template_flatten_union_array_storage_recipe = """{for (int __i=0; __i<%d; ++__i) {
    const union %s* __p = /* ATTR(%s) */ (const union %s*)(OFFADDR(unsigned char,%d)+%d*__i);
      /* AGGREGATE_FLATTEN_STRUCT_STORAGE(%s,__p); */
    AGGREGATE_FLATTEN_UNION_STORAGE_ITER(%s,__p); %s%s
}}"""
	template_flatten_struct_type_array_storage_recipe = """{for (int __i=0; __i<%d; ++__i) {
    const %s* __p = /* ATTR(%s) */ (const %s*)(OFFADDR(unsigned char,%d)+%d*__i);
      /* AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE(%s,__p); */
    AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ITER(%s,__p); %s%s
}}"""
	template_flatten_struct_array_iter_self_contained = \
		"FUNCTION_DEFINE_FLATTEN_%s_ARRAY_ITER_SELF_CONTAINED(%s,%d);"
	template_flatten_struct_type_array_iter_self_contained = \
		"FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(%s,%d);"
	template_flatten_declare_struct_array_iter_self_contained = \
		"FUNCTION_DECLARE_FLATTEN_%s_ARRAY_ITER_SELF_CONTAINED(%s);"
	template_flatten_declare_struct_type_array_iter_self_contained = \
		"FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(%s);"
	template_flatten_struct_array_pointer_self_contained = \
		"FLATTEN_%s_ARRAY_ITER_SELF_CONTAINED(%s,%d,%s,%s);"
	template_flatten_struct_type_array_pointer_self_contained = \
		"FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(%s,%d,%s,%s);"
	template_flatten_struct_type_array_pointer_self_contained =\
		"FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(%s,%d,%s,%s);"


	## Arguments:
	##  - list of recipe registrations
	##  - list of recipe de-registrations
	template_output_recipes_source = """/* This file is autogenerated (with possible requirement of minor modifications). Do it at your own peril! */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

#include "common.h"

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

	# 0 - type of argument
	# 1 - position of argument
	# 2 - size of argument
	template_output_arg_handler = """
	// Dump argument no. {1}
	{{
		struct {0} *target = (struct {0}*) regs->arg{1};
		
		FOR_EXTENDED_ROOT_POINTER(target, "_func_arg_{1}", {2},
			UNDER_ITER_HARNESS(
				FLATTEN_STRUCT_ITER_SELF_CONTAINED({0}, 1, target);
			);
		);
	}}
"""

	# 0 - name of global variable inc. kernel module
	# 1 - name of global var
	# 2 - size of global var
	# 3 - flattening commands
	template_output_global_handler = """
	// Dump global {0}
	do {{
		void* addr = flatten_global_address_by_name("{0}");
		if(addr == NULL) {{
			pr_err("skipping global {0} ...");
			break;
		}}

		FOR_EXTENDED_ROOT_POINTER(addr, "{1}", {2},
			UNDER_ITER_HARNESS(
				{3}
			);
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
		"guid_t"])

	## Arguments
	##  - Linux kernel version
	##  - list of object files for the interface module
	##  - Linux kernel version

	template_kbuild_recipes = """# SPDX-License-Identifier: GPL-2.0

%s_recipes-objs := \\
%s

ccflags-y := -Wno-undefined-internal -Wno-visibility -ferror-limit=0 -Wno-gcc-compat -Wno-unused-variable -I${PWD}/include/

obj-m = %s_recipes.o
LINUXINCLUDE := ${LINUXINCLUDE}
"""

	template_common_recipes = """#ifndef __COMMON_H__
#define __COMMON_H__

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
		self.ftdb.load(args.database,debug=False,quiet=True,no_map_memory=False)
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

		self.all_anon_struct_triggers = list()	# anonymous records
		self.all_struct_triggers = list()		# struct types
		self.all_struct_type_triggers = list()	# typedef'ed struct types
		self.all_anon_enum_triggers = list()	# anonymous enums
		self.all_enum_triggers = list()			# enum types
		self.all_enum_type_triggers = list()	# typedef'ed enum types
		self.all_complex_triggers = list()		# complex trigger to write by user
		self.all_ignored_triggers = list()		# Failed to generate triggers (to fix)

		self.global_base_addr = 0
		self.structs_spec = {}

	def parse_arguments(self, args: List[str], globals_file: Optional[str] = None) -> Tuple[list, list, set]:
		"""
		Accepted input format:
			func_args: <type>@<number>			- device@1, device
			globals: <global_name>:location		- poolinfo_table:char/random.c
		"""
		func_args_to_dump = []
		globals_to_dump = []
		deps = set()

		def _find_RI_for_func(type: str) -> Tuple[tuple, int]:
			results = [
				x
				for x in self.ftdb.types
				if x.classname == 'record' and x.str == type and not self.DI.isTypeConst(x)
			]
			if len(results) == 0:
				print(f"EE- Failed to locate structure type named - '{type}'")
				exit(1)
			elif len(results) > 1:
				print(f"EE- Failed to uniquely identify structure type named - '{type}'")
				exit(1)

			res = results[0]
			return (res.id, res.str), res.size // 8

		def _find_RI_for_global(name: str = '', loc_suffix: str = '') -> Tuple[tuple, str]:
			results = [x for x in self.ftdb.globals
						if x.name == name and x.file.endswith(loc_suffix)]
			if len(results) == 0:
				print(f"EE- Failed to locate structure type named - '{name}' @ {loc_suffix}")
				exit(1)
			elif len(results) > 1:
				print(f"EE- Failed to uniquely identify structure type named - '{name}' @ {loc_suffix}")
				exit(1)
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

			nonConstType = self.DI.typeToNonConst(type)
			return (nonConstType.id, nonConstType.str), module, type.size // 8, result.hash

		for arg in args:
			if '@' in arg:
				type, pos = arg.split('@')
				dep, size = _find_RI_for_func(type)
				func_args_to_dump.append((type, int(pos), size))
				deps.add(dep)
			elif ':' in arg:
				name, loc = arg.split(':')
				dep, module, size, hash = _find_RI_for_global(name, loc)
				globals_to_dump.append((dep[1], dep[0], name, module, size, hash))
				deps.add(dep)
			else:
				# default to first function argument
				dep, size = _find_RI_for_func(arg)
				func_args_to_dump.append((arg, 1, size))
				deps.add(dep)

		if globals_file:
			with open(globals_file, 'r') as f:
				for hash in f.read().split('\n'):
					if hash == '':
						continue
					name = hash.split('/')[0]
					loc = "/".join(hash.split('/')[-3:]) if '/' in hash else ''
					dep, module, size, hash = _find_RI_for_global(name, loc)
					globals_to_dump.append((dep[1], dep[0], name, module, size, hash))
					deps.add(dep)
		return func_args_to_dump, globals_to_dump, deps

	def parse_structures_config(self, name: str) -> None:

		try:
			with open(name, 'r') as f:
				config = json.load(f)
		except IOError:
			print(f"EE- Cannot open configuration file {name}")
			exit(1)

		try:
			for name, specs in config.items():
				self.structs_spec[name] = set()
				for spec in specs:
					self.structs_spec[name].add(spec['name'])
		except KeyError:
			print("EE- Invalid format of config file")
			exit(1)

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
		
		targets = [x for x in self.ftdb.funcs if x.name == name]
		if len(targets) == 0:
			print(f"EE- Function named '{name}' was not found in db.json")
			exit(1)
		elif len(targets) > 1:
			print(f"EE- Function name '{name}' is ambiguous")
			print(f"EE- TODO: Add support for selecting function in such case")
			exit(1)
		target = targets[0]
		add_subfuncs(target)

		self.call_tree = [target]
		for fid in discovered:
			self.call_tree.append(self.ftdb.funcs.entry_by_id(fid))

	def parse_deref_info(self):

		self.DI = ndfind.DerefInfo(self.ftdb, self.call_tree)

		# [(TR,MT,containerT,offset,expr),...]
		# TR : [(T,refname),...]
		#   type and member name of each member expression part in a member expression chain passed to the 'container_of' macro
		# MT : type of the member in the member expression passed to the 'container_of' macro
		# containerT : container type
		# offset : offset within containerT the 'container_of' pointer points to
		# expr : plain expression with 'container_of' usage
		self.container_of_vector = self.DI.findContainerOfEntries2(False, quiet=True)
		self.anchor_list = set()
		for TR,MT,containerT,offset,expr in self.container_of_vector:
			T = None
			for i in range(len(TR)):
				if TR[-1-i][0].str!="":
					T = TR[-1-i][0]
					break
			TT = self.DI.resolve_record_type(MT)
			if T and TT and T.str==TT.str:
				self.anchor_list.add(T.str)
		"""
		{
		  (TID,member_name): {(container_type_id,offset),...}
		  (...)
		}
		"""
		_m,_e = self.DI.containerOfUsageInfo(self.container_of_vector, quiet=True)
		self.container_of_mappings = _m
		self.container_of_exprs = _e
		
		ptrvL = self.DI.findAssignFromVoidPtrMembers()
		ptrvL += self.DI.findInitFromVoidPtrMembers(False)
		ptrvL += self.DI.findAssignToVoidPtrMembers(False)
		ptrvL += self.DI.findFunctionReturnFromVoidPtrMembers(False)
		ptrvL += self.DI.findMemberExprCasts(False)
		ptrvL += self.DI.findFunctionVoidPtrArguments(False)
		ptrvL += self.DI.findFunctionPtrVoidPtrArguments(False)
		ptrvL += self.DI.findAssignToVoidPtrThroughGetter()
		"""
		{
			(TID,member_name): { UTID, ... }
		}
		"""
		self.ptrvmap = self.DI.voidPtrMemberUsageInfo(ptrvL)
		if self.debug:
			print ("Total number of void* members: %d"%(len(self.DI.ptrToVoidMembers())))
			print ("Number of processed void* members: %d"%(len(self.ptrvmap)))
			print ("Number of at most 1 distinct assigned types to void* members: %d"%(len([x for x in self.ptrvmap.values() if len(x)<=1])))

		derefL = self.DI.findDerefsOnMemberExprs(False)
		"""
		{
			(TID,member_name): [ (off,m,E), ... ]
		}
		"""
		self.drmap = self.DI.DerefsOnMemberExprsUsageInfo(derefL)
		if self.debug:
			print ("Number of unary dereference expressions with member expression at its base: %d"%(len(self.drmap)))

		meAssignRHS = self.DI.findMemberExprsOnAssignRHS()
		meInitRHS = self.DI.findMemberExprsOnInit()
		"""
		[ (TID,member_name), ... ]
		"""
		self.meL = self.DI._mergeMemberExprOnRHS(meAssignRHS,meInitRHS)
		if self.debug:
			print ("Number of distinct member expressions on the RHS of assignment or initializer: %d"%(len(self.meL)))

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

	# Check the usage pattern for this struct member and if we can safely assume that all usage was in the single object context, i.e.
	# - in dereference expression this member is never used with offset > 0
	# - this member is not used in the right-hand side of any assignment expression
	# pteT - record or record_forward that a structure (TRT) member points to
	# TRT - parent structure (record) which have a pointer to the pteT
	# refname - name of the structure member within TRT
	def struct_member_safely_used_in_single_object_context(self,pteT,TRT,refname):
		
		if (TRT.id,refname) in self.drmap:
			u = self.drmap[(TRT.id,refname)]
			if any([x[0]!=0 for x in u]) or any([x[1]>0 for x in u]):
				# This member is used in dereference expression with offset > 0 (or any other variable used in the offset)
				return False
		if (TRT.id,refname) in self.meL:
			# This member if used on the right-hand side of some assignment expression
			return False

		return True

	# Check usage pattern for this struct member (which actually points to void*) and check whether we can safely conclude
	#  which type this void* actually points to (i.e. all the implicit and explicit casts in the code for this void* member
	#  points to a single object type)
	# TRT: The enclosing record type that contains this member (outermost non-anonymous record type)
	# refname: name of the member
	# Returns the concluded type this member points to (or None if cannot be deduced)
	def struct_void_pointer_member_pointee_type(self,TRT,refname):
		tid = TRT.id
		if (tid, refname) not in self.ptrvmap and self.DI.isTypeConst(TRT):
			nonC = self.DI.typeToNonConst(TRT)
			tid = nonC.id if nonC else None
		if (tid, refname) in self.ptrvmap:
			u = [
				self.ftdb.types[x].refs[0] 
				for x in self.ptrvmap[(tid, refname)] 
				if self.ftdb.types[x].classname == "pointer"
			]
			for i in range(len(u)):
				T = self.ftdb.types[u[i]]
				if T.classname == "typedef":
					u[i] = self.walkTPD(T).id
			us = set(u)
			if len(us) == 1:
				return self.ftdb.types[list(us)[0]]
			return False

		return None

	def generate_flatten_record(self,out,rT,pteEXT,refname,refoffset,tab,TPDrT=None,n=1,inUnion=False,nestedPtr=False,safe=False):
		PTEoff = 0
		PTEinfo = ""
		if pteEXT:
			PTEoff=-pteEXT[1]
			PTEinfo = RecipeGenerator.template_container_of_replacement_member_recipe%("\n".join(["  *  %s"%(x) for x in pteEXT[2]]))
		if TPDrT:
			if not nestedPtr:
				recipe = indent(RecipeGenerator.template_flatten_struct_type_member_recipe%(
						TPDrT.name,refname,str(n),
						PTEinfo,
						TPDrT.name,TPDrT.size//8,refname,refoffset//8,str(n),PTEoff,
						unionMemberInfo(inUnion),self.safeInfo(safe)
					),tab)
			else:
				recipe = indent(RecipeGenerator.template_flatten_struct_type_pointer_recipe%(
						TPDrT.name,TPDrT.size//8,refname,str(n),
						unionMemberInfo(inUnion),self.safeInfo(safe)
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
					recipe = indent(RecipeGenerator.template_flatten_struct_type_member_recipe%(
							anonstruct_type_name,refname,str(n),
							PTEinfo,
							anonstruct_type_name,rT.size//8,refname,refoffset//8,str(n),PTEoff,
							unionMemberInfo(inUnion),self.safeInfo(safe)
						),tab)
				else:
					recipe = indent(RecipeGenerator.template_flatten_struct_type_pointer_recipe%(
							anonstruct_type_name,rT.size//8,refname,str(n),
							unionMemberInfo(inUnion),self.safeInfo(safe)
						),tab)
				out.write(recipe+"\n")
				self.struct_deps.add((rT.id,anonstruct_type_name))
				return anonstruct_type_name
			else:
				if not nestedPtr:
					recipe = indent(RecipeGenerator.template_flatten_struct_member_recipe%(
							rT.str,refname,str(n),
							PTEinfo,
							"STRUCT" if rT.isunion is False else "UNION",rT.str,rT.size//8,refname,refoffset//8,str(n),PTEoff,
							unionMemberInfo(inUnion),self.safeInfo(safe)
						),tab)
				else:
					recipe = indent(RecipeGenerator.template_flatten_struct_pointer_recipe%(
							"STRUCT" if rT.isunion is False else "UNION",rT.str,rT.size//8,refname,str(n),
							unionMemberInfo(inUnion),self.safeInfo(safe)
						),tab)
				if rT.classname=="record_forward":
					if len([x for x in self.ftdb.types if x.classname=="record" and x.str==rT.str])<=0:
						recipe = "/* MISSING STRUCT: %s */"%(rT.str)
				out.write(recipe+"\n")
				self.struct_deps.add((rT.id,rT.str))
				return "struct %s"%(rT.str)

	# out - 
	# ptrT - type of the structure member being processed
	# pteT - type the structure member pointer points to
	# poffset - offset in the pteT recors type
	# refname - member pointer refname
	# refoffset - member pointer offset
	# TRT - the underlying record type for which the harness is generated
	# tab - 
	# TPDptrT - if structure member is a typedef this is the original typedef type otherwise it's None
	# TPDpteT - if structure member pointer points to a typedef this is the original typedef type otherwise it's None
	# ptrLevel -
	# inUnion -
	def generate_flatten_pointer(self,out,ptrT,pteT,pteEXT,refname,refoffset,TRT,tab,TPDptrT=None,TPDpteT=None,ptrLevel=0,inUnion=False):
		if pteT.classname=="attributed" and "__attribute__((noderef))" in pteT.attrcore:
			out.write(indent("/* Member '%s' points to __user memory */"%(refname),tab)+"\n")
			self.user_memory_pointer_members.append((TPDptrT,TRT,refname))
			self.user_count+=1
			return None
		if pteT.classname=="record" or pteT.classname=="record_forward":
			# pointer to struct
			self.pointer_to_struct_count+=1
			safe = self.struct_member_safely_used_in_single_object_context(pteT,TRT,refname)
			if not safe:
				## TODO:
				# We cannot know whether the pointer points to a single struct or an array of structs
				# Check the usage pattern for this struct member and if we can safely assume that all usage was in the single object context, i.e.
				# - in dereference expression this member is never used with offset > 0
				# - this member is not used in the right-hand side of any assignment expression
				# - (any other?)
				# do not mark this structure as a needed for verification (the default recipe dumps a single object from the pointer)
				self.simple = False
			else:
				self.verified_pointer_to_struct_count+=1
			return self.generate_flatten_record(out,pteT,pteEXT,ptrNestedRefName(refname,ptrLevel),refoffset,tab,TPDpteT,1,inUnion,ptrLevel>0,safe)+"*"
		elif pteT.classname=="incomplete_array" or pteT.classname=="const_array":
			out.write(indent("/* TODO: implement flattening member '%s' */"%(refname),tab)+"\n")
			self.complex_members.append((TPDptrT,TRT,refname))
			self.simple = False
			return None
		elif pteT.classname=="pointer":
			PTE = self.ftdb.types[pteT.refs[0]]
			TPDE = None
			if PTE.classname=="typedef":
				TPDE = PTE
				PTE = self.walkTPD(PTE)
			ptrout = io.StringIO()
			ptrtp = self.generate_flatten_pointer(ptrout,pteT,PTE,pteEXT,refname,refoffset,TRT,tab,TPDpteT,TPDE,ptrLevel+1)
			out.write(RecipeGenerator.template_flatten_pointer_recipe%(
				ptrtp,refname,refoffset//8,1,
				ptrtp,ptrNestedRefName(refname,ptrLevel+1),ptrNestedRefName(refname,ptrLevel,True,refoffset//8),
				unionMemberInfo(inUnion),self.safeInfo(False),indent(ptrout.getvalue().rstrip(),tab+1))+"\n")
			self.simple = False
			if ptrtp is None or ptrtp=="":
				# We have multi-level pointers to function or pointers to incomplete arrays (strange things like that); ask the user to fix this flattening recipe
				return None
			return ptrtp+"*"
		elif pteT.classname=="enum" or pteT.classname=="enum_forward":
			# pointer to enum
			if pteT.str=="":
				anonenum_type_name = self.get_anonenum_typename(pteT)
				self.anon_typedefs.append((pteT.id,anonenum_type_name))
				if ptrLevel<=0:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_member_recipe%(
						anonenum_type_name,ptrNestedRefName(refname,ptrLevel),str(1),
						anonenum_type_name,pteT.size//8,ptrNestedRefName(refname,ptrLevel),refoffset//8,str(1),
						unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
				else:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(
						anonenum_type_name,pteT.size//8,ptrNestedRefName(refname,ptrLevel),str(1),
						unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
				return anonenum_type_name+"*"
			else:
				if ptrLevel<=0:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_member_recipe%(
						"enum %s"%(pteT.str),ptrNestedRefName(refname,ptrLevel),str(1),
						"enum %s"%(pteT.str),pteT.size//8,ptrNestedRefName(refname,ptrLevel),refoffset//8,str(1),
						unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
				else:
					out.write(indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(
						"enum %s"%(pteT.str),pteT.size//8,ptrNestedRefName(refname,ptrLevel),str(1),
						unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
			self.simple = False
			self.enum_pointers.append((TPDptrT,TRT,refname))
			return "enum %s*"%(pteT.str)
		elif pteT.classname=="builtin" and pteT.str=="char":
			# char* - treat it as if it was a C string
			if ptrLevel<=0:
				out.write(indent(RecipeGenerator.template_flatten_string_member_recipe%(
					ptrNestedRefName(refname,ptrLevel),
					ptrNestedRefName(refname,ptrLevel),refoffset//8,
					unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
			else:
				out.write(indent(RecipeGenerator.template_flatten_string_pointer_recipe%(
					ptrNestedRefName(refname,ptrLevel),
					unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
			self.simple = False
			self.char_pointers.append((TPDptrT,TRT,refname))
			return "char*"
		elif pteT.classname=="builtin" and pteT.str=="void":
			# void*
			if ptrLevel<=0:
				out.write(indent(RecipeGenerator.template_flatten_type_array_member_recipe%(
					"unsigned char",ptrNestedRefName(refname,ptrLevel),str(1),
					"unsigned char",ptrNestedRefName(refname,ptrLevel),refoffset//8,str(1),
					unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
			else:
				out.write(indent(RecipeGenerator.template_flatten_type_array_pointer_recipe%(
					"unsigned char",ptrNestedRefName(refname,ptrLevel),str(1),
					unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
			self.simple = False
			self.void_pointers.append((TPDptrT,TRT,refname))
			return "unsigned char*"
		elif pteT.classname=="function":
			# pointer to function
			if ptrLevel<=0:
				out.write(indent(RecipeGenerator.template_flatten_fptr_member_recipe%(
					ptrNestedRefName(refname,ptrLevel),
					ptrNestedRefName(refname,ptrLevel),refoffset//8,
					unionMemberInfo(inUnion)),tab)+"\n")
			else:
				out.write(indent(RecipeGenerator.template_flatten_fptr_pointer_recipe%(
					ptrNestedRefName(refname,ptrLevel),
					unionMemberInfo(inUnion)),tab)+"\n")
			return "void*"
		else:
			# pointer to builtin
			if ptrLevel<=0:
				out.write(indent(RecipeGenerator.template_flatten_type_array_member_recipe%(
					pteT.str,ptrNestedRefName(refname,ptrLevel),str(1),
					pteT.str,ptrNestedRefName(refname,ptrLevel),refoffset//8,str(1),
					unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
			else:
				out.write(indent(RecipeGenerator.template_flatten_type_array_pointer_recipe%(
					pteT.str,ptrNestedRefName(refname,ptrLevel),str(1),
					unionMemberInfo(inUnion),self.safeInfo(False)),tab)+"\n")
			self.simple = False
			self.builtin_pointers.append((TPDptrT,TRT,refname))
			return pteT.str+"*"

	def generate_flatten_record_trigger(self,out,T,TPD,refname,tab=0):
		if TPD:
			recipe = indent(RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained%(TPD.name,TPD.size//8,refname,str(1)),tab)
			out.write(recipe+"\n")
			return TPD.name
		if T.str=="":
			anonstruct_type_name = self.get_anonstruct_typename(T)
			recipe = indent(RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained%(anonstruct_type_name,T.size//8,refname,str(1)),tab)
			out.write(recipe+"\n")
			return anonstruct_type_name
			
		if T.classname=="record_forward":
			RL = [x for x in self.ftdb.types if x.classname=="record" and x.str == T.str]
			if len(RL) <= 0:
				return None
			T = RL[0]
		recipe = indent(RecipeGenerator.template_flatten_struct_array_pointer_self_contained%(
			"STRUCT" if T.isunion is False else "UNION",T.str,T.size//8,refname,str(1)),tab)
		out.write(recipe+"\n")
		return "struct %s"%(T.str)

	def generate_flatten_pointer_trigger(self,out,T,TPD,gvname,tab=0,ptrLevel=0,arrsize=1):
		TPD = None
		if T.classname=="typedef":
			TPD = T
			T = self.walkTPD(T)
		
		if T.classname=="attributed" and "__attribute__((noderef))" in T.attrcore:
			# Global variable points to user memory
			return None
		if T.classname=="record" or T.classname=="record_forward":
			# pointer to struct
			rtp = self.generate_flatten_record_trigger(out,T,TPD,ptrNestedRefName(gvname,ptrLevel))
			if rtp is None:
				return None
			else:
				return rtp+"*"
		
		elif T.classname=="incomplete_array" or T.classname=="const_array":
			out.write(indent("/* TODO: implement flattening trigger for global member '%s' */"%(gvname),tab)+"\n")
			return None
		elif T.classname=="pointer":
			PTE = self.ftdb.types[T.refs[0]]
			TPDE = None
			if PTE.classname=="typedef":
				TPDE = PTE
				PTE = self.walkTPD(PTE)
			ptrout = io.StringIO()
			ptrtp = self.generate_flatten_pointer_trigger(ptrout,PTE,TPDE,gvname,tab+1,ptrLevel+1)
			out.write(RecipeGenerator.template_flatten_pointer_array_recipe%(ptrtp,ptrNestedRefName(gvname,ptrLevel+1),ptrNestedRefNameOrRoot(gvname,ptrLevel),str(arrsize)
				,indent(ptrout.getvalue().rstrip(),tab+1))+"\n")
			if ptrtp is None or ptrtp=="":
				# We have multi-level pointers to function or pointers to incomplete arrays (strange things like that); ask the user to fix this flattening recipe
				return None
			return ptrtp+"*"
		elif T.classname=="enum" or T.classname=="enum_forward":
			# pointer to enum
			if TPD:
				recipe = indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(
					TPD.name,T.size//8,ptrNestedRefName(gvname,ptrLevel),str(1),"",""),tab)+"\n"
				out.write(recipe+"\n")
				return TPD.name+"*"
			else:
				if T.str=="":
					anonenum_type_name = self.get_anonenum_typename(T)
					recipe = indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(
						anonenum_type_name,T.size//8,ptrNestedRefName(gvname,ptrLevel),str(1),"",""),tab)+"\n"
					out.write(recipe+"\n")
					return anonenum_type_name+"*"
				else:
					recipe = indent(RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(
						"enum %s"%(T.str),T.size//8,ptrNestedRefName(gvname,ptrLevel),str(1),"",""),tab)+"\n"
					out.write(recipe+"\n")
					return "enum %s*"%(T.str)
		elif T.classname=="builtin" and T.str=="char":
			# char* - treat it as if it was a C string
			recipe = indent(RecipeGenerator.template_flatten_string_pointer_recipe%(
				ptrNestedRefName(gvname,ptrLevel),"",""),tab)+"\n"
			out.write(recipe+"\n")
			return "char*"
		elif T.classname=="builtin" and T.str=="void":
			# void*
			recipe = indent(RecipeGenerator.template_flatten_type_array_pointer_recipe%(
				"unsigned char",ptrNestedRefName(gvname,ptrLevel),str(1),"",""),tab)+"\n"
			out.write(recipe+"\n")
			return "unsigned char*"
		elif T.classname=="function":
			# pointer to function
			recipe = indent(RecipeGenerator.template_flatten_fptr_pointer_recipe%(ptrNestedRefName(gvname,ptrLevel),""),tab)+"\n"
			out.write(recipe+"\n")
			return "void*"
		else:
			# pointer to builtin
			recipe = indent(RecipeGenerator.template_flatten_type_array_pointer_recipe%(
				T.str,ptrNestedRefName(gvname,ptrLevel),str(1),"",""),tab)+"\n"
			out.write(recipe+"\n")
			return T.str+"*"


	def generate_flatten_trigger(self,TID,gvname,out):
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
				trigger = RecipeGenerator.template_flatten_type_array_pointer_recipe%(T.str,"__root_ptr",str(1),"","")
				out.write(trigger+"\n")
				return T.str+"*"
			elif T.classname=="enum":
				if TPD:
					trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(TPD.name,T.size//8,"__root_ptr",str(1),"","")
					out.write(trigger+"\n")
					return TPD.name+"*"
				else:
					if T.str=="":
						anonenum_type_name = self.get_anonenum_typename(T)
						trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(anonenum_type_name,T.size//8,"__root_ptr",str(1),"","")
						out.write(trigger+"\n")
						return anonenum_type_name+"*"
					else:
						trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%("enum %s"%(T.str),T.size//8,"__root_ptr",str(1),"","")
						out.write(trigger+"\n")
						return "enum %s*"%(T.str)
			elif T.classname=="pointer":
				ptrtp = self.generate_flatten_pointer_trigger(out,T,TPD,gvname)
				if not ptrtp:
					self.complex_triggers.append((T,TPD))
				return ptrtp
			elif T.classname=="record":
				if TPD:
					trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained%(
									TPD.name,T.size//8,"__root_ptr",str(1))
					out.write(trigger+"\n")
					return "%s*"%(TPD.name)
				else:
					if T.str=="":
						anonstruct_type_name = self.get_anonstruct_typename(T)
						trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained%(
									anonstruct_type_name,T.size//8,"__root_ptr",str(1))
						out.write(trigger+"\n")
						return "%s*"%(anonstruct_type_name)
					else:
						trigger = RecipeGenerator.template_flatten_struct_array_pointer_self_contained%(
									"STRUCT" if T.isunion is False else "UNION",T.str,T.size//8,"__root_ptr",str(1))
						out.write(trigger+"\n")
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
					trigger = RecipeGenerator.template_flatten_type_array_pointer_recipe%(AT.str,"__root_ptr",str(T.size//AT.size),"","")
					out.write(trigger+"\n")
					return AT.str+"*"
				elif AT.classname=="enum":
					if ATPD:
						trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(ATPD.name,AT.size//8,"__root_ptr",str(T.size//AT.size),"","")
						out.write(trigger+"\n")
						return ATPD.name+"*"
					else:
						if AT.str=="":
							anonenum_type_name = self.get_anonenum_typename(AT)
							trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%(anonenum_type_name,AT.size//8,"__root_ptr",str(T.size//AT.size),"","")
							out.write(trigger+"\n")
							return anonenum_type_name+"*"
						else:
							trigger = RecipeGenerator.template_flatten_compound_type_array_pointer_recipe%("enum %s"%(AT.str),AT.size//8,"__root_ptr",str(T.size//AT.size),"","")
							out.write(trigger+"\n")
							return "enum %s*"%(AT.str)
				elif AT.classname=="pointer":
					ptrtp = self.generate_flatten_pointer_trigger(out,AT,ATPD,gvname,0,0,T.size//AT.size)
					return ptrtp
				elif AT.classname=="record":
					if ATPD:
						trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained%(
							ATPD.name,AT.size//8,"__root_ptr",str(T.size/AT.size))
						out.write(trigger+"\n")
						return "%s*"%(ATPD.name)
					else:
						if AT.str=="":
							anonstruct_type_name = self.get_anonstruct_typename(AT)
							trigger = RecipeGenerator.template_flatten_struct_type_array_pointer_self_contained%(
								anonstruct_type_name,AT.size//8,"__root_ptr",str(T.size//AT.size))
							out.write(trigger+"\n")
							return "%s*"%(anonstruct_type_name)
						else:
							try:
								trigger = RecipeGenerator.template_flatten_struct_array_pointer_self_contained%(
									"STRUCT" if AT.isunion is False else "UNION",AT.str,AT.size//8,"__root_ptr",str(T.size//AT.size))
							except Exception as e:
								print(json.dumps(T.json(),indent=4))
								print(json.dumps(AT.json(),indent=4))
								print(gvname)
								raise e
							out.write(trigger+"\n")
							return "%s %s*"%("struct" if AT.isunion is False else "union",AT.str)
				else:
					print(f"EE- Unsupported harness - {AT.id}; {AT.classname}")
					return None
			else:
				# What else could be here?
				return None

	"""
	TID - id of the struct type (might be record forward) or typedef which eventually collapses to struct type
	"""
	def generate_flatten_harness(self,TID,typename=None):
		T = self.ftdb.types[TID]
		if self.debug:
			print("g_harness %d[%s:%s]"%(TID,T.classname,T.str))
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
				if self.DI.isTypeConst(type):
					type = self.DI.typeToNonConst(type)
				results.add((type.id, type.str))
			return results
		# TRT - the underlying record type for which the harness is generated
		do_recipes = True
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
		if do_recipes:
			try:
				real_refs = list()
				ignore_count=0
				useSpecs = TRT.str in self.structs_spec
				specs = self.structs_spec.get(TRT.str, set())
				# As of the current quirk of dbjson when there's anonymous record inside a structure followed by a name we will have two entries in "refs"
				#  but only single entry in "memberoffsets"
				#	struct X { ... };       // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
				#	struct X { ... } w;     // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
				#	struct { ... };         // "__!anonrecord__" as a normal member (present in decls)
				#	struct { ... } w;       // ignore "__!anonrecord__" from refs/refnames/usedrefs (present in decls)
				#  summary: ignore all "__!recorddecl__" from decls and "__!anonrecord__" if there's the same refs entry that follows
				for i in range(len(TRT.refnames)-ndfind.getAttrNum(TRT)):
					if i in TRT.decls and ( TRT.refnames[i]!="__!anonrecord__" or (i+1<len(TRT.refs) and 
							ndfind.isAnonRecordDependent(self.ftdb.types[TRT.refs[i]],self.ftdb.types[TRT.refs[i+1]]))):
						ignore_count+=1
						continue
					
					# Check whether fields in this structure haven't been restricted by config file
					if useSpecs and TRT.refnames[i] not in specs:
						continue

					real_refs.append( (TRT,TRT.refs[i],TRT.refnames[i],TRT.usedrefs[i],TRT.memberoffsets[i-ignore_count],[],[],[TRT.refnames[i]],TRT.isunion) )
			except Exception as e:
				print(json.dumps(TRT.json(),indent=4))
				raise e
			## Structure member can be another structure hence its members leak into the parent structure type while flattening
			to_fix = False
			have_member_ptr = False
			if self.debug:
				print ("# struct %s"%(TRT.str))
			while len(real_refs)>0:
				# eT: enclosing record type for a given member in the chain (encloses anonymous and anchor members)
				# u: member_type
				# v: member_name
				# ur: member_usedref
				# moff: member_offset
				# (...)
				# erefname_list : refname list of members chain in the enclosing type
				eT,u,v,ur,moff,memberoffset_list,refname_prefix_list,erefname_list,inUnion = real_refs.pop(0)
				self.member_count+=1
				# RT - type of the structure member being processed
				# TPD - if structure member is a typedef this is the original typedef type otherwise it's None
				RT = self.ftdb.types[u]
				if self.debug:
					print("%d: %s [%s]"%(u,v,RT.classname))
				TPD = None
				if RT.classname=="typedef":
					TPD = RT
					RT = self.walkTPD(RT)
				if RT.classname=="enum" or RT.classname=="builtin":
					# No need to do anything
					pass
				elif RT.classname=="pointer":
					self.member_recipe_count+=1
					PTEExt = None
					if ur<=0:
						out.write("/* member '%s' not used */\n"%(".".join(refname_prefix_list+[v])))
						self.not_used_count+=1
					elif inUnion is True:
						out.write("/* member '%s' is a pointer inside union; TODO: please write the proper recipe */\n"%(".".join(refname_prefix_list+[v])))
						self.ptr_in_union.append((TPD,TRT,".".join(refname_prefix_list+[v])))
						self.simple = False
					else:
						# PTE - type the structure member pointer points to
						# TPDE - if structure member pointer points to a typedef this is the original typedef type otherwise it's None
						PTE = self.ftdb.types[RT.refs[0]]
						erefname = ".".join(erefname_list)
						TT,TTPD = self.resolve_record_type(PTE.id)
						if TT:
							TTstr = "struct %s"%(TT.str)
						else:
							TTstr = PTE.hash
						if self.debug:
							print ("struct %s (%s)[%s]"%(self.ftdb.types[eT.id].str,erefname,TTstr))
						# Check if the member pointer was used in the 'container_of' and can be concluded where it really points to
						if (eT.id,erefname) in self.container_of_mappings:
							self.generic_pointer_members.append((eT.id,erefname))
							gpts = self.container_of_mappings[(eT.id,erefname)]
							if len(gpts)==1:
								self.generic_pointer_members_resolved_unambiguously.append((eT.id,erefname))
								containerT,offset = [(self.ftdb.types[x[0]],x[1]) for x in gpts][0]
								# We found a member that all use of 'container_of' on it points to single other member
								PTEExt = (PTE,offset,self.container_of_exprs[(eT.id,erefname)])
								PTE = containerT
							else:
								self.generic_pointer_members_unresolved.append((eT.id,erefname))
						elif PTE.classname=="builtin" and PTE.str=="void":
							# If the member type is void* check whether we can safely conclude which type it is actually pointing to
							RPTE = self.struct_void_pointer_member_pointee_type(eT,v)
							if RPTE is False:
								self.void_pointers_resolved_ambiguous.append((TRT,PTE,v))
							elif RPTE is not None:
								PTE = RPTE
								self.void_pointers_resolved.append((TRT,PTE,v))
							else:
								self.void_pointers_not_resolved.append((TRT,PTE,v))
								# Most of the cases here is a void* member is passed to function which also takes void* as parameter
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
							out.write("/* member '%s' points to a structure of size 0 */\n"%(".".join(refname_prefix_list+[v])))
						elif PTE.size<=0 and PTE.classname=="record_forward" and resolved_record_forward is not None and resolved_record_forward.size<=0:
							out.write("/* member '%s' points to a structure of size 0 (through record forward) */\n"%(".".join(refname_prefix_list+[v])))
						else:
							have_member_ptr = True
							if resolved_record_forward:
								PTE = resolved_record_forward
							if self.generate_flatten_pointer(out,RT,PTE,PTEExt,".".join(refname_prefix_list+[v]),sum(memberoffset_list+[moff]),TRT,0,TPD,TPDE,0,inUnion) is None:
								to_fix = True
								self.complex_pointer_members.append((TPD,TRT,".".join(refname_prefix_list+[v])))
				elif RT.classname=="record":
					internal_real_refs = list()
					ignore_count=0
					for i in range(len(RT.refnames)-ndfind.getAttrNum(RT)):
						if i in RT.decls and ( RT.refnames[i]!="__!anonrecord__" or (i+1<len(RT.refs) and 
								ndfind.isAnonRecordDependent(self.ftdb.types[RT.refs[i]],self.ftdb.types[RT.refs[i+1]]))):
							ignore_count+=1
							continue
						else:
							member_list = list()
							if v!="__!anonrecord__":
								if RT.str not in self.anchor_list:
									erefname_list.clear()
									eRT = RT
								else:
									eRT = eT
								member_list.append(RT.refnames[i])
							if v=="__!anonrecord__":
								eRT = eT
							internal_real_refs.append( (eRT,RT.refs[i],RT.refnames[i],RT.usedrefs[i],RT.memberoffsets[i-ignore_count],
								memberoffset_list+[moff],refname_prefix_list+member_list,erefname_list+member_list,RT.isunion if inUnion is False else inUnion) )
					real_refs = internal_real_refs+real_refs
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
						if RT.classname=="const_array":
							if sz>0:
								if not TPDAT:
									if AT.str=="":
										anonstruct_type_name = self.get_anonstruct_typename(AT)
										self.anon_typedefs.append((AT.id,anonstruct_type_name))
										out.write(indent(RecipeGenerator.template_flatten_struct_type_array_storage_recipe%(
											sz,anonstruct_type_name,".".join(refname_prefix_list+[v]),anonstruct_type_name,sum(memberoffset_list+[moff])//8,AT.size//8,anonstruct_type_name,
											anonstruct_type_name,unionMemberInfo(inUnion),self.safeInfo(False)),0)+"\n")
										self.struct_deps.add((AT.id,anonstruct_type_name))
									else:
										if AT.isunion is False:
											out.write(indent(RecipeGenerator.template_flatten_struct_array_storage_recipe%(
												sz,AT.str,".".join(refname_prefix_list+[v]),AT.str,sum(memberoffset_list+[moff])//8,AT.size//8,AT.str,
												AT.str,unionMemberInfo(inUnion),self.safeInfo(False)),0)+"\n")
										else:
											out.write(indent(RecipeGenerator.template_flatten_union_array_storage_recipe%(
												sz,AT.str,".".join(refname_prefix_list+[v]),AT.str,sum(memberoffset_list+[moff])//8,AT.size//8,AT.str,
												AT.str,unionMemberInfo(inUnion),self.safeInfo(False)),0)+"\n")
										self.struct_deps.add((AT.id,AT.str))
								else:
									out.write(indent(RecipeGenerator.template_flatten_struct_type_array_storage_recipe%(
										sz,TPDAT.name,".".join(refname_prefix_list+[v]),TPDAT.name,sum(memberoffset_list+[moff])//8,AT.size//8,TPDAT.name,
										TPDAT.name,unionMemberInfo(inUnion),self.safeInfo(False)),0)+"\n")
									self.struct_deps.add((TPDAT.id,TPDAT.name))
									self.record_typedefs.add((TPDAT.name,AT.str,AT.id))
							else:
								out.write("/* TODO: member '%s' is a const array of size 0; consider flexible array member */\n"%(".".join(refname_prefix_list+[v])))
								self.flexible_array_members.append((TPD,TRT,".".join(refname_prefix_list+[v])))
								self.simple = False
						else:
							out.write("/* TODO: implement flattening member '%s' (save internal structure storage for incomplete array) */\n"%(".".join(refname_prefix_list+[v])))
							self.incomplete_array_member_storage.append((TPD,TRT,".".join(refname_prefix_list+[v])))
							self.simple = False
					elif AT.classname=="enum" or AT.classname=="enum_forward" or AT.classname=="builtin":
						# Still no need to do anything
						pass
					else:
						# Keep this program simple and let the user fix it
						out.write("/* TODO: implement flattening member '%s' */\n"%(".".join(refname_prefix_list+[v])))
						self.complex_members.append((TPD,TRT,".".join(refname_prefix_list+[v])))
						self.simple = False
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
						recipe_str = RecipeGenerator.template_flatten_struct_recipe%("STRUCT" if TRT.isunion is False else "UNION",T.str,TRT.size//8,indent(out.getvalue().strip()))
						self.record_recipes.append(RecordRecipe(T,TRT,recipe_str,include,loc,self.simple,to_check,check_union,to_fix))
					else:
						self.unresolved_struct_includes.append((T.str,loc))
						recipe_str = RecipeGenerator.template_flatten_struct_recipe%("STRUCT" if TRT.isunion is False else "UNION",T.str,TRT.size//8,indent(out.getvalue().strip()))
						self.record_recipes.append(RecordRecipe(T,TRT,recipe_str,None,loc,self.simple,to_check,check_union,to_fix))
					self.structs_done.append((T.str,loc))
					self.structs_done_match.add((T.str,T.isunion))
					self.gen_count+=1
			else:
				if typename not in self.struct_types_done_match:
					recipe_str = RecipeGenerator.template_flatten_struct_type_recipe%(typename,TRT.size//8,indent(out.getvalue().strip()))
					self.typename_recipes.append(TypenameRecipe(typename,TRT,recipe_str,self.simple,to_check,check_union,to_fix))
					self.struct_types_done.append((typename,""))
					self.struct_types_done_match.add(typename)
					self.gen_count+=1
		else:
			if T.name not in self.struct_types_done_match:
				new_includes = RG.resolve_struct_type_location(T.id,self.includes)
				if not new_includes:
					recipe_str = RecipeGenerator.template_flatten_struct_type_recipe%(T.name,TRT.size//8,indent(out.getvalue().strip()))
					self.record_type_recipes.append(RecordTypeRecipe(T,TRT,recipe_str,None,self.simple,to_check,check_union,to_fix))
					self.unresolved_struct_type_includes.append((T.name,T.location,T.id))
				else:
					recipe_str = RecipeGenerator.template_flatten_struct_type_recipe%(T.name,TRT.size//8,indent(out.getvalue().strip()))
					self.record_type_recipes.append(RecordTypeRecipe(T,TRT,recipe_str,new_includes,self.simple,to_check,check_union,to_fix))
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


####################################
# Program Entry point
####################################
def main():
	global RG

	parser = argparse.ArgumentParser(description="Automated generator of KFLAT flattening recipes")
	parser.add_argument("struct", help="struct type for which kflat recipes will be generated", nargs='*')
	parser.add_argument("func", help="function name for which dereference information should be processed")

	parser.add_argument("-v", dest="verbose", action="store_true", help="print verbose (debug) information")
	parser.add_argument("-d", dest="database", action="store", help="function/type JSON database file", type=str, default='db.json')
	parser.add_argument("-o", dest="output", action="store", help="output directory", type=str, default='recipe_gen')
	parser.add_argument("-c", dest="config", action="store", help="script layout config", type=str)

	parser.add_argument("--globals-list", action="store", type=str, help="File with list of hashes of globals that should be flattened")
	parser.add_argument("--ignore-structs", action="store", help="Do not generate descriptions for the following structs (delimited by ',')")

	# TODO: Consider removing include dirs
	parser.add_argument("--include-dirs", action="store", help="Include directory for header files with structure definitions (delimited by ':')")
	args = parser.parse_args()

	RG = RecipeGenerator(args)
	if args.config:
		RG.parse_structures_config(args.config)

	RG.collect_call_tree(args.func)
	print(f"--- Collected {len(RG.call_tree)} functions accessible from given entry point")
	print("--- Generating deref info")
	RG.parse_deref_info()

	deps_done = set([])
	anon_typedefs = list()
	record_typedefs = set()

	# Parse input structures lists
	func_args_to_dump, globals_to_dump, deps = RG.parse_arguments(args.struct, args.globals_list)
	if len(deps) == 0:
		print(f'EE- No structures to generate recipes for')
		exit(1)
	
	print(f"--- Generating recipes for {len(deps)} structures ...")
	os.system("setterm -cursor off")
	gen_count = 0

	while len(deps-deps_done)>0:
		T,typename = deps.pop()
		if (T,typename) not in deps_done:
			deps |= RG.generate_flatten_harness(T,typename)
			gen_count+=1
			sys.stdout.write("\r%d"%(gen_count))
			sys.stdout.flush()
			deps_done.add((T,typename))
			anon_typedefs+=RG.anon_typedefs
			record_typedefs|=RG.record_typedefs
	sys.stdout.write("\r")
	os.system("setterm -cursor on")

	print ("--- Generated flattening descriptions for %d types:\n"
			"\t[%d record recipes, %d record type recipes, %d typename recipes]\n"
			"\t(%d to check) (%d to fix) (%d missing)\n"
			"\t(%d members, %d members with recipes, %d members not safe,\n\t%d members not used, %d members points to user memory)"%(
	len(RG.record_recipes)+len(RG.typename_recipes)+len(RG.record_type_recipes),
	len(RG.record_recipes),len(RG.record_type_recipes),len(RG.typename_recipes),
	len([x for x in RG.record_recipes+RG.typename_recipes+RG.record_type_recipes if x.to_check is True]),
	len([x for x in RG.record_recipes+RG.typename_recipes+RG.record_type_recipes if x.to_fix is True]),len(RG.structs_missing),
	RG.member_count,RG.member_recipe_count,RG.not_safe_count,RG.not_used_count,RG.user_count))

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
	func_args_stream = io.StringIO()
	globals_stream = io.StringIO()

	def get_struct_or_union(isunion):
		return "union" if isunion else "struct"

	struct_forward_stream.write("%s\n"%("\n".join(["%s %s;"%(get_struct_or_union(x[1]),x[0]) for x in set(RG.structs_done_match) - set(RG.structs_missing)])))
	recipe_declare_stream.write("%s\n"%("\n".join(["FUNCTION_DECLARE_FLATTEN_%s_ITER(%s);"%(get_struct_or_union(x[1]).upper(),x[0]) for x in set(RG.structs_done_match) - set(RG.structs_missing)])))

	record_typedef_s = set()
	record_typedef_declare_s = set()
	for TPD,RT,RTid in record_typedefs:
		if TPD not in RecipeGenerator.struct_type_blacklist:
			if RT=="":
				RT = RG.get_anonstruct_typename(RG.ftdb.types[RTid])
			if TPD not in record_typedef_s:
				struct_type_forward_stream.write("struct %s;\n"%(RT))
				struct_type_forward_stream.write("typedef struct %s %s;\n"%(RT,TPD))
				record_typedef_s.add(TPD)
		if TPD not in record_typedef_declare_s:
			recipe_declare_stream.write("FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ITER(%s);\n"%(TPD))
			record_typedef_declare_s.add(TPD)

	anon_typedef_s = set()
	anon_typedef_declare_s = set()
	for _id,name in anon_typedefs:
		if name not in anon_typedef_s:
			anonrecord_forward_stream.write("struct %s;\n"%(name[:-2]))
			anonrecord_forward_stream.write("typedef struct %s %s;\n"%(name[:-2],name))
			anon_typedef_s.add(name)
		if name not in anon_typedef_declare_s:
			recipe_declare_stream.write("FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ITER(%s);\n"%(name))
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

	for x in set(RG.structs_done_match) - set(RG.structs_missing):
		name = x[0]
		
		# TODO: Match by ID rather than by name
		arg = [x for x in func_args_to_dump if x[0] == name]
		if len(arg) > 0:
			arg = arg[0]
			func_args_stream.write(RecipeGenerator.template_output_arg_handler.format(arg[0], arg[1], arg[2]))

	for glob in globals_to_dump:
		out = io.StringIO()
		RG.generate_flatten_trigger(glob[1], glob[2], out)
		var_name = glob[2]
		if glob[3] not in ['', 'vmlinux'] :
			var_name += ':' + glob[3]
		globals_stream.write(RecipeGenerator.template_output_global_handler.format(
			var_name, glob[5], glob[4], out.getvalue().strip()))
	
	recipe_register_stream.write(f"\tKFLAT_RECIPE(\"{args.func}\", handler_{args.func}),\n")
	recipe_handlers_stream.write(
		RecipeGenerator.template_output_recipe_handler.format(args.func, func_args_stream.getvalue().strip(), 
			globals_stream.getvalue().strip()))

	if not os.path.exists(args.output):
		os.makedirs(args.output)

	with open(os.path.join(args.output,"common.h"),"w") as f:
		f.write(RecipeGenerator.template_common_recipes%(
			struct_forward_stream.getvalue().strip(),
			struct_type_forward_stream.getvalue().strip(),
			anonrecord_forward_stream.getvalue().strip(),
			recipe_declare_stream.getvalue().strip(),
		))

	with open(os.path.join(args.output,"Kbuild"),"w") as f:
		f.write(RecipeGenerator.template_kbuild_recipes%(f"{args.func}"," \\\n".join(["    %s"%(x) for x in objs]), f"{args.func}"))

	for k,rL in drmap.items():
		with open(os.path.join(args.output,"%s.c"%(k)),"w") as f:
			f.write(RecipeGenerator.template_output_recipes_trigger_source%("\n".join(["%s\n"%(r) for r in rL])))

	with open(os.path.join(args.output,"kflat_recipes_main.c"),"w") as f:
		f.write(RecipeGenerator.template_output_recipes_source%(
			recipe_handlers_stream.getvalue().strip(),
			recipe_register_stream.getvalue().strip(),
			args.func))



if __name__ == "__main__":
	main()
