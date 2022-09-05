""" Dereference information extractor

	This module extracts dereference information from provided db.json
	database. With such information, user can trace the true types hidden
	behind `void*` dereference, etc.
"""

import json

from typing import Any, Set

__author__ = "Bartosz Zator @ Samsung R&D Poland - Mobile Security Group"


##################################
# Global helpers
##################################
def getAttrNum(RT) -> int:
	if RT.has_attrs():
		return RT.attrnum
	return 0

def isAnonRecordDependent(RT, depT) -> bool:
	if RT.id == depT.id:
		return True
	elif (depT.classname == "const_array" or depT.classname == "incomplete_array") and depT.refs[0] == RT.id:
		# struct { u16 index; u16 dist;} near[0];
		return True
	elif depT.classname == "pointer" and depT.refs[0] == RT.id:
		return True
	return False


##################################
# Derefs engine
##################################
class DerefException(Exception):
	def __init__(self, message: str, data: dict = None):
		self.message = message
		self.data = data
	
	def __str__(self) -> str:
		reason = f'DerefException: {self.message}\n'
		if self.data:
			reason += f'Exception occurred with the following data:\n'
			reason += json.dumps(self.data, indent=4) + '\n'
		return reason


class DerefInfo:
	
	def __init__(self, ftdb: object, funcs_list: list):
		self.ftdb = ftdb
		self.funcs_list = funcs_list
		self.report_errors = False
		self.ptr_to_void_type = self.lookForPtrToVoid()
		if len(self.ptr_to_void_type) == 0:
			raise DerefException("Couldn't find void* type in JSON database. Giving up")

	def lookForPtrToVoid(self) -> Set[int]:

		def checkPtr(typeID) -> bool:
			subT = self.ftdb.types[typeID]
			if subT.classname == "pointer":
				return checkPtr(subT.refs[0])
			elif subT.classname == "builtin" and subT.str == "void":
				return True
			else:
				return False
		pv = set()
		for x in self.ftdb.types:
			if checkPtr(x.id):
				pv.add(x.id)
		return pv

	def ptrToVoidMembers(self) -> Set[tuple]:

		ptrvms = set()
		for T in self.ftdb.types:
			if T.classname == "record":
				for n,mTID in enumerate(T.refs):
					if mTID in self.ptr_to_void_type:
						ptrvms.add((T.id, T.refnames[n], n))
		return ptrvms

	def typeMembers(self, TIDs: list) -> Set[tuple]:

		structms = set()
		for T in self.ftdb.types:
			if T.classname=="record":
				for n,mTID in enumerate(T.refs):
					if mTID in TIDs:
						structms.add((T.id,T.refnames[n],n,T.usedrefs[n]))
		return structms


	def walkTPD(self, TPD: object) -> object:
		T = self.ftdb.types[TPD.refs[0]]
		if T.classname == "typedef":
			return self.walkTPD(T)
		else:
			return T

	def isTypeConst(self, T) -> bool:
		return 'c' in T.qualifiers

	def typeToNonConst(self, T) -> object:
		if T is None or not self.isTypeConst(T):
			return T
		
		for type in self.ftdb.types:
			if type.str != T.str:
				continue

			if type.classname=="record_forward":
				continue

			if type.hash.split(':')[3] != T.hash.split(':')[3]:
				continue

			if self.isTypeConst(type):
				continue

			return type
		return T


	# Looks for structure members of a specified record types given by 'mTList' and saves the member information in the 'mTMap'
	# T - the structure type for which the members are reviewed
	# mTList - the list of structure tags to look for (e.g. 'list_read', 'rb_node' etc.) in the T members
	# mTMap - the member information map:
	# {
	#   'struct_TAG' : [
	#       (T type id, [member_type_ids], [member_names], [member_offsets])
	#       (...)
	#	 ]
	# }
	# where:
	#  member_type_ids - list of members types for the chain of embedded structures in T that lead to the member of type from 'mTList'
	#  member_names - list of member names for the chain of embedded structures in T that lead to the member of type from 'mTList'
	#  member_offsets - list of member offsets for the chain of embedded structures in T that lead to the member of type from 'mTList'
	def _lookForMemberTypes(self,T,mTList,mTMap):

		if T.classname!="record":
			return None

		try:
			real_refs = list()
			ignore_count=0
			# As of the current quirk of dbjson when there's anonymous record inside a structure followed by a name we will have two entries in "refs"
			#  but only single entry in "memberoffsets"
			#	struct X { ... };       // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
			#	struct X { ... } w;     // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
			#	struct { ... };         // "__!anonrecord__" as a normal member (present in decls)
			#	struct { ... } w;       // ignore "__!anonrecord__" from refs/refnames/usedrefs (present in decls)
			#  summary: ignore all "__!recorddecl__" from decls and "__!anonrecord__" if there's the same refs entry that follows
			for i in range(len(T.refnames)-getAttrNum(T)):
				if i in T.decls and ( T.refnames[i]!="__!anonrecord__" or (i+1<len(T.refs) and 
						isAnonRecordDependent(self.ftdb.types[T.refs[i]],self.ftdb.types[T.refs[i+1]]))):
					ignore_count+=1
					continue
				else:
					real_refs.append( (T.refs[i],T.refnames[i],T.usedrefs[i],T.memberoffsets[i-ignore_count],[],[],[],T.isunion) )
		except Exception as e:
			raise DerefException(str(e), T.json)
		
		## Structure member can be another structure hence its members leak into the parent structure type
		while len(real_refs)>0:
			_mid,_mname,_mused,_moff,memberoffset_list,refname_prefix_list,membertype_list,inUnion = real_refs.pop(0)
			RT = self.ftdb.types[_mid]
			TPD = None
			if RT.classname=="typedef":
				TPD = RT
				RT = self.walkTPD(RT)
			if RT.classname=="record":
				internal_real_refs = list()
				ignore_count=0
				for i in range(len(RT.refnames)-getAttrNum(RT)):
					if i in RT.decls and ( RT.refnames[i]!="__!anonrecord__" or (i+1<len(RT.refs) and 
							isAnonRecordDependent(self.ftdb.types[RT.refs[i]],self.ftdb.types[RT.refs[i+1]]))):
						ignore_count+=1
						continue
					else:
						member_list = list()
						if _mname!="__!anonrecord__":
							member_list.append(_mname)
						internal_real_refs.append( (RT.refs[i],RT.refnames[i],RT.usedrefs[i],RT.memberoffsets[i-ignore_count],
							memberoffset_list+[_moff],refname_prefix_list+member_list,membertype_list+[_mid],RT.isunion if inUnion is False else inUnion) )
				real_refs = internal_real_refs+real_refs
				if RT.str in mTList:
					if RT.str not in mTMap:
						mTMap[RT.str] = [(T.id,membertype_list+[_mid],refname_prefix_list+[_mname],[sz//8 for sz in memberoffset_list+[_moff]])]
					else:
						mTMap[RT.str].append((T.id,membertype_list+[_mid],refname_prefix_list+[_mname],[sz//8 for sz in memberoffset_list+[_moff]]))

	def resolve_record_type(self,T):

		if T.classname=="record":
			return T
		elif T.classname=="pointer" or T.classname=="typedef" or T.classname=="attributed":
			return self.resolve_record_type(self.ftdb.types[T.refs[0]])

	# Walk through pointer or array types and extract underlying record type
	# Returns (RT,TPD) pair where:
	#  RT: underlying record type
	#  TPD: if the underlying record type was a typedef this is the original typedef type
	# In case record type cannot be resolved returns (None,None) pair
	def resolve_record_type_or_not(self,TID,TPD=None):

		T = self.ftdb.types[TID]
		if T.classname=="record" or T.classname=="record_forward":
			return T,TPD
		elif T.classname=="pointer" or T.classname=="const_array" or T.classname=="incomplete_array":
			TPD = None
			return self.resolve_record_type_or_not(T.refs[0],TPD)
		elif T.classname=="typedef":
			if TPD is None:
				TPD = T
			return self.resolve_record_type_or_not(T.refs[0],TPD)
		elif T.classname=="attributed":
			return self.resolve_record_type_or_not(T.refs[0],TPD)
		else:
			return None,None

	def resolve_record_typedef(self,T,TPD=None):

		if T.classname=="record":
			if TPD:
				return TPD
			else:
				return None
		elif T.classname=="typedef":
			if TPD:
				return self.resolve_record_typedef(self.ftdb.types[T.refs[0]],TPD)
			else:
				return self.resolve_record_typedef(self.ftdb.types[T.refs[0]],T)
		elif T.classname=="pointer" or T.classname=="attributed":
			TPD=None
			return self.resolve_record_typedef(self.ftdb.types[T.refs[0]],TPD)

	def _resolve_common_pointer_member_name(self,initME):

		refname = ""
		refid = None
		for i,TID in reversed(list(enumerate(initME.type))):
			T = self.ftdb.types[TID]
			if initME.access[i]>0:
				T = self.resolve_record_type(T)
			if T.classname=="typedef":
				T = self.resolve_record_type(T)
			MT = self.ftdb.types[T.refs[initME.member[i]]]
			if MT.classname=="pointer":
				RT = self.resolve_record_type(T)
				refname += RT.refnames[initME.member[i]]
				refid = initME.member[i]
			break
		return refname,refid

	def _resolve_generic_pointer_member_name(self,initME):

		refname = ""
		refid = None
		for i,TID in reversed(list(enumerate(initME.type))):
			T = self.ftdb.types[TID]
			if initME.access[i]>0:
				T = self.resolve_record_type(T)
			if T.classname=="typedef":
				T = self.resolve_record_type(T)
			MT = self.ftdb.types[T.refs[initME.member[i]]]
			if MT.classname=="pointer":
				continue
			RT = self.resolve_record_type(T)
			refname += RT.refnames[initME.member[i]]
			refid = initME.member[i]
			break
		return refname,refid

	def type_abbrev(self,TID):
		T = self.ftdb.types[TID]
		if T.classname=="record":
			return "struct %s"%(T.str)
		elif T.classname=="pointer":
			return self.type_abbrev(T.refs[0])+"*"
		elif T.classname=="typedef":
			return "%s"%(T.name)
		elif T.classname=="attributed":
			return self.type_abbrev(T.refs[0])
		else:
			return T.str

	def lookForSingleMemberExpr(self,rhsOffsetrefs):
		
		mref = None
		for oref in rhsOffsetrefs:
			if oref.kindname=="member":
				if mref is not None:
					return None
				else:
					mref = oref
		return mref

	def lookForSingleVariableExpression(self,rhsOffsetrefs):
		
		vref = None
		for oref in rhsOffsetrefs:
			if oref.kindname=="global" or oref.kindname=="local" or oref.kindname=="parm" or \
					oref.kindname=="unary" or oref.kindname=="array" or oref.kindname=="member":
				if vref is not None:
					return None
				else:
					vref = oref
		return vref

	def nonVoidPtrTypes(self,Ts):

		return [x for x in Ts if x not in self.ptr_to_void_type]

	
	"""
	Returns the mapping that maps specific 'record:member' combination of void* type
	to the list of unique types (other than void*) this member is assigned to/from
	{
		(TID,member_name): { UTID, ... }
	}
	"""
	def voidPtrMemberUsageInfo(self,ptrvL,debug=False):

		ptrvmap = {}
		for TT in ptrvL: # (T,TPD,R,MT,LT,E,(n...))
			if TT[1] is not None:
				T = self.resolve_record_type(TT[1])
			else:
				T = TT[0]
			_k = (T.id,TT[2])
			if TT[4].id not in self.ptr_to_void_type:
				if _k in ptrvmap:
					ptrvmap[_k].add(TT[4].id)
				else:
					ptrvmap[_k] = set([TT[4].id])
		return ptrvmap


	"""
	Returns the mapping that maps specific 'record:member' combination used as a base
	for unary dereference expression to the list of information about the offset and
	number of other variables used at this dereference expression
	{
		(TID,member_name): [ (off,m,E), ... ]
	}
	"""
	def DerefsOnMemberExprsUsageInfo(self,derefL,debug=False):

		drmap = {}
		for TT in derefL: # (F,T,TPD,R,MT,off,m,E,(n...))
			if TT[2] is not None:
				T = self.resolve_record_type(TT[2])
			else:
				T = TT[1]
			_k = (T.id,TT[3])
			if _k in drmap:
				drmap[_k].append((TT[5],TT[6],TT[7]))
			else:
				drmap[_k] = [(TT[5],TT[6],TT[7])]
		return drmap


	"""
	Let's say we have the following structure definition:
	struct <TAG> {
		(...)
		struct list_head <MEMBER>;
		(...)
	}
	And then we use container_of macro as follows at some point in the code:
	container_of((&<var>.<MEMBER>)->next, struct <OTHER_TAG>, <OTHER_MEMBER>)
	where the 'var' variable is of type 'struct <TAG>'
	What that actually means is that the 'list_head' <MEMBER> value is a part of some other
	structure storage (and most likely facilitates the linked list of that structure type)
	This function finds all usages of 'container_of' macro where the pointer passed
	as its first argument was a member of some structure and then it tries to extract the
	underlying data passed to that macro. It returns the following mapping:
	{
		<struct MEMBER_TAG> : /* e.g. 'struct list_head' */
			{
				(TID,member_name): [(container_type_id,[(expr,loc),...]),...]
				(...)
			}
		(...)
	}
	The keys are the different structure tags of the members passed as its first argument
	The value is the map that maps the definition specifics of the structure member passed
	as first argument to the 'container_of' with all the different structure types its
	casted to (together with the involved expressions and locations in code).
	"""
	"""
	To have it handy for discussion below is the definition of the 'container_of' macro in latest kernels:
	----------------------------------------
	#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })
	----------------------------------------
	"""

	def findContainerOfEntries(self,report_errors=False,quiet=False,debug=False,tpdebug=False,logdebug=False):

		__read_once_size_entry = None
		if self.ftdb.funcs.contains_name("__read_once_size"):
			__read_once_size_entry = self.ftdb.funcs.entry_by_name("__read_once_size")[0]

		# List of locations for purported usage of 'container_of' macro
		# We get it by first extracting locations of all '__mptr' local variables (which are used inside 'container_of' macro)
		#  and then matching offsetof dereference expressions with these locations (which happens later inside 'container_of' macro)
		# (D,dloc,f), where
		#   D - offsetof dereference expression used at the location with '__mptr' variable
		#   dloc - location of '__mptr' variable
		#   f - original function where offsetof was taken
		container_of_derefs = list()
		for f in self.funcs_list:
			mptr_locs = set([":".join(x.location.split()[0].split(":")[:-1]) for x in f.locals if x.parm is False and x.name=="__mptr"])
			for D in f.derefs:
				if D.kindname=="offsetof":
					# We will look for offsetof expressions with computed offset value
					dloc = ":".join(D.expr.split("]:")[0][1:].split()[0].split(":")[:-1])
					if dloc in mptr_locs:
						container_of_derefs.append((D,dloc,f))
		if not quiet:
			print ("Number of 'container_of' invocations: %d"%(len(container_of_derefs)))
		initExpr_count = 0
		initExpr_member_count = 0
		container_of_ptr_types = {}
		generic_pointer_type_list = set(["list_head","device","crypto_alg","device_driver","rb_node"])
		generic_pointer_type_stats = {}
		for u in generic_pointer_type_list:
			uTs = [T.id for T in self.ftdb.types if T.classname=="record" and T.str==u]
			generic_pointer_type_stats[u] = self.typeMembers(uTs)

		fi=0
		for D,dloc,f in container_of_derefs:
			# How to extract the pointer passed to 'container_of' macro?
			# First we get the location of the 'container_of' invocation ('dloc')
			#  and lookup the index of the corresponding '__mptr' variable (with the same location)
			# Then search for the 'init' dereference expression that initializes the '__mptr' variable detected above
			# Finally extract the initializer member expression when applicable
			# There's a quirk however when the member expression passed to 'container_of' goes through 'READ_ONCE' macro
			# To account for that whenever we detect that the initializer member expression type is anonymous union we do the following steps:
			#  look into 'calls' array from this function where 'container_of' is used and locate invocations of '__read_once_size' function
			#  find first '__read_once_size' invocation location (from 'call_info' array) that matches the 'dloc' location
			#  get the dereference expression for its first argument ('parm' kind) and extract the member expression it points to (this is what we're looking for)
			# To complicate things further we might have several 'container_of' invocations in one higher-level macro (and hence the same location)
			#  This can be resolved by combining '__mptr' variable with offsetof dereference expression that both share the same 'csid'
			mptr_map = { (":".join(x.location.split()[0].split(":")[:-1]),x.csid):i for i,x in enumerate(f.locals) if x.parm is False and x.name=="__mptr" }
			if (dloc,D.csid) in mptr_map:
				i = mptr_map[(dloc,D.csid)]
				for x in f.derefs:
					if x.kindname=="init":
						iloc = ":".join(x.expr.split("]:")[0][1:].split()[0].split(":")[:-1])
						if iloc==dloc and x.csid==D.csid and x.offsetrefs[0].kindname=="local" and x.offsetrefs[0].id==i:
							initExpr = x.offsetrefs[1]
							initExpr_count+=1
							if initExpr.kindname=="member":
								# init expression for the 'container_of' pointer variable (void *__mptr = <EXPR>) is a mamber expression
								initME = f.derefs[initExpr.id]
								initExpr_member_count+=1
								T = None # Enclosing non-anonymous structure type for the given member expression
								RT = self.resolve_record_type(self.ftdb.types[initME.type[-1]])
								mRT = self.ftdb.types[RT.refs[initME.member[-1]]]
								mName,mId = self._resolve_generic_pointer_member_name(initME)
								refname_list = list()
								for i in range(len(D.type)):
									tpT = self.ftdb.types[D.type[i]]
									refname_list.append(tpT.refnames[D.member[i]])
								ME = initME
								pRT = None
								if mId is None:
									# 'container_of' used on a common member pointer
									mName,mId = self._resolve_common_pointer_member_name(initME)
									pRT = RT
								if __read_once_size_entry is not None and RT.isunion is True and RT.str=="":
									# Check if the initializer member expression goes through 'READ_ONCE' macro
									rdonceList = [ii for ii,cid in enumerate(f.calls) if cid==__read_once_size_entry.id]
									rdonceCI = [f.call_info[ii] for ii in rdonceList if ":".join(f.call_info[ii].loc.split()[0].split(":")[:-1])==dloc]
									if len(rdonceCI)>0:
										parmD = f.derefs[rdonceCI[0].args[0]]
										if len(parmD.offsetrefs)>0 and parmD.offsetrefs[0].kindname=="member":
											ME = f.derefs[parmD.offsetrefs[0].id]
											RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
									mRT = self.ftdb.types[RT.refs[ME.member[-1]]]
									mName,mId = self._resolve_generic_pointer_member_name(ME)
								if ME.offsetrefs[0].kindname=="array":
									# We might access generic pointer through array access in member expression as in:
									# struct A {
									#	struct {
									#		struct list_head lhArr[4];
									#   }
									#   struct X* pX;
									# } obA, obAarr[4];
									# (1) container_of( obA.lhArr[2].next, ...)
									# (2) container_of( obAarr[2].pX, ...)
									arrD = f.derefs[ME.offsetrefs[0].id]
									if arrD.offsetrefs[0].kindname=="member":
										# Here goes for (1)
										ME = f.derefs[arrD.offsetrefs[0].id]
										mName,mId = self._resolve_generic_pointer_member_name(ME)
										if RT.str in generic_pointer_type_list:
											pRT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
									else:
										# Here goes for (2)
										if arrD.offsetrefs[0].kindname=="parm" or arrD.offsetrefs[0].kindname=="local":
											if RT.str in generic_pointer_type_list:
												vT = f.locals[arrD.offsetrefs[0].id].type
												pRT = self.resolve_record_type(self.ftdb.types[vT])
										elif arrD.offsetrefs[0].kindname=="global":
											if RT.str in generic_pointer_type_list:
												vT = self.ftdb.globals[arrD.offsetrefs[0].id].type
												pRT = self.resolve_record_type(self.ftdb.types[vT])
								else:
									# Plain array of struct with generic pointer
									# struct A {
									#	struct list_head lh;
									# } obA;
									# container_of( obA.lh.next, ...)
									if RT.str in generic_pointer_type_list and len(ME.type)>1:
										# Walk the nested members backwards to find first non-anonymous record
										for u in reversed(range(len(ME.type)-1)):
											pRT = self.resolve_record_type(self.ftdb.types[ME.type[u]])
											if pRT.str!="": break
									elif RT.str not in generic_pointer_type_list and mRT.str in generic_pointer_type_list:
										# 'container_of' used on an address of generic pointer directly
										# struct A {
										#	struct list_head lh;
										# } obA;
										# container_of( &obA.lh, ...)
										#pass
										pRT = RT

								# container_of vector
								# RT - record type of the member expression passed as a ptr to 'container_of' macro
								# pRT - record type of the member expression (containing the generic pointer (e.g. 'list_head')) passed as a ptr to 'container_of' macro
								#   When pRT is None it means generic pointer is not used inside member expression or RT is not a generic pointer
								# mi - index of the member in the member expression passed as a ptr to 'container_of' macro
								# ME - 
								# mRT - type of the member in the member expression passed as a ptr to 'container_of' macro
								# mName - 
								# mId - 
								# D - original 'offsetof' dereference entry from this 'container_of' macro
								# dloc - location of the 'container_of' macro invocation
								# f - original function where offsetof was taken
								_RT,_TPD = self.resolve_record_type_or_not(mRT.id)
								if _RT and _RT.str!="":
									_k = "struct %s"%(_RT.str)
								else:
									_k = mRT.hash
								_v = (RT,pRT,f.derefs[initExpr.id],ME,mRT,mName,mId,D,dloc,f,fi)
								if _k in container_of_ptr_types:
									container_of_ptr_types[_k].append(_v)
								else:
									container_of_ptr_types[_k] = [_v]
								fi+=1
		if not quiet:
			print ("Number of extracted 'container_of' pointer expressions: %d"%(initExpr_count))
			print ("Number of extracted 'container_of' member pointer expressions: %d"%(initExpr_member_count))
			print ("Number of distinct 'container_of' pointer types: %d"%(len(container_of_ptr_types)))
		container_of_ptr_types_items = sorted(container_of_ptr_types.items(),key = lambda x: len(x[1]),reverse=True)
		generic_pointer_type_mappings = {}


		def container_of_entry_string(RT,pRT,ME,PT,mRT,mName,dloc,ref,D):
			s = ""
			if pRT is not None:
				s+="container_of parent ptr: %s\n"%(pRT.hash)
			else:
				s+="container_of ptr: %s\n"%(RT.hash)
			s+="member type: %s\n"%(mRT.hash)
			s+="member name: %s\n"%(mName)
			s+="expr: %s\n"%(ME.expr.split("]:")[1].strip())
			s+="loc: %s\n"%(dloc)
			s+="container type: %s ---> [%s:%d]\n\n"%(PT.hash,ref,D.offset)
			return s

		# {
		#   <member_type> : (
		#						[ parent_record_type_mapping_log ]				# Generic pointer is mapped into structure type that differs from the structure it is embedded in
		#						[ parent_record_type_mapping_failed_log ]
		#						[ parent_record_type_mapping_unhandled_log ]
		#						[ parent_record_type_mapping_match_log ]		# Generic pointer cast in 'container_of' matches the structure it is embedded in
		#						[ parent_record_type_mapping_generic_log ]		# Generic pointer is itself an container structure (it is used as a variable, not a structure member)
		#					)
		# }
		container_of_logs = {}
		for _k,_v in container_of_ptr_types_items:
			if _k not in container_of_logs:
				container_of_logs[_k] = ([],[],[],[],[])
			for RT,pRT,initME,ME,mRT,mName,mId,D,dloc,f,fi in _v:
				# PT - the type of container structure used in the 'container_of' cast
				PT = self.ftdb.types[D.type[0]]
				container_type = PT.str
				locT = (initME.expr.split("]:")[1].strip(),dloc)
				refname_list = list()
				for i in range(len(D.type)):
					tpT = self.ftdb.types[D.type[i]]
					refname_list.append(tpT.refnames[D.member[i]])
				if pRT is not None and pRT.hash!=PT.hash:
					# Parent structure holding generic pointer differs from the type generic pointer is casted to
					container_of_parent_ptr = pRT.str
					if container_of_parent_ptr!="" and container_type!="":
						logs = container_of_entry_string(RT,pRT,initME,PT,mRT,mName,dloc,".".join(refname_list),D)
						if _k not in generic_pointer_type_mappings:
							generic_pointer_type_mappings[_k] = {}
						gptm_key = (pRT.id,mName)
						if gptm_key not in generic_pointer_type_mappings[_k]:
							generic_pointer_type_mappings[_k][gptm_key] = list()
						generic_pointer_type_mappings[_k][gptm_key].append((container_type,PT.id,logs,locT,".".join(refname_list),D.offset))
						# [mapping log]
						container_of_logs[_k][0].append(logs)
					else:
						# [failed log]
						container_of_logs[_k][1].append(container_of_entry_string(RT,pRT,initME,PT,mRT,mName,dloc,".".join(refname_list),D))
				elif pRT is None:
					# Either generic pointer is not used inside member expression or RT is not a generic pointer
					if RT.str in generic_pointer_type_list and len(ME.type)==1 and len(ME.offsetrefs)==1 and \
							(ME.offsetrefs[0].kindname=="global" or ME.offsetrefs[0].kindname=="local" or ME.offsetrefs[0].kindname=="parm" or ME.offsetrefs[0].kindname=="unary"):
						# 'container_of' is directly used on generic pointer variable (no member expression in specific class)
						# [generic log]
						container_of_logs[_k][4].append(container_of_entry_string(RT,pRT,initME,PT,mRT,mName,dloc,".".join(refname_list),D))
					else:
						if RT.str not in generic_pointer_type_list:
							# [mapping log]
							logs = container_of_entry_string(RT,pRT,initME,PT,mRT,mName,dloc,".".join(refname_list),D)
							container_of_logs[_k][0].append(logs)
							if False:
								container_of_ptr = RT.str
								if _k not in generic_pointer_type_mappings:
									generic_pointer_type_mappings[_k] = {}
								gptm_key = (RT.id,"",-1)
								if gptm_key not in generic_pointer_type_mappings[_k]:
									generic_pointer_type_mappings[_k][gptm_key] = list()
								generic_pointer_type_mappings[_k][gptm_key].append((container_type,PT.id,logs,locT,".".join(refname_list),D.offset))
								if False:
									print(_k,gptm_key[2])
									#for RT,pRT,initME,ME,mRT,mName,mId,D,dloc,f in _v:
									print( RT.str,pRT,json.dumps(initME.json(),indent=4),mRT,"[%s]"%(mName),mId,dloc )
									print (D)
									print (fi)
									gone()
						else:
							# Unhandled generic pointer
							# [unhandled log]
							container_of_logs[_k][2].append(container_of_entry_string(RT,pRT,initME,PT,mRT,mName,dloc,".".join(refname_list),D))
				else:
					# Parent structure and the type generic pointer is casted to match
					# [match log]
					logs = container_of_entry_string(RT,pRT,initME,PT,mRT,mName,dloc,".".join(refname_list),D)
					container_of_logs[_k][3].append(logs)
					if _k not in generic_pointer_type_mappings:
						generic_pointer_type_mappings[_k] = {}
					gptm_key = (PT.id,mName)
					if gptm_key not in generic_pointer_type_mappings[_k]:
						generic_pointer_type_mappings[_k][gptm_key] = list()
					generic_pointer_type_mappings[_k][gptm_key].append((container_type,PT.id,logs,locT,".".join(refname_list),D.offset))

		if logdebug:
			for _k,_v in sorted(container_of_logs.iteritems(),key = lambda x: len(x[1][0])+len(x[1][1])+len(x[1][2])+len(x[1][3]),reverse=True):
				print ("## 'container_of' usage for member '%s' : %d\n"%(_k,len(_v[0])+len(_v[1])+len(_v[2])+len(_v[3])))
				print ("#  Matching logs")
				for logl in _v[3]:
					print (logl)
				print ("#  Mapping logs")
				for logl in _v[0]:
					print (logl)
				print ("#  Generic logs")
				for logl in _v[4]:
					print (logl)
				print ("#  Failed logs")
				for logl in _v[1]:
					print (logl)
				print ("#  Unhandled logs")
				for logl in _v[2]:
					print (logl)

		if not quiet:
			print
		container_of_mappings = {}
		for _k in generic_pointer_type_mappings:
			vmap = {}
			# kT: (TID,member_name)
			# vT: (container_type,container_type_id,usage_logs,location_tuple,memberref_string,memberref_offset)
			#	container_type: the type of container structure used in the 'container_of' cast
			for kT,vT in generic_pointer_type_mappings[_k].items():
				for Ts,TID,lg,locT,ref,off in vT:
					if kT not in vmap:
						vmap[kT] = list()
					vmap[kT].append((Ts,TID,lg,locT,ref,off))
			if len(vmap)>=5:
				if not quiet:
					# structms.add((T.id,T.refnames[n],n,T.usedrefs[n]))
					if _k.split()[-1] in generic_pointer_type_stats:
						stats = generic_pointer_type_stats[_k.split()[-1]]
						print ("# Number of '%s' mappings: %d (%d members, %d used members)"%(_k,len(vmap),len(stats),len([x for x in stats if x[3]>=0])))
					else:
						print ("# Number of '%s' mappings: %d"%(_k,len(vmap)))
				for kT,v in vmap.items():
					k = "%s:%s"%(self.ftdb.types[kT[0]].str,kT[1])
					vm = {}
					for Ts,TID,lg,locT,ref,off in v:
						if (Ts,TID) not in vm:
							vm[(Ts,TID)] = list()
						vm[(Ts,TID)].append(locT)
					if not quiet:
						pass
						#print (" %s => [%s]%s"%(k,",".join(["%s(%d)"%("%s"%(u[0]),len(vm[u])) for u in vm.keys()])," "*20+"".join(["*"*5+" " for x in vm.keys()]) if len(vm.keys())>1 else ""))
						#print (kT)
					gpk = _k.split()[1]
					if gpk not in container_of_mappings:
						container_of_mappings[gpk] = {}
					container_of_mappings[gpk][(kT[0],kT[1])] = [(uk[1],uv) for uk,uv in vm.items()]
					if debug:
						for Ts,lgL in vm.iteritems():
							print ("    @ %s => %s(%d):"%(k,Ts,len(lgL)))
							for lg in lgL:
								print ("\n".join(" "*6+x for x in lg.split("\n")))

		if not quiet:
			print ("Number of container_of final mappings: %d"%(len(container_of_mappings)))
			for k in container_of_mappings:
				vm = container_of_mappings[k]
				print ("# %s : %d entries (%d single entries)"%(k,len(vm),len([x for x in vm.values() if len(x)<=1])))
		return container_of_mappings

	# [(TR,MT,containerT,offset,expr),...]
	# TR : [(T,refname),...]
	#   type and member name of each member expression part in a member expression chain passed to the 'container_of' macro
	# MT : type of the member in the member expression passed to the 'container_of' macro
	# containerT : container type
	# offset : offset within containerT the 'container_of' pointer points to
	# expr : plain expression with 'container_of' usage
	def findContainerOfEntries2(self,report_errors=False,quiet=False,debug=False,tpdebug=False,logdebug=False):

		__read_once_size_entry = None
		if self.ftdb.funcs.contains_name("__read_once_size"):
			__read_once_size_entry = self.ftdb.funcs.entry_by_name("__read_once_size")[0]
		
		# List of locations for purported usage of 'container_of' macro
		# We get it by first extracting locations of all '__mptr' local variables (which are used inside 'container_of' macro)
		#  and then matching offsetof dereference expressions with these locations (which happens later inside 'container_of' macro)
		# (offsetD,__mptr_loc,f), where
		#   offsetD - offsetof dereference expression used at the location with '__mptr' variable
		#   __mptr_loc - location of '__mptr' variable
		#   f - original function where offsetof was taken
		container_of_derefs = list()
		for f in self.funcs_list:
			mptr_locs = set([":".join(x.location.split()[0].split(":")[:-1]) for x in f.locals if x.parm is False and x.name=="__mptr"])
			for D in f.derefs:
				if D.kindname=="offsetof":
					# We will look for offsetof expressions with computed offset value
					__mptr_loc = ":".join(D.expr.split("]:")[0][1:].split()[0].split(":")[:-1])
					if __mptr_loc in mptr_locs:
						container_of_derefs.append((D,__mptr_loc,f))

		__mptr_initExpr_count = 0
		__mptr_initExpr_member_count = 0
		container_of_vector = list()
		for offsetD,__mptr_loc,f in container_of_derefs:

			# How to extract the pointer passed to 'container_of' macro?
			# First we get the location of the 'container_of' invocation ('__mptr_loc')
			#  and lookup the index of the corresponding '__mptr' variable (with the same location)
			# Then search for the 'init' dereference expression that initializes the '__mptr' variable detected above
			# Finally extract the initializer member expression when applicable
			# There's a quirk however when the member expression passed to 'container_of' goes through 'READ_ONCE' macro
			# To account for that whenever we detect that the initializer member expression type is anonymous union we do the following steps:
			#  look into 'calls' array from this function where 'container_of' is used and locate invocations of '__read_once_size' function
			#  find first '__read_once_size' invocation location (from 'call_info' array) that matches the '__mptr_loc' location
			#  get the dereference expression for its first argument ('parm' kind) and extract the member expression it points to (this is what we're looking for)
			# To complicate things further we might have several 'container_of' invocations in one higher-level macro (and hence the same location)
			#  This can be resolved by combining '__mptr' variable with offsetof dereference expression that both share the same 'csid'

			mptr_map = { (":".join(x.location.split()[0].split(":")[:-1]),x.csid):i for i,x in enumerate(f.locals) if x.parm is False and x.name=="__mptr" }
			if (__mptr_loc,offsetD.csid) in mptr_map:
				i = mptr_map[(__mptr_loc,offsetD.csid)]
				for x in f.derefs:
					if x.kindname=="init":
						iloc = ":".join(x.expr.split("]:")[0][1:].split()[0].split(":")[:-1])
						if iloc==__mptr_loc and x.csid==offsetD.csid and x.offsetrefs[0].kindname=="local" and x.offsetrefs[0].id==i:
							__mptr_initExpr = x.offsetrefs[1]
							__mptr_initExpr_count+=1
							if __mptr_initExpr.kindname=="member":
								# init expression for the 'container_of' pointer variable (void *__mptr = <EXPR>) is a mamber expression
								ME = f.derefs[__mptr_initExpr.id]
								__mptr_initExpr_member_count+=1
								TR = list()
								RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
								if RT.classname!="record":
									raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
								MT = self.ftdb.types[RT.refs[ME.member[-1]]]
								#refname = RT.refnames[ME.member[-1]]
								if __read_once_size_entry is not None and RT.isunion is True and RT.str=="":
									rdonceList = [ii for ii,cid in enumerate(f.calls) if cid==__read_once_size_entry.id]
									rdonceCI = [f.call_info[ii] for ii in rdonceList if ":".join(f.call_info[ii].loc.split()[0].split(":")[:-1])==dloc]
									if len(rdonceCI)>0:
										parmD = f.derefs[rdonceCI[0].args[0]]
										if len(parmD.offsetrefs)>0 and parmD.offsetrefs[0].kindname=="member":
											ME = f.derefs[parmD.offsetrefs[0].id]
											RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
								for i in range(len(ME.type)):
									U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
									TR.insert(0,(U,U.refnames[ME.member[-1-i]]))
								if len([x for x in TR if x[0].str!=""])==0: # Couldn't find enclosing non-anonymous structure type for a given member
									# Don't give up just yet, the base of member expression can be an array of anonymous structure type as in:
									#   struct A {
									#     struct { struct list_head* link; } m[N];
									#     (...)
									#   };
									#  struct A obA;
									#  obA.m[4].link
									if ME.offsetrefs[0].kindname=="array":
										arrD = f.derefs[ME.offsetrefs[0].id]
										arrME = f.derefs[arrD.offsetrefs[0].id]
										for i in range(len(arrME.type)):
											U = self.resolve_record_type(self.ftdb.types[arrME.type[-1-i]])
											TR.insert(0,(U,U.refnames[ME.member[-1-i]]))
										if len([x for x in TR if x[0].str!=""])==0: # Ok, give up now
											TR.insert(0,(U,U.refnames[ME.member[-1-i]]))
									else:
										TR.insert(0,(U,U.refnames[ME.member[-1-i]]))
								TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
								TT = self.resolve_record_type(MT)
								if TT:
									MTstr = "struct %s"%(TT.str)
								else:
									MTstr = MT.hash
								container_of_vector.append((TR,MT,self.ftdb.types[offsetD.type[0]],offsetD.offset,ME.expr))

		if not quiet:
			print ("Number of 'container_of' invocations: %d"%(__mptr_initExpr_count))
			print ("Number of 'container_of' invocations with member expression pointer: %d"%(__mptr_initExpr_member_count))

		return container_of_vector

	# {
	#	 (TID,member_name): {(container_type_id,offset),...}
	#	 (...)
	# }

	def containerOfUsageInfo(self,container_of_vector,quiet=False):

		# Finding structure member anchors
		# We define anchors like a member of a struct X which points to the same struct X
		# For example:
		# struct U {
		#   struct list_head {
		#      struct list_head* next;
		#   }
		# }
		# Now we call the 'struct list_head' in struct U an anchor
		anchor_list = set()
		for TR,MT,containerT,offset,expr in container_of_vector:
			T = None
			for i in range(len(TR)):
				if TR[-1-i][0].str!="":
					T = TR[-1-i][0]
					break
			TT = self.resolve_record_type(MT)
			if T and TT and T.str==TT.str:
				anchor_list.add(T.str)

		container_of_mappings = {}
		container_of_exprs = {}
		usg = set()
		for TR,MT,containerT,offset,expr in container_of_vector:
			TT = self.resolve_record_type(MT)
			if TT:
				MTstr = "struct %s"%(TT.str)
			else:
				MTstr = MT.hash
			T = None
			refname_list = list()
			for i in range(len(TR)):
				refname_list.insert(0,TR[-1-i][1])
				T = TR[-1-i][0]
				if T.str not in anchor_list:
					break
			if T.str in anchor_list:
				continue
			refname = ".".join(refname_list)
			usg.add((T.str,refname,MTstr))
			if (T.id,refname) in container_of_mappings:
				container_of_mappings[(T.id,refname)].add((containerT.id,offset))
			else:
				container_of_mappings[(T.id,refname)] = set([(containerT.id,offset)])
			if (T.id,refname) in container_of_exprs:
				container_of_exprs[(T.id,refname)].append(expr)
			else:
				container_of_exprs[(T.id,refname)] = [expr]

		if not quiet:
			print ("Number of distinct member expression pointers in 'container_of' invocation: %d"%(len(container_of_mappings)))
			print ("Number of distinct member expression pointers in 'container_of' invocation with single container type: %d"%(
				len([k for k,v in container_of_mappings.items() if len(v)<=1])))

		return container_of_mappings,container_of_exprs

	"""
	Looks in dereference expressions for assignments directly from member expression from void* members
	Returns the list of the following items (T,TPD,R,MT,LT,E,n):
	  T: type of the structure to which member expression was applied on the RHS (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member on the RHS
	  MT: type of the member on the RHS
	  LT: type of the variable on the LHS
	  E: text of the full assignment expression
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) on the RHS
	Example:
	  struct A {
	    int x;
	    union {
	    	void* p;
	    };
	  };
	  struct U* u;
	  struct A obA;
	  u = obA.p;
	  --> T : struct A
	  --> TPD: None
	  --> R: 'p'
	  --> MT: void*
	  --> LT: struct U*
	  --> E: 'u = obA.p'
	  --> n: (1,0)
	"""
	def findAssignFromVoidPtrMembers(self,report_errors=False):

		assign_count = 0
		assign_from_ME_count = 0
		ptr_to_void_member_count = 0
		ptrvL = list()
		for f in self.funcs_list:
			for D in f.derefs:
				if D.kindname=="assign" and D.offset==21:
					assign_count+=1
					# Handle LHS
					lhs = D.offsetrefs[0]
					if lhs.kindname=="global":
						tp = self.ftdb.globals[lhs.id].type
					elif lhs.kindname=="local" or lhs.kindname=="parm":
						tp = f.locals[lhs.id].type
					elif lhs.kindname=="unary":
						tp = lhs.cast
					elif lhs.kindname=="array":
						tp = lhs.cast
					elif lhs.kindname=="member":
						if len(f.derefs)<=lhs.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at LHS of assignment (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[lhs.id]
						T = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						if T.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						n = ME.member[-1]
						tp = T.refs[n]
					else:
						raise DerefException("Unhandled case on the LHS of assignment", [x.json() for x in f.derefs])
					if len(D.offsetrefs)<2:
						if self.report_errors or report_errors:
							print ("WARNING: Missing RHS of an assignment (need to check DBJSON)")
							print (json.dumps(D.json(),indent=4))
						continue
					# Now check the RHS
					# We will look for exactly one member expression on the RHS
					rhs = self.lookForSingleMemberExpr(D.offsetrefs[1:])
					if rhs is not None:
						if len(f.derefs)<=rhs.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at RHS of assignment (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[rhs.id]
						assign_from_ME_count+=1
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.tpes[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if MT.id in self.ptr_to_void_type:
							ptr_to_void_member_count+=1
							ptrvL.append((T,TPD,refname,MT,self.ftdb.types[tp],D.expr.strip(),tuple(reversed(n))))

		return ptrvL

	"""
	Looks in dereference expressions for initialization that comes directly from member expression from void* members
	Returns the list of the following items (T,TPD,R,MT,LT,E,n):
	  T: type of the structure to which member expression was applied on the RHS (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member on the RHS
	  MT: type of the member on the RHS
	  LT: type of the variable being initialized
	  E: text of the full initialization expression
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) on the RHS
	Example:
	  struct A { void* p; };
	  struct U* u = obA.p;
	"""
	def findInitFromVoidPtrMembers(self,report_errors=False):

		init_count = 0
		init_from_ME_count = 0
		ptr_to_void_member_count = 0
		ptrvL = list()
		for f in self.funcs_list:
			for D in f.derefs:
				if D.kindname=="init":
					init_count+=1
					# The variable being initialized
					lhs = D.offsetrefs[0]
					if lhs.kindname=="global":
						tp = self.ftdb.globals[lhs.id].type
					elif lhs.kindname=="local":
						tp = f.locals[lhs.id].type
					else:
						raise DerefException("Unhandled case on the LHS of initialization", [x.json() for x in f.derefs])
					if len(D.offsetrefs)<2:
						if self.report_errors or report_errors:
							print ("WARNING: Missing RHS of the initialization (need to check DBJSON)")
							print (json.dumps(D.json(),indent=4))
						continue
					# Now check the RHS
					# We will look for exactly one member expression on the RHS
					rhs = self.lookForSingleMemberExpr(D.offsetrefs[1:])
					if rhs is not None:
						if len(f.derefs)<=rhs.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at RHS of assignment (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[rhs.id]
						init_from_ME_count+=1
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if MT.id in self.ptr_to_void_type:
							ptr_to_void_member_count+=1
							ptrvL.append((T,TPD,refname,MT,self.ftdb.types[tp],D.expr.strip(),tuple(reversed(n))))

		return ptrvL

	"""
	Looks in dereference expressions for assignments directly to void* member expression members
	Returns the list of the following items (T,TPD,R,MT,LT,E,n):
	  T: type of the structure to which member expression was applied on the LHS (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member on the LHS
	  MT: type of the member on the LHS
	  LT: type of the variable on the RHS
	  E: text of the full assignment expression
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) on the LHS
	Example:
	  struct A { void* p; };
	  struct U* u;
	  struct A obA;
	  obA.p = u;
	"""
	def findAssignToVoidPtrMembers(self,report_errors=False):

		assign_count = 0
		assign_to_ME_count = 0
		ptr_to_void_member_count = 0
		ptrvL = list()
		for f in self.funcs_list:
			for D in f.derefs:
				if D.kindname=="assign" and D.offset==21:
					assign_count+=1
					# Handle RHS first
					if len(D.offsetrefs)<2:
						if self.report_errors or report_errors:
							print ("WARNING: Missing RHS of an assignment (need to check DBJSON)")
							print (json.dumps(D.json(),indent=4))
						continue
					# We will look for exactly one variable expression on the RHS
					rhs = self.lookForSingleVariableExpression(D.offsetrefs[1:])
					if rhs is not None:
						if rhs.kindname=="global":
							tp = self.ftdb.globals[rhs.id].type
						elif rhs.kindname=="local" or rhs.kindname=="parm":
							tp = f.locals[rhs.id].type
						elif rhs.kindname=="unary" or rhs.kindname=="array" or rhs.kindname=="member":
							if not rhs.has_cast():
								if self.report_errors or report_errors:
									print ("WARNING: Missing cast information on member expression in offsetrefs (need to check DBJSON)")
									print (D.expr)
									print (json.dumps(rhs.json(),indent=4))
								continue
							tp = rhs.cast
						# Now handle LHS
						lhs = D.offsetrefs[0]
						if lhs.kindname!="member":
							# We only care about the member assignments
							continue
						else:
							if len(f.derefs)<=lhs.id:
								if self.report_errors or report_errors:
									print ("WARNING: Missing deref entry referenced at LHS of assignment (need to check DBJSON)")
									print (json.dumps([x.json() for x in f.derefs],indent=4))
								continue
						ME = f.derefs[lhs.id]
						assign_to_ME_count+=1
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if T.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if MT.id in self.ptr_to_void_type:
							ptr_to_void_member_count+=1
							ptrvL.append((T,TPD,refname,MT,self.ftdb.types[tp],D.expr.strip(),tuple(reversed(n))))
		return ptrvL


	"""
	Looks into return expressions for functions that return void* and tracks the type of single returned variable expression
	Returns the list of the following items (F,T,E):
	  F: function id where this return expression was used
	  T: type of the return expression
	  E: text of the full return expression
	Example:
	  struct A { char* s; };
	  void* fun(void) {
		unsigned long ul = 0;
		unsigned long* pul = &ul;
		return pul;
	  }
	"""
	def findVoidPtrReturnFromFunctions(self,report_errors=False):

		voidptr_return_fun_count = 0
		return_count = 0
		retL = list()
		for f in self.funcs_list:
			if f.types[0] not in self.ptr_to_void_type:
				continue
			voidptr_return_fun_count+=1
			for D in f.derefs:
				if D.kindname=="return":
					return_count+=1
					# We will look for exactly one variable expression in the return expression
					rexpr = self.lookForSingleVariableExpression(D.offsetrefs)
					if rexpr is not None:
						if rexpr.kindname=="global":
							tp = self.ftdb.globals[rexpr.id].type
						elif rexpr.kindname=="local" or rexpr.kindname=="parm":
							tp = f.locals[rexpr.id].type
						elif rexpr.kindname=="unary" or rexpr.kindname=="array" or rexpr.kindname=="member":
							if not rexpr.has_cast():
								if self.report_errors or report_errors:
									print ("WARNING: Missing cast information on member expression in offsetrefs (need to check DBJSON)")
									print (D.expr)
									print (json.dumps(rexpr.json(),indent=4))
								continue
							tp = rexpr.cast
						retL.append((f.id,self.ftdb.types[tp],D.expr.strip()))
		return retL

	

	"""
	Looks into function pointer call arguments for single member expression with void* type
	Returns the list of the following items (T,TPD,R,MT,RT,E,n,F):
	  T: type of the structure to which member expression was applied in the function call argument (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member in the argument member expression
	  MT: type of the member in the argument member expression
	  RT: function parameter type for this function call argument
	  E: text of the function call argument
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the function argument expression
	  F: function id where this function call argument was used
	Example:
	  struct A { void* p; };
	  struct B { void (*fun)(const struct A*); };
	  (...)
	  {
		struct A* pA;
		struct B b;
		(...)
		b.fun(pA->p);
	  }
	"""
	def findFunctionPtrVoidPtrArguments(self,report_errors=False):

		arg_count = 0
		arg_with_ME_count = 0
		argL = list()
		for f in self.funcs_list:
			for ci_i,ci in enumerate(f.refcall_info):
				for ca_i,ca in enumerate(ci.args):
					arg_count+=1
					D = f.derefs[ca]
					if D.kindname!="parm":
						if self.report_errors or report_errors:
							print ("WARNING: Invalid derefence kind in function call information (%d) argument (%d) (need to check DBJSON)"%(i,j))
							print (json.dumps(f.json(),indent=4))
							continue
					# We will look for exactly one member expression in the function argument
					pexpr = self.lookForSingleMemberExpr(D.offsetrefs)
					if pexpr is not None:
						if len(f.derefs)<=pexpr.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at return expression (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[pexpr.id]
						arg_with_ME_count+=1
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if MT.id in self.ptr_to_void_type:
							rfT = self.ftdb.types[f.refcalls[ci_i][0]]
							if 1+ca_i>=len(rfT.refs):
								if not rfT.variadic:
									print ("WARNING: Couldn't detect function ref (%d) argument (%d)"%(rfT.id,1+ca_i))
									continue
								# Calling function with variable number of arguments
								continue
							parm_type = self.ftdb.types[rfT.refs[1+ca_i]]
							if parm_type not in self.ptr_to_void_type:
								argL.append((T,TPD,refname,MT,parm_type,D.expr.strip(),tuple(reversed(n)),f.id))
		return argL

	"""
	Looks into function call arguments for single member expression with void* type
	Returns the list of the following items (T,TPD,R,MT,RT,E,n,F):
	  T: type of the structure to which member expression was applied in the function call argument (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member in the argument member expression
	  MT: type of the member in the argument member expression
	  RT: function parameter type for this function call argument
	  E: text of the function call argument
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the function argument expression
	  F: function id where this function call argument was used
	Example:
	  struct A { void* p; };
	  void fun(const struct A*);
	  (...)
	  {
		struct A* pA;
		(...)
		fun(pA->p);
	  }
	"""
	def findFunctionVoidPtrArguments(self,report_errors=False):

		arg_count = 0
		arg_with_ME_count = 0
		argL = list()
		for f in self.funcs_list:
			for ci_i,ci in enumerate(f.call_info):
				for ca_i,ca in enumerate(ci.args):
					arg_count+=1
					D = f.derefs[ca]
					if D.kindname!="parm":
						if self.report_errors or report_errors:
							print ("WARNING: Invalid derefence kind in function call information (%d) argument (%d) (need to check DBJSON)"%(i,j))
							print (json.dumps(f.json(),indent=4))
							continue
					# We will look for exactly one member expression in the function argument
					pexpr = self.lookForSingleMemberExpr(D.offsetrefs)
					if pexpr is not None:
						if len(f.derefs)<=pexpr.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at return expression (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[pexpr.id]
						arg_with_ME_count+=1
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if MT.id in self.ptr_to_void_type:
							if self.ftdb.funcs.contains_id(f.calls[ci_i]):
								called_f = self.ftdb.funcs.entry_by_id(f.calls[ci_i])
							elif self.ftdb.funcdecls.contains_id(f.calls[ci_i]):
								called_f = self.ftdb.funcdecls.entry_by_id(f.calls[ci_i])
							else:
								# Calling some builtin function: ignore
								continue
							if 1+ca_i>=len(called_f.types):
								if not called_f.variadic:
									print ("WARNING: Couldn't detect function (%d) argument (%d)"%(called_f.id,1+ca_i))
									continue
								# Calling function with variable number of arguments
								continue
							parm_type = self.ftdb.types[called_f.types[1+ca_i]]
							if parm_type.id not in self.ptr_to_void_type:
								argL.append((T,TPD,refname,MT,parm_type,D.expr.strip(),tuple(reversed(n)),f.id))
		return argL

	"""
	Looks into return expression for functions and tracks single member expression with void* type
	Returns the list of the following items (T,TPD,R,MT,RT,E,n,F):
	  T: type of the structure to which member expression was applied in the return expression (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member in the return expression
	  MT: type of the member in the return expression
	  RT: return type of this function
	  E: text of the full return expression
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the returned expression
	  F: function id where this return expression was used
	Example:
	  struct A { void* p; };
	  unsigned long* fun(void) {
		struct A* pA;
		(...)
		return pA->p;
	  }
	"""
	def findFunctionReturnFromVoidPtrMembers(self,report_errors=False):

		return_count = 0
		return_with_ME_count = 0
		retL = list()
		for f in self.funcs_list:
			for D in f.derefs:
				if D.kindname=="return":
					return_count+=1
					# We will look for exactly one member expression in the return expression
					rexpr = self.lookForSingleMemberExpr(D.offsetrefs)
					if rexpr is not None:
						if len(f.derefs)<=rexpr.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at return expression (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[rexpr.id]
						return_with_ME_count+=1
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						if len(n) == 0 or len(RT.refs) <= n[0]:
							continue
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if MT.id in self.ptr_to_void_type and f.types[0] not in self.ptr_to_void_type:
							retL.append((T,TPD,refname,MT,self.ftdb.types[f.types[0]],D.expr.strip(),tuple(reversed(n)),f.id))
		return retL

	"""
	Looks into all void* member expressions in dereference information and notify all casts other than void*
	Returns the list of the following items (T,TPD,R,MT,CT,E,n,F):
	  T: type of the structure to which member expression was applied (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member in the member expression
	  MT: type of the member in the member expression
	  CT: the type this member expression was casted to
	  E: text of the full return expression
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the cast expression
	  F: function id where this member expression was used
	Example:
	  struct A { void* p; };
	  struct A obA;
	  (struct B*)obA.p;
	  }
	"""
	def findMemberExprCasts(self,report_errors=False):

		castMeL = list()
		for i,f in enumerate(self.funcs_list):
			for D in f.derefs:
				for oref in D.offsetrefs:
					if oref.kindname=="member":
						if len(f.derefs)<=oref.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at return expression (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[oref.id]
						if oref.has_cast() and oref.cast not in self.ptr_to_void_type:
							T = None
							n = list()
							RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
							for i in range(len(ME.type)):
								U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
								n.append(ME.member[-1-i])
								if U.str!="":
									T = U
									break
							if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
								T=U
							TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
							if RT.classname!="record":
								raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
							if len(n) == 0 or len(RT.refs) <= n[0]:
								continue
							MT = self.ftdb.types[RT.refs[n[0]]]
							refname = RT.refnames[n[0]]
							if MT.id in self.ptr_to_void_type:
								castMeL.append((T,TPD,refname,MT,self.ftdb.types[oref.cast],D.expr.strip(),tuple(reversed(n)),f.id))
		return castMeL

	"""
	Looks into all unary dereference expressions and tracks the usage of member expressions at its base (for single member expressions only)
	For each such expression looks if the dereference offset is non-zero or other variable expressions are used in the dereference expressions
	Returns the list of the following items (F,T,TPD,R,MT,off,m,E,n):
	  F: function id where this unary dereference expression was used
	  T: type of the structure to which member expression at the base of unary expression was applied (outermost type in case of member expression in a chain of anonymous records)
	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
	  R: refname of the member in the member expression at the base of unary expression was applied
	  MT: type of the member in the member expression at the base of unary expression was applied
	  off: dereference offset used in the dereference expression
	  m: number of other variable expressions used in the dereference expression (other than original member expression)
	  E: text of the unary dereference expression
	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the original member expression
	Example:
      struct B;
	  struct A { struct B* p; };
	  struct A obA;
	  *(obA.p+2);
	  }
	"""
	def findDerefsOnMemberExprs(self,report_errors=False):

		derefL = list()
		for f in self.funcs_list:
			for D in f.derefs:
				if D.kindname=="unary":
					# We will look for exactly one member expression in the dereference expression
					bexpr = self.lookForSingleMemberExpr(D.offsetrefs)
					if bexpr is not None:
						if len(f.derefs)<=bexpr.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at return expression (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs()],indent=4))
							continue
						ME = f.derefs[bexpr.id]
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						derefL.append((f.id,T,TPD,refname,MT,D.offset,len(D.offsetrefs)-1,D.expr.strip(),tuple(reversed(n))))
		return derefL

	"""
	Looks into all assignment expressions and returns all member expressions found at the RHS of assignment operator
	Returns the list of the following items (F,T,TPD,R,MT,E,(n...)):
	  F: function id where this assignment operator was used
  	  T: type of the structure of the member expression used at the RHS of assignment operator (outermost type in case of member expression in a chain of anonymous records)
  	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
  	  R: refname of the member of the member expression used at the RHS of assignment operator
  	  MT: type of the member of the member expression used at the RHS of assignment operator
  	  E: text of the assignment operator
  	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the original member expression
	"""
	def findMemberExprsOnAssignRHS(self,report_errors=False):
			
		assign_count = 0
		meL = list()
		ks = set()
		for f in self.funcs_list:
			for D in f.derefs:
				if D.kindname=="assign" and D.offset==21:
					assign_count+=1
					# We will look for exactly one member expression on the RHS
					rhs = self.lookForSingleMemberExpr(D.offsetrefs[1:])
					if rhs is not None:
						if len(f.derefs)<=rhs.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at RHS of assignment (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[rhs.id]
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if TPD is not None:
							_k = (T.id,TPD.id,refname)
						else:
							_k = (T.id,None,refname)
						if _k not in ks:
							ks.add(_k)
							meL.append((f.id,T,TPD,refname,MT,D.expr.strip(),tuple(reversed(n))))
		return meL

	def _mergeMemberExprOnRHS(self,aL,bL):

		meL = list()
		ks = set()
		for x in aL: # (F,T,TPD,R,MT,E,(n...))
			if x[2] is not None:
				RT = self.resolve_record_type(self.ftdb.types[x[2].id])
				_k = (RT.id,x[3])
			else:
				_k = (x[1].id,x[3])
			ks.add(_k)
			meL.append(_k)
		for x in bL:
			if x[2] is not None:
				RT = self.resolve_record_type(self.ftdb.types[x[2].id])
				_k = (RT.id,x[3])
			else:
				_k = (x[1].id,x[3])
			if _k not in ks:
				ks.add(_k)
				meL.append(_k)
		return meL


	"""
	Looks into all init dereference expressions and returns all member expressions found at the initializer side of the expression
	Returns the list of the following items (F,T,TPD,R,MT,E,(n...)):
	  F: function id where this initialization expression was used
  	  T: type of the structure of the member expression used at the initializer (outermost type in case of member expression in a chain of anonymous records)
  	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
  	  R: refname of the member of the member expression used at the initializer
  	  MT: type of the member of the member expression used at the initializer
  	  E: text of the initialization expression
  	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the original member expression
	"""
	def findMemberExprsOnInit(self,report_errors=False):
		
		init_count = 0
		meL = list()
		ks = set()
		for f in self.funcs_list:
			for D in f.derefs:
				if D.kindname=="init":
					init_count+=1
					# We will look for exactly one member expression on the RHS
					rhs = self.lookForSingleMemberExpr(D.offsetrefs[1:])
					if rhs is not None:
						if len(f.derefs)<=rhs.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at RHS of assignment (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[rhs.id]
						T = None
						n = list()
						RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
						for i in range(len(ME.type)):
							U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
							n.append(ME.member[-1-i])
							if U.str!="":
								T = U
								break
						if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
							T=U
						TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
						if RT.classname!="record":
							raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
						MT = self.ftdb.types[RT.refs[n[0]]]
						refname = RT.refnames[n[0]]
						if TPD is not None:
							_k = (T.id,TPD.id,refname)
						else:
							_k = (T.id,None,refname)
						if _k not in ks:
							ks.add(_k)
							meL.append((f.id,T,TPD,refname,MT,D.expr.strip(),tuple(reversed(n))))
		return meL


	"""
	Finds all invocations of function INIT_LIST_HEAD() and grabs all single member expressions (or array of member expressions) passed thereof
	Returns the list of the following items (F,T,TPD,R,MT,E,(n...)):
	  F: function id where INIT_LIST_HEAD() was called
  	  T: type of the structure of the member expression passed to the INIT_LIST_HEAD function (outermost type in case of member expression in a chain of anonymous records)
  	  TPD: if the structure type T was used through the typedef'ed type this is the original typedef type otherwise it is None
  	  R: refname of the member of the member expression passed to the INIT_LIST_HEAD()
  	  MT: type of the member of the member expression passed to the INIT_LIST_HEAD()
  	  E: text of expression passed to the INIT_LIST_HEAD()
  	  n: list of member ids in the member chain (that leads to the member from the outermost struct type) from the original member expression
	"""
	def findListHeadInitializers(self,report_errors=False):

		
		INIT_LIST_HEAD_ids = [f.id for f in self.funcs_list if f.name=="INIT_LIST_HEAD"]

		call_count = 0
		call_with_ME_count = 0
		ILHL = list()
		for f in self.funcs_list:
			for ci_i,cid in enumerate(f.calls):
				if cid in INIT_LIST_HEAD_ids:
					call_count+=1
					ci = f.call_info[ci_i]
					D = f.derefs[ci.args[0]]
					if D.kindname!="parm":
						if self.report_errors or report_errors:
							print ("WARNING: Invalid derefence kind in function call information (%d) argument (%d) (need to check DBJSON)"%(i,j))
							print (json.dumps(f.json(),indent=4))
							continue
					# We will look for exactly one member expression in the function argument
					pexpr = self.lookForSingleMemberExpr(D.offsetrefs)
					if pexpr is not None:
						if len(f.derefs)<=pexpr.id:
							if self.report_errors or report_errors:
								print ("WARNING: Missing deref entry referenced at return expression (need to check DBJSON)")
								print (json.dumps([x.json() for x in f.derefs],indent=4))
							continue
						ME = f.derefs[pexpr.id]
					else:
						# No direct member expression in INIT_LIST_HEAD argument; check if we have member expression at base of array subscript
						if len(D.offsetrefs)<=1:
							if D.offsetrefs[0].kindname=="array":
								arrD = f.derefs[D.offsetrefs[0].id]
								#print (arrD.json())
								pexpr = self.lookForSingleMemberExpr(arrD.offsetrefs)
								#print (pexpr)
								if pexpr is not None:
									ME = f.derefs[pexpr.id]
							else:
								# Here we have (most likely) a variable passed to the INIT_LIST_HEAD
								continue
						else:
							# Here we have multiple variables used in the expression passed to INIT_LIST_HEAD
							continue
					call_with_ME_count+=1
					T = None
					n = list()
					RT = self.resolve_record_type(self.ftdb.types[ME.type[-1]])
					for i in range(len(ME.type)):
						U = self.resolve_record_type(self.ftdb.types[ME.type[-1-i]])
						n.append(ME.member[-1-i])
						if U.str!="":
							T = U
							break
					if T is None: # Couldn't find enclosing non-anonymous structure type for a given member
						T=U
					TPD = self.resolve_record_typedef(self.ftdb.types[ME.type[-1-i]])
					if RT.classname!="record":
						raise DerefException("Invalid structure type in member expression type", self.ftdb.types[ME.type[-1]].json())
					MT = self.ftdb.types[RT.refs[n[0]]]
					refname = RT.refnames[n[0]]
					ILHL.append((f.id,T,TPD,refname,MT,D.expr.strip(),tuple(reversed(n))))
		return ILHL

	"""
	Find all assignments to structure from void* type accessed via getter. Returns the list of the same format
		as all above funcions.
	Example:
		struct device {void* drv_data;};
		void* get_drvdata(struct device* device) {
			return device->drv_data;
		}
		struct int* a = get_drvdata(dev);

		// Result: mapping between device->drv_data and int* type
	"""
	def findAssignToVoidPtrThroughGetter(self):
		targets = []

		for f in self.funcs_list:
			returns = [deref for deref in f['derefs'] if deref['kind'] == 'return']
			if len(returns) != 1:
				continue
			
			offsetref = returns[0]['offsetrefs']
			if len(offsetref) == 0 or offsetref[0]['kind'] != 'member':
				continue

			returnTypeID = returns[0]['offsetrefs'][0]['cast']
			returnType = self.ftdb.types[returnTypeID] 
			isVoidPtr = returnType['class'] == 'pointer' and self.ftdb.types[returnType['refs'][0]]['str'] == 'void'
			if not isVoidPtr:
				continue

			# At this point, we've narrowed all db.json functions to those having a single return statement
			#  and returning void* pointer
			# What we have to do now is to check what field of stucture is used while casting to void*
			derefEntryForAccess = f['derefs'][returns[0]['offsetrefs'][0]['id']]
			derefEntryForAccessType = derefEntryForAccess.type

			RT = self.resolve_record_type(self.ftdb.types[derefEntryForAccessType[-1]])
			if RT.classname != "record":
				raise DerefException("Invalid structure type in member expression type", 
									self.ftdb.types[derefEntryForAccess.type[-1]].json())

			n = []
			finalType = None
			for i in range(len(derefEntryForAccess.type)):
				type = self.resolve_record_type(self.ftdb.types[derefEntryForAccess.type[-1 - i]])
				n.append(derefEntryForAccess.member[-1 - i])
				if type.str != "":
					finalType = type
					break
			if finalType is None:
				finalType = type

			TPD = self.resolve_record_typedef(self.ftdb.types[derefEntryForAccess.type[-1 - i]])
			if len(n) == 0 or len(RT.refs) <= n[0]:
				continue
			MT = self.ftdb.types[RT.refs[n[0]]]
			refname = RT.refnames[n[0]]
			if MT.id in self.ptr_to_void_type:
				targets.append((finalType, TPD, refname, MT, tuple(reversed(n)), f.id))

		result = []
		# Next, find all structures to which the return value of this function is casted
		for func in self.funcs_list:
			for target in targets:
				targetID = target[-1]
				if targetID not in func.calls:
					continue

				# Look for deref entry of type 'assing' referencing to this func
				for deref in func.derefs:
					if deref.kindname != 'assign' and deref.kindname != 'init':
						continue
					
					if deref.offsetrefs[1].kindname != 'callref':
						continue
					if func.calls[deref.offsetrefs[1].id] != targetID:
						continue
					
					assert(deref.offsetrefs[0].kindname == 'local')
					localID = deref.offsetrefs[0].id
					typeID = func.locals[localID].type

					type = self.ftdb.types[typeID]
					if len(type.refs) == 0:
						continue

					unpointeredType = self.ftdb.types[type.refs[0]]
					typedefType = self.resolve_record_typedef(unpointeredType)
					result.append((
						self.typeToNonConst(target[0]),
						self.typeToNonConst(typedefType),
						target[2],
						target[3],
						type,
						deref.expr.strip(),
						target[4],
						func.id))
		return result
