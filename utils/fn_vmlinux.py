print("Detecting kernel flatten image function pointers (gdb {})".format(gdb.VERSION))
import struct
import os
flatten_header_size = 80
fptrmapsz_header_offset = 56
with open(imgpath,"rb") as f:
	hdr = f.read(8+flatten_header_size)
memory_size, ptr_count, fptr_count, root_addr_count, root_addr_extended_count, root_addr_extended_size, this_addr, fnsize, mcount, magic =\
	struct.unpack('QQQQQQQQQQ', hdr[8:flatten_header_size+8])
assert magic==5065495511331851776, "Invalid magic in flattened image"
print("Flatten magic: OK")
print("  Memory size: %d"%(memory_size))
print("  Pointer count: %d"%(ptr_count))
print("  Function pointer count: %d"%(fptr_count))
print("  Root address count: %d"%(root_addr_count))
print("  Root address extended count: %d"%(root_addr_extended_count))
print("  Root address extended size: %d"%(root_addr_extended_size))
print("  Base address: %d"%(this_addr))
print("  fnsize: %d"%(fnsize))
print("  mcount: %d"%(mcount))
try:
	s = gdb.execute("info address flatten_base_function_address",False,True)
except Exception as e:
	print(e)
	sys.exit(0)
vmlinux_fdi_addr = int(s.split()[-1].strip(".").strip()[2:],16)
kernel_load_addr = this_addr - vmlinux_fdi_addr
print("Kernel load address: %lx"%(kernel_load_addr))
print("Found %d function pointers"%(fptr_count))
kernel_dir = os.getcwd()
fptrMap = {}
matched = 0
with open(imgpath, "rb") as f:
	f.seek(8+flatten_header_size+root_addr_count*8+root_addr_extended_size+ptr_count*8)
	u = list(struct.unpack('%dQ'%(fptr_count), f.read(fptr_count*8)))
	f.seek(8+flatten_header_size+root_addr_count*8+root_addr_extended_size+ptr_count*8+fptr_count*8+mcount*2*8)
	img = f.read(memory_size)
	vmlinux_fptrs = [struct.unpack('Q',img[i:i+8])[0]-kernel_load_addr for i in u if struct.unpack('Q',img[i:i+8])[0]>0]
	import re
	smre = re.compile("(\w+)\sin\ssection\s.text$")
	for vp in vmlinux_fptrs:
		try:
			s = gdb.execute("info symbol 0x%lx"%(vp),False,True).strip()
			m = smre.match(s)
			if m:
				fsym = m.groups()[0]
				fsL = gdb.execute("info fun %s"%(fsym),False,True).strip().split("\n\n")[1:]
				for fs in fsL:
					kfn = fs.split(":")[0].split("File ")[1]
					sdi = gdb.execute("p '%s'::%s"%(kfn,fsym),False,True).strip()
					addr = int(sdi.split()[-2][2:],16)
					if (addr==vp):
						if os.path.isabs(kfn):
							kfn = kfn[len(kernel_dir)+1:]
						symbol_repr = "%s__%s"%(kfn.replace("/","__").replace("-","___").replace(".","____"),fsym)
						print("Successfully matched function pointer 0x%lx to function %s::%s"%(vp,kfn,fsym))
						print("Symbol representation: %s"%(symbol_repr))
						matched+=1
						if addr+kernel_load_addr not in fptrMap:
							fptrMap[addr+kernel_load_addr] = symbol_repr
						break
				else:
					print("Couldn't match symbol at vmlinux address 0x%lx: %s\n"%(vp,str(fsL)))
			else:
				print("Couldn't match symbol at vmlinux address 0x%lx: [%s]\n"%(vp,s))
		except Exception as e:
			print("Couldn't find symbol at vmlinux address: 0x%lx\n"%(vp))
			print(e)
			print("Skipping...")
print("# Summary:")
print("Matched %d/%d function pointers"%(matched,fptr_count))
if matched!=fptr_count:
	print("WARNING: some function pointers were not matched and will not be replaced")
fptrmapsz = 8+len(fptrMap)*8*2+sum([len(x) for x in fptrMap.values()])
with open(imgpath, "r+b") as f:
	f.seek(8+flatten_header_size+root_addr_count*8+root_addr_extended_size+ptr_count*8+fptr_count*8+mcount*2*8+memory_size)
	f.write(struct.pack("Q",len(fptrMap))) # Number of elements
	for k,v in fptrMap.items():
		f.write(struct.pack("Q",k)) # function pointer address
		f.write(struct.pack("Q",len(v))) # length of the function symbol
		f.write(struct.pack("%ds"%(len(v)),str.encode(v))) # actual symbol
	f.seek(8+fptrmapsz_header_offset)
	f.write(struct.pack("Q",fptrmapsz))