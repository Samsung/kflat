# Flatten image specification

The flatten image has the following format:

```
[imgsz:8B]
[flatten_header:80B]
[root_addr_array:n*8B]
[root_addr_extended_array:m*B]
[ptr_array:k*8B]
[fptr_array:q*8B]
[fragment_array:v*16B]
[memory:s*B][fptrmap:x*B]
```

`imgsz` is the full size of the flatten image file.

The flatten header has the following entries:
```
memory_size : 8B                 (s)
ptr_count : 8B                   (k)
fptr_count : 8B                  (q)
root_addr_count : 8B             (n)
root_addr_extended_count : 8B    (r)
root_addr_extended_size : 8B     (m)
this_addr : 8B
fptrmapsz : 8B                   (x)
mcount : 8B                      (v)
magic : 8B
```

Most of the above entries describe the size of the corresponding array of data. `this_addr` is an original address of a predefined code location in the original address space which servers as an base for offset computation for function pointer addresses. The magic value is an ASCII coded work `FLATTEN\0`.

`root_addr_array` stores a list of root addresses (i.e. the points in the image which can be used to further access the data embedded into the image) stored consecutively as a list of offsets into the `memory` array.
```
[root_addr:8B,...]: n times
```

`root_addr_extended_array` stores a list of so called extended root addresses which provides additional meta information apart from the mere address into the memory (i.e. name).
```
[root_addr_extended:(24+z)*B]: r times
```

Each entry (there is exactly `r` such entries) contains the following data:
```
name size: 8B  (z)
name:      z*B
index:     8B
size:      8B
```

`ptr_array` array stores a list of locations in the `memory` array which stores a pointer value (which require to be fixed whenever the memory has been read and established into new memory address space).
```
[fix_loc:8B,...]: k times
```

`fptr_array` array stores a list of locations in the `memory` array which stores a function pointer value (which need to be translated into new function pointer address whenever the memory has been read and established into new memory address space).
```
[fptr:8B,...]: q times
```

The flatten image can contain information about memory fragments the original memory is composed of. The `fragment_array` describes each such fragment (where it is located and what is the size of this fragment).
```
[fragment:16B,...]: v times
```

Each fragment provides information about:
```
index: 8B
size:  8B
```

`index` points to the `memory` array where the memory fragment begins and the `size` describes the size of this fragment.

Having information about fragments in crucial for potential memory operations on the read/established memory in new memory address space. Imagine that the goal of the tool after reading the memory image is to enable fuzzing of specific code that uses the memory image. Without the fragment information from the original address space the fuzzer would have hard time finding memory problems (i.e. buffer overflows) as the new memory image is a one allocated memory area. Taking into account the original fragments the memory images can be constructed is such a way that each fragment is allocated separately and the fuzzer can take advantage of sanitizer infrastructure to look for buffer overflows over a fragment boundaries.

The `memory` array is a dump of the original flatten memory with a size `s`.

The last part of the image is an array of function pointer information embedded into the original `memory` array.
```
[u:8B]
[fptr_info:(16+l)*B,...]: u times
```

The single function pointer information has the following format:
```
address:     8B
symbol size: 8B (l)
symbol:      l*B
```

# Image visualization

There is possibility to view the contents of the image file using the `imginfo` tool with the `INFO` option, i.e.:
```
imginfo <path_to_img> INFO
```

It will print the contents of the entire image file with some possibility for exploration. Additional parameter makes it possible to inspect only selected features of the image file, i.e.:
```
imginfo <path_to_img> INFO -r		// prints root pointer information
imginfo <path_to_img> INFO -p		// prints pointer location information
imginfo <path_to_img> INFO -m		// prints memory information
imginfo <path_to_img> INFO -f		// prints information about memory fragments
imginfo <path_to_img> INFO -a		// prints information about function pointer map
```
