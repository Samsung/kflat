#!/bin/bash
# Utility script that marks all rb_tree-related functions in libunflatten as local 
# in order to avoid linking issues (when running KFLAT + AOT).
# Outputs libunflatten_aot.a

if [ $# -ne 1 ]; then
    echo "Usage: $0 <path_to_cmake_build_dir>"
    exit 1
fi

BINARY_DIR=$1
UNFLATTEN_O_PATH=$BINARY_DIR/lib/CMakeFiles/unflatten_obj.dir/unflatten.cpp.o
RBTREE_O_PATH=$BINARY_DIR/lib/CMakeFiles/unflatten_obj.dir/rbtree.c.o
OUT_O=$BINARY_DIR/lib/CMakeFiles/unflatten_obj.dir/unflatten_combined.o
UNFLATTEN_LIB_OUT=$BINARY_DIR/lib/libunflatten_aot.a

if [ ! -f $UNFLATTEN_O_PATH ] || [ ! -f $RBTREE_O_PATH ]; then
    echo "You need to build kflat's \"unflatten\" target first."
    exit 1
fi

# Combine unflatten.cpp.o and rbtree.c.o into one object file
ld -r -o $OUT_O $UNFLATTEN_O_PATH $RBTREE_O_PATH

# Extract all rbtree related symbols...
SYMS_TO_LOCALIZE=$(nm -A $OUT_O | grep rb_ | grep -v _Z | cut -d ' ' -f 3)
# ... and mark them as local
for sym in ${SYMS_TO_LOCALIZE[@]}; do
    objcopy --localize-symbol=$sym $OUT_O
done

ar -rcs $UNFLATTEN_LIB_OUT $OUT_O 
