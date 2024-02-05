package main

// syzkaller API is very documented... :-)

import (
	"fmt"
	"os"
	"strings"
	"io"
	// "bufio"
	// "flag"
	// "runtime"
	"path/filepath"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/prog"
)

const (
	header string = `/* autogenerated by ksyzrecip (by michal.lach@samsung.com) */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

`
)

type emptyType struct{}

var (
	descFiles []string
	constFiles []string
	descs *ast.Description
	consts map[string]uint64 = make(map[string]uint64)
	paths []string = []string{ "/home/michal.lach/Documents/go/src/github.com/google/syzkaller/sys/models/linux_base", "/home/michal.lach/syzgen/new_out/" }
)

func parseFromList(files []string, eh ast.ErrorHandler) *ast.Description {
	desc := &ast.Description{}
	for _, f := range files {
		buf, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		other := ast.Parse(buf, f, eh)
		if other != nil {
			desc.Nodes = append(desc.Nodes, other.Nodes...)
		}
	}
	return desc
}

func constsFromList(files []string, eh ast.ErrorHandler) map[string]uint64 {
	var out map[string]uint64 = make(map[string]uint64)

	for _, f := range files {
		other := compiler.DeserializeConstFile(f, eh).Arch(targets.ARM64)
		for k, v := range other {
			out[k] = v
		}
	}

	return out
}

func errorHandler(pos ast.Pos, msg string) {
	fmt.Printf("(%s:%d) %s\n", pos.File, pos.Line, msg)
}

func compileErrorHandler(pos ast.Pos, msg string) {
	if strings.HasPrefix(msg, "unsupported syscall") {
		return
	}

	for i, f := range descFiles {
		if pos.File == f {
			fmt.Printf("removing %s because: %s\n", f, msg)
			descFiles = append(descFiles[:i], descFiles[i + 1:]...)
			descs = parseFromList(descFiles, errorHandler)
			consts = constsFromList(constFiles, errorHandler)
		}
	}
}

func shouldQueue(typ prog.Type) bool {
again:
	switch typ.(type) {
	case *prog.StructType:
		return true
		break
	case *prog.UnionType:
		return true
		break
	case *prog.PtrType:
		typ = typ.(*prog.PtrType).Elem
		goto again
	}

	return false
}

func hasPointer(typ prog.Type) bool {
	if record, ok := typ.(*prog.StructType); ok {
		for _, f := range record.Fields {
			if _, ok := f.Type.(*prog.PtrType); ok {
				return true
			}
		}
	} else if union, ok := typ.(*prog.UnionType); ok {
		for _, f := range union.Fields {
			if _, ok := f.Type.(*prog.PtrType); ok {
				return true
			}
		}
	}

	return false
}

func generateRecipes(ioctls []*prog.Syscall) {
	for _, sc := range ioctls {
		derefType, ok := sc.Args[2].Type.(*prog.PtrType)
		if !ok {
			continue
		}

		insideType, ok := derefType.Elem.(*prog.StructType)
		if !ok {
			continue
		}

		types := make(map[prog.Type]struct{})
		typQueue := make([]prog.Type, 1)
		typQueue[0] = insideType
		types[insideType] = struct{}{}

		for len(typQueue) > 0 {
			var iter prog.Type
			typ := typQueue[0]
			iter = typ
			if _, ok := types[typ]; ok {
				typQueue = append(typQueue[:0], typQueue[1:]...)
				continue
			}

			ptr, ok := typ.(*prog.PtrType)
			if ok {
				iter = ptr.Elem
			}

			if record, ok := iter.(*prog.StructType); ok {
				for _, field := range record.Fields {
					if shouldQueue(field.Type) {
						typQueue = append(typQueue, field.Type)
					}
				}

				if hasPointer(record) {
					types[record] = struct{}{}
				}
				typQueue = append(typQueue[:0], typQueue[1:]...)
			} else if union, ok := iter.(*prog.UnionType); ok {
				for _, field := range union.Fields {
					if shouldQueue(field.Type) {
						typQueue = append(typQueue, field.Type)
					}
				}

				if hasPointer(union) {
					types[union] = struct{}{}
				}
				typQueue = append(typQueue[:0], typQueue[1:]...)
			}
		}

		f, err := os.Create(filepath.Join("recipes", fmt.Sprintf("%s.c", strings.TrimPrefix(sc.Name, "ioctl$"))))
		if err != nil {
			return
		}

		f.WriteString(header)
		for k, _ := range types {
			switch k.(type) {
			case *prog.UnionType:
				r := k.(*prog.UnionType)
				f.WriteString(fmt.Sprintf("FUNCTION_DECLARE_FLATTEN_UNION(%s);\n", r.Name()))
				break
			case *prog.StructType:
				r := k.(*prog.StructType)
				f.WriteString(fmt.Sprintf("FUNCTION_DECLARE_FLATTEN_STRUCT(%s);\n", r.Name()))
				break
			}
		}

		f.WriteString("\n")

		for k, _ := range types {
			switch k.(type) {
			case *prog.StructType:
				r := k.(*prog.StructType)
				f.WriteString(fmt.Sprintf("FUNCTION_DEFINE_FLATTEN_STRUCT(%s", r.Name()))
				needExpansion(r, f)
				f.WriteString(");\n")
				break
			case *prog.UnionType:
				r := k.(*prog.UnionType)
				f.WriteString(fmt.Sprintf("FUNCTION_DEFINE_FLATTEN_UNION(%s", r.Name()))
				needExpansion(r, f)
				f.WriteString(");\n")
				break
			}
		}

		fmt.Printf("Collected %d types for %s: %v\n", len(types), sc.Name, types)
	}
}

func needExpansion(t prog.Type, w io.Writer) bool {
	types := make(map[prog.Type]struct{})
	typQueue := make([]prog.Type, 1)
	typQueue[0] = t
	var i int32 = 0

	for len(typQueue) > 0 {
		var iter prog.Type
		typ := typQueue[0]
		iter = typ
		if _, ok := types[typ]; ok {
			typQueue = append(typQueue[:0], typQueue[1:]...)
			continue
		}

		if record, ok := iter.(*prog.StructType); ok {
			for _, field := range record.Fields {
				if ptr, ok := field.Type.(*prog.PtrType); ok {
					if record2, ok := ptr.Elem.(*prog.StructType); ok {
						if i == 0 {
							w.Write([]byte(","))
						}
						w.Write([]byte(fmt.Sprintf("\n\tAGGREGATE_FLATTEN_STRUCT(%s, %s);\n", record2.Name(), field.Name)))
						i += 1
					}
					if union2, ok := ptr.Elem.(*prog.UnionType); ok {
						if i == 0 {
							w.Write([]byte(","))
						}
						w.Write([]byte(fmt.Sprintf("\n\tAGGREGATE_FLATTEN_UNION(%s, %s);\n", union2.Name(), field.Name)))
						i += 1
					}
				}
			}
			typQueue = append(typQueue[:0], typQueue[1:]...)
		} else if union, ok := iter.(*prog.UnionType); ok {
			for _, field := range union.Fields {
				if ptr, ok := field.Type.(*prog.PtrType); ok {
					if record2, ok := ptr.Elem.(*prog.StructType); ok {
						if i == 0 {
							w.Write([]byte(","))
						}
						w.Write([]byte(fmt.Sprintf("\n\tAGGREGATE_FLATTEN_STRUCT(%s, %s);\n", record2.Name(), field.Name)))
						i += 1
					}
					if union2, ok := ptr.Elem.(*prog.UnionType); ok {
						if i == 0 {
							w.Write([]byte(","))
						}
						w.Write([]byte(fmt.Sprintf("\n\tAGGREGATE_FLATTEN_UNION(%s, %s);\n", union2.Name(), field.Name)))
						i += 1
					}
				}
			}
			typQueue = append(typQueue[:0], typQueue[1:]...)
		}
	}

	return false
}

func removeDir(path string) error {
	paths, err := filepath.Glob(path)
	if err != nil {
		return err
	}

	for _, item := range paths {
		err = os.RemoveAll(item)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	_ = os.Mkdir("recipes", 0775)
	existingRecipes, _ := filepath.Glob(filepath.Join("recipes", "*.c"))
	for _, item := range existingRecipes {
		_ = os.RemoveAll(item)
	}

	for _, str := range paths {
		tmp, err := filepath.Glob(filepath.Join(str, "*.txt"))
		if err != nil {
			os.Exit(1)
		}
		descFiles = append(descFiles, tmp...)
	}

	for _, str := range paths {
		tmp, err := filepath.Glob(filepath.Join(str, "*.const"))
		if err != nil {
			os.Exit(1)
		}
		constFiles = append(constFiles, tmp...)
	}

	descs = parseFromList(descFiles, errorHandler)
	consts = constsFromList(constFiles, errorHandler)

	var p *compiler.Prog = nil
	for p == nil {
		p = compiler.Compile(descs, consts, targets.List[targets.Linux][targets.ARM64], compileErrorHandler)
	}

	prog.RestoreLinks(p.Syscalls, p.Resources, p.Types)

	// What about v4l2?
	ioctls := make([]*prog.Syscall, 0)
	for _, sc := range p.Syscalls {
		if !strings.HasPrefix(sc.Name, "ioctl$") || len(sc.Args) < 3 {
			continue
		}

		ioctls = append(ioctls, sc)
	}

	generateRecipes(ioctls)
}
