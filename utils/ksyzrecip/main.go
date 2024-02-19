package main

// syzkaller API is very documented... :-)

import (
	"fmt"
	"os"
	"strings"
	"io"
	// "reflect"
	// "bufio"
	// "flag"
	// "runtime"
	"path/filepath"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/prog"
)

type RecordKind uint

type emptyType struct{}

type StructType struct {
	*prog.StructType
}

type UnionType struct {
	*prog.UnionType
}

type RecordType interface {
	RecordFields() []prog.Field
}

func (s *StructType) RecordFields() []prog.Field {
	return s.Fields
}

func (s *UnionType) RecordFields() []prog.Field {
	return s.Fields
}

const (
	header string = `/* autogenerated by ksyzrecip (by michal.lach@samsung.com) */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

`
	KIND_UNION RecordKind = iota
	KIND_STRUCT
)

var (
	descFiles []string
	constFiles []string
	descs *ast.Description
	consts map[string]uint64 = make(map[string]uint64)
	// paths []string = []string{ "/home/michal.lach/Documents/go/src/github.com/google/syzkaller/sys/models/linux_base", "/home/michal.lach/syzgen/new_out/" }
	paths []string = []string{ "/home/michal.lach/Documents/go/src/github.com/google/syzkaller/sys/linux" }
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

func shouldQueue(typ prog.Type) (bool, prog.Type) {
again:
	switch typ.(type) {
	case *prog.StructType:
		return true, typ
		break
	case *prog.UnionType:
		return true, typ
		break
	case *prog.PtrType:
		typ = typ.(*prog.PtrType).Elem
		goto again
	}

	return false, nil
}

func recordMap(typ prog.Type, fn func(RecordType, RecordKind)) {
	switch typ.(type) {
	case *StructType:
		record := typ.(*StructType)
		fn(record, KIND_STRUCT)
		break;
	case *UnionType:
		record := typ.(*UnionType)
		fn(record, KIND_UNION)
		break;
	case *prog.StructType:
		base := typ.(*prog.StructType)
		record := &StructType{base}
		fn(record, KIND_STRUCT)
		break
	case *prog.UnionType:
		base := typ.(*prog.UnionType)
		record := &UnionType{base}
		fn(record, KIND_UNION)
		break
	default:
		break
	}
}

func toProgType(typ RecordType) prog.Type {
	switch typ.(type) {
	case *StructType:
		base := typ.(*StructType)
		return base
	case *UnionType:
		base := typ.(*UnionType)
		return base
	default:
		break
	}

	return nil
}

func hasPointer(typ prog.Type) ([]prog.Type, bool) {
	types := make([]prog.Type, 0)
	recordMap(typ, func(t RecordType, k RecordKind) {
		for _, f := range t.RecordFields() {
			ptr, ok := f.Type.(*prog.PtrType)
			if !ok {
				continue
			}
			recordMap(ptr.Elem, func (tt RecordType, kk RecordKind) {
				types = append(types, toProgType(tt))
			})
		}
	})

	if len(types) > 0 {
		return types, true
	}

	return types, false
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

		// Map containing every type which should have its own flattening function.
		types := make(map[string]prog.Type)
		typQueue := make([]prog.Type, 1)
		typQueue[0] = insideType

		for len(typQueue) > 0 {
			var iter prog.Type
			typ := typQueue[0]
			iter = typ
			typQueue = append(typQueue[:0], typQueue[1:]...)
			if _, ok := types[typ.Name()]; ok {
				continue
			}

			// We don't queue pointers, but the entry might just be a pointer so this is here just in case.
			ptr, ok := typ.(*prog.PtrType)
			if ok {
				iter = ptr.Elem
			}

			// We should track also string types.
			// This function will iterate only over structs and unions, so all other potentially queued types are for sure discarded by now.
			recordMap(iter, func(typ RecordType, _ RecordKind) {
				for _, field := range typ.RecordFields() {
					// Queue up only records and if field is a pointer to a record, dereference it and queue it
					ok, t := shouldQueue(field.Type)
					if ok {
						typQueue = append(typQueue, t)
					}
				}
			})

			if t, ok := hasPointer(typ); ok {
				for _, typp := range t {
					types[typp.Name()] = typp
				}
			}
		}

		// Add the root type
		types[insideType.Name()] = insideType
		fmt.Printf("Collected %d types for %s: %v\n", len(types), sc.Name, types)

		f, err := os.Create(filepath.Join("recipes", fmt.Sprintf("%s.c", strings.TrimPrefix(sc.Name, "ioctl$"))))
		if err != nil {
			return
		}

		f.WriteString(header)
		for _, k := range types {
			recordMap(k, func(typ RecordType, kind RecordKind) {
				var formatStr string
				switch kind {
				case KIND_UNION:
					formatStr = "FUNCTION_DECLARE_FLATTEN_UNION(%s);\n"
					break;
				case KIND_STRUCT:
					formatStr = "FUNCTION_DECLARE_FLATTEN_STRUCT(%s);\n"
					break;
				}
				f.WriteString(fmt.Sprintf(formatStr, k.TemplateName()))
			})
		}

		f.WriteString("\n")

		for _, k := range types {
			recordMap(k, func(typ RecordType, kind RecordKind) {
				var formatStr string
				switch kind {
				case KIND_UNION:
					formatStr = "FUNCTION_DEFINE_FLATTEN_UNION_SELF_CONTAINED(%s, %d"
					break;
				case KIND_STRUCT:
					formatStr = "FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(%s, %d"
					break;
				}
				f.WriteString(fmt.Sprintf(formatStr, k.TemplateName(), calculateActualSize(k)))
				needExpansion(k, f)
				f.WriteString(");\n\n")
			})
		}
	}
}

func calculateActualSize(typ prog.Type) uint64 {
	if typ.Varlen() {
		var size uint64 = 0
		recordMap(typ, func(rec RecordType, _ RecordKind) {
			for _, field := range rec.RecordFields() {
				size += calculateActualSize(field.Type)
			}
		})

		return size
	}

	return typ.Size()
}

func needExpansion(t prog.Type, w io.Writer) {
	types := make(map[string]prog.Type)
	typQueue := make([]prog.Type, 1)
	typQueue[0] = t
	var i int32 = 0

	for len(typQueue) > 0 {
		var iter prog.Type
		typ := typQueue[0]
		iter = typ
		typQueue = append(typQueue[:0], typQueue[1:]...)
		if _, ok := types[typ.Name()]; ok {
			continue
		}

		recordMap(iter, func (typ RecordType, kind RecordKind) {
			var fieldOffset uint64 = 0
			for _, field := range typ.RecordFields() {
				ptr, ok := field.Type.(*prog.PtrType)
				if !ok {
					typQueue = append(typQueue, field.Type)
					fieldOffset += calculateActualSize(field.Type)
					continue
				}

				recordMap(ptr.Elem, func (typ2 RecordType, kind2 RecordKind) {
					var formatString string
					switch kind {
					case KIND_STRUCT:
						formatString = "\n\tAGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(%s, %d, %s, %d);"
						break
					case KIND_UNION:
						formatString = "\n\tAGGREGATE_FLATTEN_UNION_SELF_CONTAINED(%s, %d, %s, %d);"
						break;
					}

					if i == 0 {
						w.Write([]byte(","))
					}

					w.Write([]byte(fmt.Sprintf(formatString, toProgType(typ2).TemplateName(), calculateActualSize(toProgType(typ2)), field.Name, fieldOffset)))
					i += 1
				})
				fieldOffset += calculateActualSize(field.Type)
			}
		})
	}
	w.Write([]byte("\n"))
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
	// Should get ARM64 syscall numbers dynamically, there was a function in syzkaller API for that
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

	// We should generate recipes on per type basis rather than on per ioctl() command basis
	// This creates too much redundant recipes.
	generateRecipes(ioctls)
}
