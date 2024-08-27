package generator

import (
	"errors"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/sys/targets"
)

type Generator struct {
	descriptionFiles []string
	constantFiles []string

	syscalls []*prog.Syscall
	constants map[string]uint64
	descriptions *ast.Description
	arch string

	foka map[string]FokaEntry

	usedFlatteners map[string]struct{}
	usedTriggers []string

	fds map[string][]string
	syscall2Paths map[string][]string

	DiscardedDescriptions []string
	Flatteners map[string]*Flattener
	Triggers map[string]*Trigger
}

type FokaEntry struct {
	Read              []string `json:"read"`
	ReadBranch        []string `json:"read_branch"`
	Write             []string `json:"write"`
	WriteBranch       []string `json:"write_branch"`
	Mmap              []string `json:"mmap"`
	MmapBranch        []string `json:"mmap_branch"`
	Ioctl             []string `json:"ioctl"`
	IoctlBranch       []string `json:"ioctl_branch"`
	IoctlCompat       []string `json:"ioctl_c"`
	IoctlCompatBranch []string `json:"ioctl_c_branch"`
	Permissions       string   `json:"perm"`
	Owner             string   `json:"user"`
	Group             string   `json:"group"`
}

func unmarshalFoka(path string) (map[string]FokaEntry, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var foka map[string]FokaEntry = nil
	err = json.Unmarshal(file, &foka)
	if err != nil {
		return nil, err
	}

	return foka, nil
}

func globFileSet(paths []string, glob string) []string {
	var files []string = nil

	for _, path := range paths {
		globbed, err := filepath.Glob(filepath.Join(path, glob))
		if err != nil {
			return make([]string, 0, 0)
		}

		files = append(files, globbed...)
	}

	return files
}

func (g *Generator) compileSyscalls() error {
	for _, file := range g.constantFiles {
		parsed := compiler.DeserializeConstFile(file, func (_ ast.Pos, _ string) {}).Arch(g.arch)
		for k, v := range parsed {
			g.constants[k] = v
		}
	}

	var p *compiler.Prog
	errorFile := ""

	for p == nil {
		// Remove file which caused the last error
		if errorFile != "" {
			for i, f := range g.descriptionFiles {
				if errorFile == f {
					g.descriptionFiles = append(g.descriptionFiles[:i], g.descriptionFiles[i+1:]...)
				}
			}

			g.DiscardedDescriptions = append(g.DiscardedDescriptions , errorFile)
			errorFile = ""
			g.descriptions = &ast.Description{}
		}

		for _, file := range g.descriptionFiles {
			buf, err := os.ReadFile(file)
			if err != nil {
				return err
			}

			parsed := ast.Parse(buf, file, func(_ ast.Pos, _ string) {})
			if parsed != nil {
				g.descriptions.Nodes = append(g.descriptions.Nodes, parsed.Nodes...)
			}
		}

		if len(g.constants) <= 0 || g.descriptions == nil {
			return errors.New("neither descriptions nor constants got parsed")
		}

		p = compiler.Compile(g.descriptions, g.constants, targets.List[targets.Linux][g.arch], func(pos ast.Pos, _ string) {
			errorFile = pos.File
		})
	}

	prog.RestoreLinks(p.Syscalls, p.Resources, p.Types)

	g.syscalls = p.Syscalls

	return nil
}

func (g *Generator) reversePathsToSyscalls() error {
	for _, syscall := range g.syscalls {
		if syscall.CallName != "openat" {
			continue
		}

		name := syscall.Ret.Name()
		ptr, ok := syscall.Args[1].Type.(*prog.PtrType)
		if !ok {
			return errors.New("argument at path position 1 is not a pointer in openat")
		}

		buf, ok := ptr.Elem.(*prog.BufferType)
		if !ok {
			return errors.New("pointee type is not a buffer in openat")
		}

		// Too generic of a name, we don't want to collide with more sensible stuff
		if name == "fd" {
			continue
		}

		g.fds[name] = buf.Values
	}

	for _, syscall := range g.syscalls {
		if syscall.CallName != "ioctl" {
			continue
		}

		fd := syscall.Args[0].Type.Name()
		if _, ok := g.fds[fd]; ok {
			g.syscall2Paths[syscall.Name] = g.fds[fd]
		}
	}

	return nil
}

func sumTypeSize(typ prog.Type) uint64 {
	var size uint64 = 0

	if typ.Varlen() {
		fields := getRecordFields(typ)
		for _, field := range fields {
			size += sumTypeSize(field.Type)
		}
	} else {
		size = typ.Size()
	}

	return size
}

func (g *Generator) generate() {
	for _, syscall := range g.syscalls {
		// For some reason Args can be less than 3...
		if syscall.CallName != "ioctl" || len(syscall.Args) < 3 {
			continue
		}

		cmd, ok := syscall.Args[1].Type.(*prog.ConstType)
		if !ok {
			continue
		}

		arg, ok := syscall.Args[2].Type.(*prog.PtrType)
		if !ok {
			continue
		}

		pointee, ok := arg.Elem.(*prog.StructType)
		if !ok {
			continue
		}

		deps := g.findDependencies(pointee)
		deps[pointee.Name()] = pointee

		for _, t := range deps {
			flat := g.generateFlattener(t)
			if flat == nil {
				continue
			}

			g.Flatteners[flat.Name] = flat
		}

		path, err := g.nodePath(syscall.Name)
		if err != nil {
			// Maybe do something more?
			continue
		}

		name, err := g.fokaName(path)
		if err != nil {
			continue
		}

		trigger, ok := g.Triggers[name]
		if !ok {
			g.Triggers[name] = g.makeTrigger(name, path)
			trigger = g.Triggers[name]
		}

		trigger.addCommand(cmd.Val, pointee.TemplateName(), sumTypeSize(pointee))
	}
}

func (g *Generator) makeTrigger(name, path string) *Trigger {
	return &Trigger{
		Name:         "syz_trigger_" + name,
		FunctionName: name,
		NodePath:     path,
		Commands:     make(map[int]IoctlCommand),
	}
}

func (g *Generator) nodePath(name string) (string, error) {
	paths, ok := g.syscall2Paths[name]
	if !ok {
		return "", errors.New("")
	}

	path := paths[len(paths) - 1]
	if path[len(path) - 1] == '\x00' {
		path = path[:len(path) - 1]
	}

	return path, nil
}

func (g *Generator) fokaName(path string) (string, error) {
	ioctls := g.foka[path].Ioctl
	if len(ioctls) <= 0 {
		return "", errors.New("")
	}

	return stripName(ioctls[len(ioctls) - 1]), nil
}

func (g *Generator) generateFlattener(t prog.Type) *Flattener {
	shouldAggregate := func (t prog.Type) bool {
		if ptr, ok := t.(*prog.PtrType); ok {
			if _, ok := ptr.Elem.(*prog.StructType); ok {
				return true
			} else if _, ok := ptr.Elem.(*prog.UnionType); ok {
				return true
			}
		} else if _, ok := t.(*prog.ArrayType); ok {
			return true
		} else if buf, ok := t.(*prog.BufferType); ok {
			if buf.Kind == prog.BufferString && buf.TypeName == "string" {
				return true
			}
		}

		return false
	}

	shouldLenReplace := func (t prog.Type) bool {
		if l, ok := t.(*prog.LenType); ok {
			if len(l.Path) == 1 && l.Path[0] != "parent" && l.BitSize == 0 {
				return true
			}
		}

		return false
	}

	if _, ok := g.usedFlatteners[t.TemplateName()]; ok {
		return nil
	}

	fields := getRecordFields(t)
	if fields == nil {
		return nil
	}

	offset := uint64(0)
	flattener := &Flattener{
		Name:       t.TemplateName(),
		Size:       sumTypeSize(t),
		Aggregates: make(map[string]Aggregate),
	}

	for _, field := range fields {
		if !shouldAggregate(field.Type) {
			continue
		}

		flattener.Aggregates[field.Name] = g.generateAggregate(field.Type, field.Name, offset)
		offset += sumTypeSize(field.Type)
	}

	for _, field := range fields {
		if !shouldLenReplace(field.Type) {
			continue
		}

		l := field.Type.(*prog.LenType)

		aggregate, ok := flattener.Aggregates[l.Path[0]]
		if !ok {
			continue
		}

		flattener.Aggregates[l.Path[0]] = g.lengthAggregate(aggregate, field.Name)
	}

	return flattener
}

func (g *Generator) lengthAggregate(a Aggregate, field string) Aggregate {
	size := &FieldSize{
		FieldName: field,
	}
	common := AggregateCommon{
		name:   a.Name(),
		field:  a.Field(),
		offset: a.Offset(),
		size:   a.Size(),
	}


	if ra, ok := a.(*RecordArrayAggregate); ok {
		return &RecordArrayAggregate{
			AggregateCommon: common,
			Union:           ra.Union,
			ArraySize:       size,
		}
	}

	return &BuiltinArrayAggregate{
		AggregateCommon: common,
		ArraySize:       size,
	}
}

func (g *Generator) translate(name string) string {
	switch name {
	case "intptr":
		fallthrough
	case "int8":
		fallthrough
	case "int16":
		fallthrough
	case "int32":
		fallthrough
	case "int64":
		fallthrough
	case "uint8":
		fallthrough
	case "uint16":
		fallthrough
	case "uint32":
		fallthrough
	case "uint64":
		return name + "_t"
	}

	// Weird syzlang types
	if strings.Contains(name, "[") {
		return "UNKNOWN_TYPE(" + name + ")"
	}

	// All other types like unions, structs or enums
	return name
}

func (g *Generator) pointerAggregate(p *prog.PtrType, field string, offset uint64) Aggregate {
	union := false
	aggregate := &RecordAggregate{
		AggregateCommon: AggregateCommon{
			name:    p.Elem.TemplateName(),
			size:    sumTypeSize(p.Elem),
			field:   field,
			offset:  offset,
		},
	}

	if _, ok := p.Elem.(*prog.UnionType); ok {
		union = true
	}

	aggregate.Union = union

	return aggregate
}

func (g *Generator) arrayAggregate(a *prog.ArrayType, field string, offset uint64) Aggregate {
	size := &IntegerSize{
		Size: a.RangeBegin,
	}
	common := AggregateCommon{
		name:    g.translate(a.Elem.TemplateName()),
		field:   field,
		offset:  offset,
		size:    sumTypeSize(a.Elem),
	}

	if _, ok := a.Elem.(*prog.StructType); ok {
		return &RecordArrayAggregate{
			AggregateCommon: common,
			Union:           false,
			ArraySize:       size,
		}
	} else if _, ok := a.Elem.(*prog.UnionType); ok {
		return &RecordArrayAggregate{
			AggregateCommon: common,
			Union:           true,
			ArraySize:       size,
		}
	}

	return &BuiltinArrayAggregate{
		AggregateCommon: common,
		ArraySize:       size,
	}
}

func (g *Generator) bufferAggregate (b *prog.BufferType, field string, offset uint64) Aggregate {
	size := len(b.Values[0])
	for _, value := range b.Values {
		if size > len(value) {
			size = len(value)
		}
	}

	common := AggregateCommon{
		name:   "char",
		field:  field,
		offset: offset,
		size:   1,
	}

	return &BuiltinArrayAggregate{
		AggregateCommon: common,
		ArraySize:       &IntegerSize{
			Size: uint64(size),
		},
	}
}

func (g *Generator) generateAggregate(t prog.Type, field string, offset uint64) Aggregate {
	if p, ok := t.(*prog.PtrType); ok {
		return g.pointerAggregate(p, field, offset)
	} else if a, ok := t.(*prog.ArrayType); ok {
		return g.arrayAggregate(a, field, offset)
	} else if b, ok := t.(*prog.BufferType); ok {
		return g.bufferAggregate(b, field, offset)
	}

	return nil
}

func getRecordFields(t prog.Type) []prog.Field {
	if s, ok := t.(*prog.StructType); ok {
		return s.Fields
	} else if u, ok := t.(*prog.UnionType); ok {
		return u.Fields
	}

	return nil
}

// Finds dependencies recursively for type t
func (g *Generator) findDependencies(t prog.Type) map[string]prog.Type {
	deps := make(map[string]prog.Type)
	traversed := make(map[string]int)
	queue := []prog.Type{t} // Queue for recursive type traversal

	shouldQueue := func (typ prog.Type) (prog.Type, bool, bool) {
		isPointer := false
again:
		switch typ.(type) {
		case *prog.StructType:
			return typ, true, isPointer
		case *prog.UnionType:
			return typ, true, isPointer
		case *prog.ArrayType:
			typ = typ.(*prog.ArrayType).Elem
			isPointer = true
			goto again
		case *prog.PtrType:
			typ = typ.(*prog.PtrType).Elem
			isPointer = true
			goto again
		}

		return nil, false, isPointer
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = append(queue[:0], queue[1:]...)
		if _, ok := deps[current.TemplateName()]; ok {
			val, ok := traversed[current.TemplateName()]
			if ok && val > 1 {
				continue
			}
		}

		// We don't queue pointers, but the entry might just be a pointer so this is here just in case.
		ptr, ok := current.(*prog.PtrType)
		if ok {
			current = ptr.Elem
		}

		fields := getRecordFields(current)
		for _, field := range fields {
			typ, ok, isPtr := shouldQueue(field.Type)
			if ok {
				queue = append(queue, typ)
				if isPtr {
					deps[typ.TemplateName()] = typ
				}
			}
		}

		traversed[current.TemplateName()] += 1
	}

	return deps
}

func (g *Generator) Recipe() *Recipe {
	recipe := &Recipe{}

	for _, flattener := range g.Flatteners {
		recipe.Flatteners = append(recipe.Flatteners, flattener)
	}

	for _, trigger := range g.Triggers {
		recipe.Triggers = append(recipe.Triggers, trigger)
	}

	return recipe
}

func Generate(descriptionPaths []string, arch string, fokaPath string) (*Generator, error) {
	foka, err := unmarshalFoka(fokaPath)
	if err != nil {
		return nil, err
	}

	generator := &Generator{
		descriptionFiles: globFileSet(descriptionPaths, "*.txt"),
		constantFiles:    globFileSet(descriptionPaths, "*.const"),
		arch:             arch,
		foka:             foka,
		constants:        make(map[string]uint64),
		descriptions:     &ast.Description{},
		usedFlatteners:   make(map[string]struct{}),
		fds:              make(map[string][]string),
		syscall2Paths:    make(map[string][]string),
		Flatteners:       make(map[string]*Flattener),
		Triggers:         make(map[string]*Trigger),
	}

	err = generator.compileSyscalls()
	if err != nil {
		return generator, err
	}

	err = generator.reversePathsToSyscalls()
	if err != nil {
		return generator, err
	}

	generator.generate()

	return generator, nil
}

func stripName(name string) string {
	if strings.Contains(name, " [") {
		return strings.Split(name, " [")[0]
	} else if strings.Contains(name, ".cfi_jt") {
		return strings.Split(name, ".cfi_jt")[0]
	}

	return name
}
