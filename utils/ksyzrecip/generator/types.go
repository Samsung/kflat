package generator

import (
	"fmt"
	"strings"
	"strconv"
)

type Aggregate interface {
	Name()   string
	Size()   uint64
	Field()  string
	Offset() uint64
	String() string
}

type AggregateCommon struct {
	name   string
	size   uint64
	field  string
	offset uint64
}

func (a *AggregateCommon) Name() string {
	return a.name
}

func (a *AggregateCommon) Size() uint64 {
	return a.size
}

func (a *AggregateCommon) Field() string {
	return a.field
}

func (a *AggregateCommon) Offset() uint64 {
	return a.offset
}

type RecordAggregate struct {
	AggregateCommon
	Union bool
}

func (r *RecordAggregate) String() string {
	sb := strings.Builder{}

	if r.Union {
		sb.WriteString("AGGREGATE_FLATTEN_UNION_SELF_CONTAINED(")
	} else {
		sb.WriteString("AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(")
	}

	sb.WriteString(r.name)
	sb.WriteString(", ")
	sb.WriteString(strconv.FormatUint(r.size, 10))
	sb.WriteString(", ")
	sb.WriteString(r.field)
	sb.WriteString(", ")
	sb.WriteString(strconv.FormatUint(r.offset, 10))
	sb.WriteString(");")

	return sb.String()
}

type RecordArrayAggregate struct {
	AggregateCommon
	Union     bool
	ArraySize SizeReference
}

func (ra *RecordArrayAggregate) String() string {
	sb := strings.Builder{}

	if ra.Union {
		sb.WriteString("AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_SELF_CONTAINED(")
	} else {
		sb.WriteString("AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE_SELF_CONTAINED(")
	}

	sb.WriteString(ra.name)
	sb.WriteString(", ")
	sb.WriteString(strconv.FormatUint(ra.size, 10))
	sb.WriteString(", ")
	sb.WriteString(ra.field)
	sb.WriteString(", ")
	sb.WriteString(strconv.FormatUint(ra.offset, 10))
	sb.WriteString(", ")
	sb.WriteString(ra.ArraySize.String())
	sb.WriteString(");")

	return sb.String()
}

type BuiltinArrayAggregate struct {
	AggregateCommon
	ArraySize SizeReference
}

func (ba *BuiltinArrayAggregate) String() string {
	sb := strings.Builder{}

	sb.WriteString("AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(")
	sb.WriteString(ba.name)
	sb.WriteString(", ")
	sb.WriteString(ba.field)
	sb.WriteString(", ")
	sb.WriteString(strconv.FormatUint(ba.offset, 10))
	sb.WriteString(", ")
	sb.WriteString(ba.ArraySize.String())
	sb.WriteString(");")

	return sb.String()
}

type SizeReference interface {
	String() string
}

type IntegerSize struct {
	Size uint64
}

func (i *IntegerSize) String() string {
	return strconv.FormatUint(i.Size, 10)
}

type FieldSize struct {
	FieldName string
}

func (f *FieldSize) String() string {
	return fmt.Sprintf("ATTR(%s)", f.FieldName)
}

type Flattener struct {
	Name       string
	Size       uint64
	Aggregates map[string]Aggregate
	Union      bool
}

func (f *Flattener) Declaration() string {
	sb := strings.Builder{}

	if f.Union {
		sb.WriteString("FUNCTION_DECLARE_FLATTEN_UNION(")
	} else {
		sb.WriteString("FUNCTION_DECLARE_FLATTEN_STRUCT(")
	}

	sb.WriteString(f.Name)
	sb.WriteString(");")

	return sb.String()
}

func (f *Flattener) Definition() string {
	sb := strings.Builder{}

	if f.Union {
		sb.WriteString("FUNCTION_DEFINE_FLATTEN_UNION_SELF_CONTAINED(")
	} else {
		sb.WriteString("FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(")
	}

	sb.WriteString(f.Name)
	sb.WriteString(", ")
	sb.WriteString(strconv.FormatUint(f.Size, 10))

	i := int(0)
	for _, aggregate := range f.Aggregates {
		if i == 0 {
			sb.WriteString(",")
		}

		sb.WriteString("\n\t")
		sb.WriteString(aggregate.String())
		sb.WriteString("\n")
		i++
	}

	sb.WriteString(");")

	return sb.String()
}

type IoctlCommand struct {
	Value    uint64
	TypeName string
	TypeSize uint64
}

type Trigger struct {
	Name         string
	Commands     map[int]IoctlCommand
	FunctionName string
	NodePath     string
}

func (t *Trigger) Definition() string {
	sb := strings.Builder{}

	sb.WriteString("static void ")
	sb.WriteString(t.Name)
	sb.WriteString("(struct kflat *kflat, struct probe_regs *regs) {\n")

	sb.WriteString("\tFOR_ROOT_POINTER(&regs->arg2,\n")
	sb.WriteString("\t\tFLATTEN_TYPE(unsigned long, &regs->arg2);\n")
	sb.WriteString("\t);\n")
	sb.WriteString("\n")
	sb.WriteString("\tFOR_USER_ROOT_POINTER(regs->arg3,\n")

	for _, cmd := range t.Commands {
		sb.WriteString("\t\tif (regs->arg2 == ")
		sb.WriteString(strconv.FormatUint(cmd.Value, 10))
		sb.WriteString(") {\n")
		sb.WriteString("\t\t\tFLATTEN_STRUCT_SELF_CONTAINED(")
		sb.WriteString(cmd.TypeName)
		sb.WriteString(", ")
		sb.WriteString(strconv.FormatUint(cmd.TypeSize, 10))
		sb.WriteString(", (void *) regs->arg3);\n")
		sb.WriteString("\t\t}\n")
		sb.WriteString("\n")
	}

	sb.WriteString("\t);\n}")

	return sb.String()
}

func (t *Trigger) Declaration() string {
	return fmt.Sprintf("KFLAT_RECIPE(\"%s\", %s),\n", t.FunctionName, t.Name)
}

func (t *Trigger) addCommand(value uint64, name string, size uint64) {
	t.Commands[int(value)] = IoctlCommand{
		Value:    value,
		TypeName: name,
		TypeSize: size,
	}
}

type Recipe struct {
	Triggers   []*Trigger
	Flatteners []*Flattener
}

func (r *Recipe) String() string {
	sb := strings.Builder{}

	sb.WriteString(`/* autogenerated by ksyzrecip */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"
`)

	for _, flattener := range r.Flatteners {
		sb.WriteString("\n")
		sb.WriteString(flattener.Declaration())
		sb.WriteString("\n")
	}

	for _, flattener := range r.Flatteners {
		sb.WriteString("\n")
		sb.WriteString(flattener.Definition())
		sb.WriteString("\n")
	}

	sb.WriteString("\n")

	for _, trigger := range r.Triggers {
		sb.WriteString(trigger.Definition())
		sb.WriteString("\n\n")
	}

	sb.WriteString("KFLAT_RECIPE_LIST(\n")

	for _, trigger := range r.Triggers {
		sb.WriteString("\t")
		sb.WriteString(trigger.Declaration())
	}

	sb.WriteString(");\n\n")
	sb.WriteString("KFLAT_RECIPE_MODULE(\"Automatically generated kflat module from syzkaller recipes\");\n")

	return sb.String()
}
