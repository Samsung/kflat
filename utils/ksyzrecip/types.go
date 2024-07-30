package main

import (
	"fmt"
	"strings"
)

type Aggregate interface {
	Name() string
	Size() uint64
	Field() string
	Offset() uint64
	Specification() string
}

type AggregateCommon struct {
	TypeName    string
	TypeSize    uint64
	FieldName   string
	FieldOffset uint64
}

type RecordAggregate struct {
	AggregateCommon
	IsUnion bool
}

func (p *RecordAggregate) Name() string {
	return p.TypeName
}

func (p *RecordAggregate) Size() uint64 {
	return p.TypeSize
}

func (p *RecordAggregate) Field() string {
	return p.FieldName
}

func (p *RecordAggregate) Offset() uint64 {
	return p.FieldOffset
}

func (p *RecordAggregate) Specification() string {
	if p.IsUnion {
		return fmt.Sprintf("AGGREGATE_FLATTEN_UNION_SELF_CONTAINED(%s, %d, %s, %d);", p.TypeName, p.TypeSize, p.FieldName, p.FieldOffset)
	}

	return fmt.Sprintf("AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(%s, %d, %s, %d);", p.TypeName, p.TypeSize, p.FieldName, p.FieldOffset)
}

type ArrayAggregate interface {
	Aggregate
	Elements() Sizable
}

type RecordArrayAggregate struct {
	AggregateCommon
	IsUnion   bool
	ArraySize Sizable
}

func (p *RecordArrayAggregate) Name() string {
	return p.TypeName
}

func (p *RecordArrayAggregate) Size() uint64 {
	return p.TypeSize
}

func (p *RecordArrayAggregate) Field() string {
	return p.FieldName
}

func (p *RecordArrayAggregate) Offset() uint64 {
	return p.FieldOffset
}

func (p *RecordArrayAggregate) Specification() string {
	if p.IsUnion {
		return fmt.Sprintf("AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_SELF_CONTAINED(%s, %d, %s, %d, %s);", p.TypeName, p.TypeSize, p.FieldName, p.FieldOffset, p.ArraySize.Specification())
	}

	return fmt.Sprintf("AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE_SELF_CONTAINED(%s, %d, %s, %d, %s);", p.TypeName, p.TypeSize, p.FieldName, p.FieldOffset, p.ArraySize.Specification())
}

type BuiltinArrayAggregate struct {
	AggregateCommon
	ArraySize Sizable
}

func (p *BuiltinArrayAggregate) Name() string {
	return p.TypeName
}

func (p *BuiltinArrayAggregate) Size() uint64 {
	return p.TypeSize
}

func (p *BuiltinArrayAggregate) Field() string {
	return p.FieldName
}

func (p *BuiltinArrayAggregate) Offset() uint64 {
	return p.FieldOffset
}

func (p *BuiltinArrayAggregate) Specification() string {
	return fmt.Sprintf("AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(%s, %s, %d, %s);", p.TypeName, p.FieldName, p.FieldOffset, p.ArraySize.Specification())
}

type Sizable interface {
	Specification() string
}

type IntegerSize struct {
	Size uint64
}

func (p *IntegerSize) Specification() string {
	return fmt.Sprintf("%d", p.Size)
}

type FieldSize struct {
	FieldName string
}

func (p *FieldSize) Specification() string {
	return fmt.Sprintf("ATTR(%s)", p.FieldName)
}

type FlatHandler struct {
	Name       string
	Size       uint64
	Aggregates map[string]Aggregate
	IsUnion    bool
}

func (p *FlatHandler) Declaration() string {
	if p.IsUnion {
		return fmt.Sprintf("FUNCTION_DECLARE_FLATTEN_UNION(%s);", p.Name)
	}

	return fmt.Sprintf("FUNCTION_DECLARE_FLATTEN_STRUCT(%s);", p.Name)
}

func (p *FlatHandler) Definition() string {
	var sb strings.Builder

	if p.IsUnion {
		sb.WriteString(fmt.Sprintf("FUNCTION_DEFINE_FLATTEN_UNION_SELF_CONTAINED(%s, %d", p.Name, p.Size))
	} else {
		sb.WriteString(fmt.Sprintf("FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(%s, %d", p.Name, p.Size))
	}

	var i int = 0
	for _, aggregate := range p.Aggregates {
		if i == 0 {
			sb.WriteString(",")
		}

		sb.WriteString("\n\t" + aggregate.Specification() + "\n")
		i++
	}

	sb.WriteString(");")

	return sb.String()
}

type TriggerFunction struct {
	Name               string
	FlattenedType      string
	FlattenedSize      uint64
	TargetFunctionName string
	NodePath           string
}

func (p *TriggerFunction) Definition() string {
	return fmt.Sprintf(`static void %s(struct kflat *kflat, struct probe_regs *regs) {
	FOR_USER_ROOT_POINTER(regs->arg3,
		FLATTEN_STRUCT_SELF_CONTAINED(%s, %d, (void *) regs->arg3);
	);
}`, p.Name, p.FlattenedType, p.FlattenedSize)
}

func (p *TriggerFunction) Declaration() string {
	return fmt.Sprintf("KFLAT_RECIPE(\"%s\", %s),\n", p.TargetFunctionName, p.Name)
}