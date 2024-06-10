package main

import (
	"fmt"
	"strings"
)

type Aggregate interface {
	Name() string
	Size() Sizable
	Field() string
	Offset() uint64
	Specification() string
}

type AggregateCommon struct {
	TypeName    string
	TypeSize    Sizable
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

func (p *RecordAggregate) Size() Sizable {
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
		return fmt.Sprintf("AGGREGATE_FLATTEN_UNION_SELF_CONTAINED(%s, %s, %s, %d);", p.TypeName, p.TypeSize.Specification(), p.FieldName, p.FieldOffset)
	}

	return fmt.Sprintf("AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(%s, %s, %s, %d);", p.TypeName, p.TypeSize.Specification(), p.FieldName, p.FieldOffset)
}

type ArrayAggregate interface {
	Aggregate
}

type RecordArrayAggregate struct {
	AggregateCommon
	IsUnion bool
}

func (p *RecordArrayAggregate) Name() string {
	return p.TypeName
}

func (p *RecordArrayAggregate) Size() Sizable {
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
		return fmt.Sprintf("AGGREGATE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(%s, %s, %s, %d, %d);", p.TypeName, p.TypeSize.Specification(), p.FieldName, p.FieldOffset, 1)
	}

	return fmt.Sprintf("AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(%s, %s, %s, %d, %d);", p.TypeName, p.TypeSize.Specification(), p.FieldName, p.FieldOffset, 1)
}

type BuiltinArrayAggregate struct {
	AggregateCommon
}

func (p *BuiltinArrayAggregate) Name() string {
	return p.TypeName
}

func (p *BuiltinArrayAggregate) Size() Sizable {
	return p.TypeSize
}

func (p *BuiltinArrayAggregate) Field() string {
	return p.FieldName
}

func (p *BuiltinArrayAggregate) Offset() uint64 {
	return p.FieldOffset
}

func (p *BuiltinArrayAggregate) Specification() string {
	return fmt.Sprintf("AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(%s, %s, %d, %s);", p.TypeName, p.FieldName, p.FieldOffset, p.TypeSize.Specification())
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
