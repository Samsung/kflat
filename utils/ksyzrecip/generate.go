package main

import (
	"errors"
	"strings"

	"github.com/google/syzkaller/prog"
)

func syzlangTypeToC(typeName string) string {
	switch typeName {
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
		return typeName + "_t"
	}

	// Weird syzlang types
	if strings.Contains(typeName, "[") {
		return "UNKNOWN_TYPE(" + typeName + ")"
	}

	// All other types like unions, structs or enums
	return typeName
}

func shouldQueue(typ prog.Type) (bool, prog.Type, bool) {
	isPointer := false

again:
	switch typ.(type) {
	case *prog.StructType:
		return isPointer, typ, true
	case *prog.UnionType:
		return isPointer, typ, true
	case *prog.ArrayType:
		typ = typ.(*prog.ArrayType).Elem
		isPointer = true
		goto again
	case *prog.PtrType:
		typ = typ.(*prog.PtrType).Elem
		isPointer = true
		goto again
	}

	return isPointer, nil, false
}

func getRecordFields(syzType interface{}) ([]prog.Field, error) {
	switch t := syzType.(type) {
	case *prog.StructType:
		return t.Fields, nil
	case *prog.UnionType:
		return t.Fields, nil
	default:
		break
	}

	return nil, errors.New("not a record type")
}

func deduceDependantTypes(targetType prog.Type) map[string]prog.Type {
	// Map containing every type which should have its own flattening function.
	types := make(map[string]prog.Type)
	traversed := make(map[string]int)
	typQueue := make([]prog.Type, 1)
	typQueue[0] = targetType

	for len(typQueue) > 0 {
		var iter prog.Type
		typ := typQueue[0]
		iter = typ
		typQueue = append(typQueue[:0], typQueue[1:]...)
		if _, ok := types[typ.Name()]; ok {
			val, ok := traversed[typ.TemplateName()]
			if ok && val > 1 {
				continue
			}
		}

		// We don't queue pointers, but the entry might just be a pointer so this is here just in case.
		ptr, ok := typ.(*prog.PtrType)
		if ok {
			iter = ptr.Elem
		}

		// This will iterate only over structs and unions, so all other potentially queued types are for sure discarded by now.
		fields, _ := getRecordFields(iter)
		// We should queue up array elements type
		for _, field := range fields {
			// Queue up only records and if field is a pointer to a record, dereference it and queue it
			pointer, t, ok := shouldQueue(field.Type)
			if ok {
				typQueue = append(typQueue, t)
				if pointer {
					types[t.TemplateName()] = t
				}
			}
		}

		traversed[iter.TemplateName()] += 1
	}

	return types
}

func aggregateFromPointer(subType prog.Type, field string, offset uint64) (Aggregate, bool) {
	switch t := subType.(type) {
	case *prog.StructType:
		aggregate := &RecordAggregate{
			AggregateCommon: AggregateCommon{
				TypeName:    t.TemplateName(),
				TypeSize:    calculateActualSize(t),
				FieldName:   field,
				FieldOffset: offset,
			},

			IsUnion: false,
		}
		return aggregate, true
	case *prog.UnionType:
		aggregate := &RecordAggregate{
			AggregateCommon: AggregateCommon{
				TypeName:    t.TemplateName(),
				TypeSize:    calculateActualSize(t),
				FieldName:   field,
				FieldOffset: offset,
			},

			IsUnion: true,
		}
		return aggregate, true
	}

	return nil, false
}

func createSizable(arg interface{}) Sizable {
	switch t := arg.(type) {
	case uint64:
		size := &IntegerSize{
			Size: t,
		}

		return size
	case string:
		size := &FieldSize{
			FieldName: t,
		}

		return size
	}

	return nil
}

func generateFlatteningFunctions(insideType prog.StructType) ([]*FlatHandler, error) {
	types := deduceDependantTypes(&insideType)

	// Add the root type as well
	types[insideType.Name()] = &insideType
	recipeTypes := make([]*FlatHandler, 0)

	for _, iter := range types {
		fields, err := getRecordFields(iter)
		if err != nil {
			continue
		}

		var fieldOffset uint64 = 0

		flat := &FlatHandler{
			Name: iter.TemplateName(),
			// TODO: Investigate later, hiddev_usage_ref_multi returns size 4124 from syzkaller????
			Size:       calculateActualSize(iter),
			Aggregates: make(map[string]Aggregate),
		}

		for _, field := range fields {
			switch t := field.Type.(type) {
			case *prog.PtrType:
				aggregate, ok := aggregateFromPointer(t.Elem, field.Name, fieldOffset)
				if !ok {
					continue
				}

				flat.Aggregates[field.Name] = aggregate
			case *prog.ArrayType:
				arraySize := &IntegerSize{
					Size: t.RangeBegin,
				}
				common := AggregateCommon{
					TypeName:    syzlangTypeToC(t.Elem.TemplateName()),
					FieldName:   field.Name,
					FieldOffset: fieldOffset,
					TypeSize:    calculateActualSize(t.Elem),
				}

				// TODO: Array of pointers to records should be handled separately
				switch t.Elem.(type) {
				case *prog.StructType:
					flat.Aggregates[field.Name] = &RecordArrayAggregate{
						AggregateCommon: common,
						IsUnion:         false,
						ArraySize:       arraySize,
					}
				case *prog.UnionType:
					flat.Aggregates[field.Name] = &RecordArrayAggregate{
						AggregateCommon: common,
						IsUnion:         true,
						ArraySize:       arraySize,
					}
				default:
					flat.Aggregates[field.Name] = &BuiltinArrayAggregate{
						AggregateCommon: common,
						ArraySize:       arraySize,
					}
				}
			case *prog.BufferType:
				if t.Kind != prog.BufferString || t.TypeName != "string" {
					continue
				}

				min := len(t.Values[0])
				for _, value := range t.Values {
					if min > len(value) {
						min = len(value)
					}
				}

				common := &AggregateCommon{
					TypeName:    "char",
					FieldName:   field.Name,
					FieldOffset: fieldOffset,
					TypeSize:    1,
				}

				flat.Aggregates[field.Name] = &BuiltinArrayAggregate{
					AggregateCommon: *common,
					ArraySize:       createSizable(uint64(min)),
				}
			}

			fieldOffset += calculateActualSize(field.Type)
		}

		// syzlang specifications says len[] it can point to a
		// field in a child of current parent record.
		// As of 8.04.23, this does not happen in base syzkaller recipes
		// However, some descriptions use len to refer to its parent.
		// I don't really know how to express that in terms of KFLAT recipes
		// so I don't have an idea how to implement this feature.
		// Here we are considering lengths only on sibling fields.
		for _, field := range fields {
			t, ok := field.Type.(*prog.LenType)
			if !ok || len(t.Path) != 1 || t.Path[0] == "parent" {
				continue
			}

			// t.BitSize == 0 is len[] (if len's argument is a pointer, turn it into array)
			// t.BitSize == 8 is bytesize[] (
			// t.BitSizeN == 8 * N is bytesizeN[] (for N byte words)
			// !(t.BitSize % 8) is bitsize[]

			aggregate, ok := flat.Aggregates[t.Path[0]]
			if t.BitSize != 0 || !ok {
				continue
			}

			lengthWrapper := &FieldSize{
				FieldName: field.Name,
			}

			common := &AggregateCommon{
				TypeName:    aggregate.Name(),
				FieldName:   aggregate.Field(),
				FieldOffset: aggregate.Offset(),
				TypeSize:    aggregate.Size(),
			}

			switch aggregate := aggregate.(type) {
			case *RecordArrayAggregate:
				flat.Aggregates[t.Path[0]] = &RecordArrayAggregate{
					AggregateCommon: *common,
					IsUnion:         aggregate.IsUnion,
					ArraySize:       lengthWrapper,
				}
			case *BuiltinArrayAggregate:
				flat.Aggregates[t.Path[0]] = &BuiltinArrayAggregate{
					AggregateCommon: *common,
					ArraySize:       lengthWrapper,
				}
			}
		}

		recipeTypes = append(recipeTypes, flat)
	}

	return recipeTypes, nil
}

func calculateActualSize(typ prog.Type) uint64 {
	var size uint64 = 0

	if typ.Varlen() {
		fields, _ := getRecordFields(typ)
		for _, field := range fields {
			size += calculateActualSize(field.Type)
		}
	} else {
		size = typ.Size()
	}

	return size
}
