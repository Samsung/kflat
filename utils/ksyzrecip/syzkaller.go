package main

import (
	"errors"
	"os"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func tryCompileFromPaths(descriptionFiles []string, constantFiles []string, arch string) ([]*prog.ResourceDesc, []*prog.Syscall, []prog.Type, error) {
	constants := make(map[string]uint64)

	for _, file := range constantFiles {
		constantContent := compiler.DeserializeConstFile(file, func(_ ast.Pos, _ string) {}).Arch(arch)
		for k, v := range constantContent {
			constants[k] = v
		}
	}

	var p *compiler.Prog = nil
	descriptions := &ast.Description{}
	errorFile := ""

	for p == nil {
		// Remove file which caused the last error
		if errorFile != "" {
			for i, f := range descriptionFiles {
				if errorFile == f {
					descriptionFiles = append(descriptionFiles[:i], descriptionFiles[i+1:]...)
				}
			}

			errorFile = ""
			descriptions = &ast.Description{}
		}

		for _, f := range descriptionFiles {
			buf, err := os.ReadFile(f)
			if err != nil {
				return nil, nil, nil, err
			}

			parsed := ast.Parse(buf, f, func(_ ast.Pos, _ string) {})
			if parsed != nil {
				descriptions.Nodes = append(descriptions.Nodes, parsed.Nodes...)
			}
		}

		if len(constants) <= 0 || descriptions == nil {
			return nil, nil, nil, errors.New("Neither descriptions nor constants got parsed")
		}

		p = compiler.Compile(descriptions, constants, targets.List[targets.Linux][arch], func(pos ast.Pos, _ string) {
			errorFile = pos.File
		})
	}

	prog.RestoreLinks(p.Syscalls, p.Resources, p.Types)

	return p.Resources, p.Syscalls, p.Types, nil
}
