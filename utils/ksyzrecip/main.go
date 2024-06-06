/* -*- compile-command: "go build" -*- */
package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"os"
	"path/filepath"
	"strings"
)

const (
	header string = `/* autogenerated by ksyzrecip (by michal.lach@samsung.com) */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

`
)

var (
	lastFile  string
	lastMsg   string
	outputDir string
	syzArch   string
	paths     []string
	concatenateOutput bool
)

func compileErrorHandler(pos ast.Pos, msg string) {
	lastFile = pos.File
	lastMsg = msg
}

func init() {
	flag.StringVar(&outputDir, "output", "recipes_out", "path to directory for generated recipes")
	flag.StringVar(&syzArch, "arch", "arm64", "targeted arch of syzkaller descriptions (sizes or constants might differ) from sys/targets package")
	flag.BoolVar(&concatenateOutput, "concatenate", true, "put all recipes to one file")

	flag.Usage = func() {
		out := flag.CommandLine.Output()

		fmt.Fprintf(out, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, "Most importantly ksyzrecip takes at least 1 positional argument which is a path to folder with syzkaller descriptions.\n")
		fmt.Fprintf(out, "Normally that would be in syzkaller/sys/$TARGETOS\n")
	}

	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(0)
	}

	paths = flag.Args()
}

func main() {
	if len(os.Args) <= 1 {
		flag.Usage()
		os.Exit(0)
	}

	os.Mkdir(outputDir, 0775)
	existingRecipes, _ := filepath.Glob(filepath.Join(outputDir, "*.c"))
	for _, item := range existingRecipes {
		os.RemoveAll(item)
	}

	var descFiles []string
	var constFiles []string

	for _, str := range paths {
		txts, err := filepath.Glob(filepath.Join(str, "*.txt"))
		cnsts, err := filepath.Glob(filepath.Join(str, "*.const"))
		if err != nil {
			panic(err)
		}

		descFiles = append(descFiles, txts...)
		constFiles = append(constFiles, cnsts...)
	}

	var descs *ast.Description = &ast.Description{}
	var p *compiler.Prog = nil
	consts := make(map[string]uint64)

	for p == nil {
		if lastFile != "" && lastMsg != "" {
			fmt.Fprintf(os.Stderr, "error, retrying without file %s: %s\n", lastFile, lastMsg)

			for i, f := range descFiles {
				if lastFile == f {
					descFiles = append(descFiles[:i], descFiles[i+1:]...)
				}
			}

			lastFile = ""
			lastMsg = ""

			descs = &ast.Description{}
			consts = make(map[string]uint64)
		}

		for _, f := range descFiles {
			buf, err := os.ReadFile(f)
			if err != nil {
				panic(err)
			}

			other := ast.Parse(buf, f, func(_ ast.Pos, _ string) {})
			if other != nil {
				descs.Nodes = append(descs.Nodes, other.Nodes...)
			}
		}

		for _, f := range constFiles {
			other := compiler.DeserializeConstFile(f, func(_ ast.Pos, _ string) {}).Arch(targets.ARM64)
			for k, v := range other {
				consts[k] = v
			}
		}

		if len(consts) <= 0 || descs == nil {
			panic("No descriptions nor const got parsed")
		}

		p = compiler.Compile(descs, consts, targets.List[targets.Linux][syzArch], compileErrorHandler)
	}

	prog.RestoreLinks(p.Syscalls, p.Resources, p.Types)
	var f *os.File = nil

	if concatenateOutput {
		var err error
		f, err = os.Create(filepath.Join(outputDir, "recipes.c"))
		if err != nil {
			panic(err)
		}

		f.WriteString(header)
	}

	for _, sc := range p.Syscalls {
		if !strings.HasPrefix(sc.Name, "ioctl$") || len(sc.Args) < 3 {
			continue
		}

		derefed, ok := sc.Args[2].Type.(*prog.PtrType)
		if !ok {
			continue
		}

		inner, ok := derefed.Elem.(*prog.StructType)
		if !ok {
			continue
		}

		recipes, err := generateRecipe(*inner)
		if err != nil {
			continue
		}

		if !concatenateOutput {
			f, err = os.Create(filepath.Join(outputDir, fmt.Sprintf("%s.c", inner.Name())))
			if err != nil {
				continue
			}

			f.WriteString(header)
		}

		for _, recipe := range recipes {
			f.WriteString(recipe.Declaration() + "\n")
		}

		f.WriteString("\n")

		for _, recipe := range recipes {
			f.WriteString(recipe.Definition() + "\n")
		}
	}
}
