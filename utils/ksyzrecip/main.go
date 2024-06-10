/* -*- compile-command: "go build" -*- */
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

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

var (
	outputDir         string
	syzArch           string
	fokaPath          string
	paths             []string
	concatenateOutput bool
)

func removeAllFilesInDirectory(path string) {
	existingRecipes, _ := filepath.Glob(filepath.Join(outputDir, "*.c"))
	for _, item := range existingRecipes {
		os.RemoveAll(item)
	}
}

func globFilesFromPaths(paths []string, glob string) []string {
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

func init() {
	flag.StringVar(&outputDir, "output", "recipes_out", "path to directory for generated recipes")
	flag.StringVar(&syzArch, "arch", "arm64", "targeted arch of syzkaller descriptions (sizes or constants might differ) from sys/targets package")
	flag.StringVar(&fokaPath, "foka", "foka_v2.json", "path to FOKA output")
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
	removeAllFilesInDirectory(outputDir)

	descriptions := globFilesFromPaths(paths, "*.txt")
	constants := globFilesFromPaths(paths, "*.const")

	_, syscalls, _, err := tryCompileFromPaths(descriptions, constants, syzArch)
	if err != nil {
		panic(err)
	}

	var f *os.File = nil

	if concatenateOutput {
		var err error
		f, err = os.Create(filepath.Join(outputDir, "recipes.c"))
		if err != nil {
			panic(err)
		}

		f.WriteString(header)
	}

	usedRecipes := make(map[string]struct{})
	for _, sc := range syscalls {
		if sc.CallName != "ioctl" || len(sc.Args) < 3 {
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
			if concatenateOutput {
				if _, ok := usedRecipes[recipe.Name]; ok {
					continue
				}
			}

			f.WriteString(recipe.Declaration() + "\n")
		}

		f.WriteString("\n")

		for _, recipe := range recipes {
			if concatenateOutput {
				if _, ok := usedRecipes[recipe.Name]; ok {
					continue
				}
			}

			f.WriteString(recipe.Definition() + "\n")

			if concatenateOutput {
				usedRecipes[recipe.Name] = struct{}{}
			}
		}
	}
}
