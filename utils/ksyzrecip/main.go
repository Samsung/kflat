/* -*- compile-command: "go build" -*- */
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	. "github.com/samsung/kflat/ksyzrecip/generator"
)

var (
	output     string
	arch       string
	foka       string
	paths      []string
)

func init() {
	flag.StringVar(&output, "output", "_gen.c", "path to outputted file")
	flag.StringVar(&arch, "arch", "arm64", "targeted arch of syzkaller descriptions (sizes or constants might differ) from sys/targets package")
	flag.StringVar(&foka, "foka", "foka_v2.json", "path to FOKA output")

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

	generator, err := Generate(paths, arch, foka)
	if err != nil {
		log.Fatal(err)
	}

	recipe := generator.Recipe()
	f, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("discarded descriptions: %d\n", len(generator.DiscardedDescriptions))
	log.Printf("generated flatteners:   %d\n", len(recipe.Flatteners))
	log.Printf("generated triggers:     %d\n", len(recipe.Triggers))

	f.WriteString(recipe.String())
}
