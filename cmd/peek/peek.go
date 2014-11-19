// peek is a tool which parses and pretty prints Portable Executable (PE) files.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/mewrev/pe"
)

func init() {
	flag.Usage = usage
}

func usage() {
	fmt.Fprintln(os.Stderr, "peek FILE...")
}

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	for _, path := range flag.Args() {
		err := peek(path)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

// peek parses and pretty prints the provided Portable Executable (PE) file.
func peek(path string) (err error) {
	file, err := pe.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	err = file.Parse()
	if err != nil {
		return err
	}
	spew.Dump(file)
	return nil
}
