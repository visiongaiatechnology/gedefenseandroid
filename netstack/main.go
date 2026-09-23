package main

import "os"

func main() {
	os.Exit(runHelperMain(os.Args[1:]))
}
