package main

import (
	"github.com/spectre-tool/spectre/cmd"
	"github.com/spectre-tool/spectre/wordlists"
)

func main() {
	cmd.Execute(wordlists.FS)
}
