package cmd

import (
	"embed"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/safety"
)

var (
	embeddedFS  embed.FS
	globalScope *safety.Scope
	globalAudit *safety.Audit

	// Global flags
	outputFile string
	outputFmt  string
	scopeFile  string
	noAudit    bool
	silent     bool
	noColor    bool
)

const banner = `
███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
  Scan · Probe · Enumerate · Crawl · Trace · Recon · Examine
  For authorized security testing only.
`

var rootCmd = &cobra.Command{
	Use:   "spectre",
	Short: "SPECTRE — fast recon suite for authorized security testing",
	Long:  banner,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "wordlists" || cmd.Name() == "help" {
			return nil
		}
		var err error
		if scopeFile != "" {
			globalScope, err = safety.LoadScope(scopeFile)
			if err != nil {
				return fmt.Errorf("loading scope file: %w", err)
			}
		}
		if !noAudit {
			globalAudit, err = safety.NewAudit("")
			if err != nil {
				return fmt.Errorf("opening audit log: %w", err)
			}
		}
		return nil
	},
}

// Execute wires the embedded FS and runs the root command.
func Execute(fs embed.FS) {
	embeddedFS = fs
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "format", "f", "text", "Output format: text|json")
	rootCmd.PersistentFlags().StringVar(&scopeFile, "scope", "", "Scope file (one CIDR/host/wildcard per line)")
	rootCmd.PersistentFlags().BoolVar(&noAudit, "no-audit", false, "Disable audit logging")
	rootCmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "Suppress banner and info messages")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output")
}
