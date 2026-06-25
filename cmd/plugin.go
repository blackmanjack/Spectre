package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/output"
	"github.com/spectre-tool/spectre/internal/plugin"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage and run SPECTRE plugins",
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available plugins",
	Run: func(cmd *cobra.Command, args []string) {
		names := plugin.List()
		if len(names) == 0 {
			fmt.Println("No plugins registered.")
			return
		}
		for _, name := range names {
			p := plugin.Registry[name]
			fmt.Printf("  %-20s %s\n", name, p.Description())
		}
	},
}

var pluginRunCmd = &cobra.Command{
	Use:   "run [name] [target]",
	Short: "Run a plugin",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		target := args[1]

		if globalScope != nil {
			if ok, reason := globalScope.Authorized(target); !ok {
				return fmt.Errorf("out of scope: %s", reason)
			}
		}

		p, err := plugin.Get(name)
		if err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		dest := os.Stdout
		if outputFile != "" {
			f, err := os.Create(outputFile)
			if err != nil {
				return err
			}
			defer f.Close()
			dest = f
		}

		writer := output.NewWriter(outputFmt, dest, noColor)
		defer writer.Close()

		return p.Run(ctx, target, nil, writer)
	},
}

func init() {
	pluginCmd.AddCommand(pluginListCmd)
	pluginCmd.AddCommand(pluginRunCmd)
	rootCmd.AddCommand(pluginCmd)
}
