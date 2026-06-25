package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spectre-tool/spectre/internal/wordlists"
)

var wordlistsCmd = &cobra.Command{
	Use:   "wordlists",
	Short: "Manage wordlists (list, pull, update)",
	Long: `Wordlist manager for SPECTRE.

Third-party wordlists are NOT bundled — they are fetched from their official
upstream repositories on demand, so their licenses remain with their owners.
Run 'spectre wordlists pull <name>' to download a specific list.

Examples:
  spectre wordlists list
  spectre wordlists groups
  spectre wordlists pull raft-medium-dirs
  spectre wordlists pull subdomain:medium
  spectre wordlists pull all
  spectre wordlists update`,
}

var wordlistsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available wordlists",
	RunE: func(cmd *cobra.Command, args []string) error {
		cat, err := wordlists.LoadCatalog()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tTAGS\tSIZE\tPULLED\tLICENSE\tDESC")
		fmt.Fprintln(w, "----\t----\t----\t------\t-------\t----")
		for _, e := range cat.Lists {
			pulled := "✗"
			if wordlists.IsPulled(e.Name) {
				pulled = "✓"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				e.Name,
				strings.Join(e.Tags, ","),
				e.Size,
				pulled,
				e.License,
				e.Desc,
			)
		}
		return w.Flush()
	},
}

var wordlistsGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Show resolvable tag groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		cat, err := wordlists.LoadCatalog()
		if err != nil {
			return err
		}
		// Collect unique category:size combinations
		groups := make(map[string][]string)
		for _, e := range cat.Lists {
			var category, size string
			for _, t := range e.Tags {
				switch t {
				case "subdomain", "directory", "files", "words", "params":
					category = t
				case "small", "medium", "large", "huge":
					size = t
				}
			}
			if category != "" && size != "" {
				key := category + ":" + size
				groups[key] = append(groups[key], e.Name)
			}
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "GROUP\tLISTS")
		fmt.Fprintln(w, "-----\t-----")
		for k, names := range groups {
			fmt.Fprintf(w, "%s\t%s\n", k, strings.Join(names, ", "))
		}
		return w.Flush()
	},
}

var wordlistsPullCmd = &cobra.Command{
	Use:   "pull [name|group|all]",
	Short: "Download wordlists from upstream",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cat, err := wordlists.LoadCatalog()
		if err != nil {
			return err
		}
		spec := strings.Join(args, " ")
		var toPull []wordlists.Entry

		if spec == "all" {
			toPull = cat.Lists
		} else if strings.Contains(spec, ":") {
			tags := strings.Split(spec, ":")
			toPull = cat.ByTags(tags...)
			if len(toPull) == 0 {
				return fmt.Errorf("no lists match group %q", spec)
			}
		} else {
			e := cat.ByName(spec)
			if e == nil {
				return fmt.Errorf("unknown wordlist %q — check `spectre wordlists list`", spec)
			}
			toPull = []wordlists.Entry{*e}
		}

		for _, e := range toPull {
			if err := wordlists.Pull(e, func(dl, total int64) {
				if total > 0 {
					pct := int(100 * dl / total)
					fmt.Printf("\r  %d%% (%d / %d bytes)", pct, dl, total)
				} else {
					fmt.Printf("\r  %d bytes", dl)
				}
			}); err != nil {
				fmt.Fprintf(os.Stderr, "[error] %s: %v\n", e.Name, err)
			} else {
				fmt.Println() // newline after progress
			}
		}
		return nil
	},
}

var wordlistsUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Re-download all already-pulled wordlists",
	RunE: func(cmd *cobra.Command, args []string) error {
		cat, err := wordlists.LoadCatalog()
		if err != nil {
			return err
		}
		updated := 0
		for _, e := range cat.Lists {
			if wordlists.IsPulled(e.Name) {
				fmt.Printf("Updating %s...\n", e.Name)
				if err := wordlists.Pull(e, nil); err != nil {
					fmt.Fprintf(os.Stderr, "[error] %s: %v\n", e.Name, err)
				} else {
					updated++
				}
			}
		}
		fmt.Printf("Updated %d wordlist(s).\n", updated)
		return nil
	},
}

var wordlistsPathCmd = &cobra.Command{
	Use:   "path [name]",
	Short: "Print local path of a pulled wordlist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := wordlists.LocalPath(args[0])
		if err != nil {
			return err
		}
		if !wordlists.IsPulled(args[0]) {
			return fmt.Errorf("%q not pulled yet — run: spectre wordlists pull %s", args[0], args[0])
		}
		fmt.Println(p)
		return nil
	},
}

func init() {
	wordlistsCmd.AddCommand(wordlistsListCmd)
	wordlistsCmd.AddCommand(wordlistsGroupsCmd)
	wordlistsCmd.AddCommand(wordlistsPullCmd)
	wordlistsCmd.AddCommand(wordlistsUpdateCmd)
	wordlistsCmd.AddCommand(wordlistsPathCmd)
	rootCmd.AddCommand(wordlistsCmd)
}
