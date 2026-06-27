package analyze

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var skipDirNames = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "bin": true, "obj": true,
}

var scannableExt = map[string]bool{
	".js": true, ".html": true, ".htm": true, ".aspx": true, ".asp": true, ".cshtml": true,
}

// walkDirectory recursively collects scannable source files under root,
// skipping common dependency/build-output directories.
func walkDirectory(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirNames[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if scannableExt[strings.ToLower(filepath.Ext(path))] {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
