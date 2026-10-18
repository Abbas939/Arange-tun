// Package safearchive validates a backup completely before a restore touches
// live configuration. Both compressed and expanded sizes are bounded.
package safearchive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const MaxCompressed = 32 << 20
const MaxExpanded = 64 << 20
const MaxFiles = 2048

// Stage returns the validated original archive, rewound. The caller closes and
// removes it. Symlinks, hardlinks, duplicate paths and special files are refused.
func Stage(r io.Reader) (*os.File, error) {
	f, err := os.CreateTemp("", "arange-restore-*.tar.gz")
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	n, err := io.Copy(f, io.LimitReader(r, MaxCompressed+1))
	if err != nil {
		return nil, err
	}
	if n > MaxCompressed {
		return nil, fmt.Errorf("backup exceeds compressed size limit")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err = Validate(f); err != nil {
		return nil, err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ok = true
	return f, nil
}

func Validate(r io.Reader) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	expanded := &io.LimitedReader{R: gz, N: MaxExpanded + 1}
	tr := tar.NewReader(expanded)
	seen := map[string]bool{}
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if count >= MaxFiles {
			return fmt.Errorf("too many backup entries")
		}
		name := path.Clean(h.Name)
		if name == "." || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\:") {
			return fmt.Errorf("unsafe backup path %q", h.Name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate backup path %q", name)
		}
		seen[name] = true
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg {
			return fmt.Errorf("unsupported backup entry %q", name)
		}
		if h.Size < 0 || h.Size > MaxExpanded {
			return fmt.Errorf("backup file too large")
		}
		if _, err = io.Copy(io.Discard, tr); err != nil {
			return err
		}
	}
	// Read through gzip's trailer so a bad CRC is found before any live write.
	if _, err = io.Copy(io.Discard, expanded); err != nil {
		return err
	}
	if expanded.N <= 0 {
		return fmt.Errorf("backup exceeds expanded size limit")
	}
	return nil
}
