package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"f2n/internal/convert"
)

// TestGolden verifies byte-exact conversion output for every committed golden file.
// If a mapping changes intentionally, regenerate goldens:
//   convert all presets from testdata/flowseal into testdata/smoke2/<name> and copy
//   testdata/smoke2/<name>/nfqws2.conf -> testdata/golden/<name>.conf
func TestGolden(t *testing.T) {
	goldenDir := `testdata/golden`
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no golden files")
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".conf")
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join(goldenDir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			opts := convert.Options{
				FlowsealDir: `testdata/flowseal`,
				BatFile:     filepath.Join(`testdata/flowseal`, name+".bat"),
				Interface:   "eth3",
				Policy:      "nfqws",
				GameFilter:  "disabled",
			}
			res, err := convert.Run(opts)
			if err != nil {
				t.Fatal(err)
			}
			if res.Conf != string(want) {
				wantLines := strings.Split(string(want), "\n")
				gotLines := strings.Split(res.Conf, "\n")
				for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
					var w, g string
					if i < len(wantLines) {
						w = wantLines[i]
					}
					if i < len(gotLines) {
						g = gotLines[i]
					}
					if w != g {
						t.Fatalf("line %d differs:\n  want: %q\n  got:  %q", i+1, w, g)
					}
				}
				t.Fatalf("output differs in length: want %d lines, got %d", len(wantLines), len(gotLines))
			}
		})
	}
}
