package rulecatalog

import (
	"encoding/csv"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPinnedFrameworkTable(t *testing.T) {
	file, err := os.Open("testdata/frameworks.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.Comma = '\t'
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	entries := All()
	if len(rows) != len(entries)+1 || len(frameworkTable) != len(entries) {
		t.Fatal("every rule needs an explicit framework entry")
	}
	for i, row := range rows[1:] {
		if len(row) != 4 || row[0] != entries[i].ID {
			t.Fatal("mapping order or column drift", row)
		}
		if _, ok := frameworkTable[row[0]]; !ok {
			t.Fatal("implicit mapping", row[0])
		}
		expected := []FrameworkMapping{}
		for j, cell := range row[1:] {
			if cell != "" {
				for _, ref := range strings.Split(cell, ";") {
					id, name, ok := strings.Cut(ref, " ")
					if !ok {
						t.Fatal("invalid pinned reference")
					}
					expected = append(expected, FrameworkMapping{rows[0][j+1], id, name})
				}
			}
		}
		if !reflect.DeepEqual(entries[i].Frameworks, expected) {
			t.Errorf("%s mapping drift: %+v", row[0], entries[i].Frameworks)
		}
	}
	// The newly nested slices must not allow poisoning global catalog state.
	entries[0].Frameworks[0].Name = "mutated"
	got, _ := Lookup(entries[0].ID)
	if got.Frameworks[0].Name == "mutated" {
		t.Fatal("All aliases mappings")
	}
	got.Frameworks[0].Name = "also-mutated"
	again, _ := Lookup(got.ID)
	if again.Frameworks[0].Name == "also-mutated" {
		t.Fatal("Lookup aliases mappings")
	}
}
