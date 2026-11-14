package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func TestConsoleTokenGolden(t *testing.T) {
	var b bytes.Buffer
	token := "synthetic-console-token-for-tests"
	if err := writeConsoleToken(&b, token); err != nil {
		t.Fatal(err)
	}

	golden, err := os.ReadFile(filepath.Join("testdata", "console-token.golden.txt"))
	if err != nil {
		t.Fatal(err)
	}

	if b.String() != string(golden) || strings.Count(b.String(), token) != 1 {
		t.Fatalf("golden mismatch: %s", b.String())
	}
}

func TestConsoleCLI(t *testing.T) {
	for _, testCase := range []struct {
		args  []string
		input string
		bad   bool
	}{
		{
			args:  []string{"hash"},
			input: "synthetic-token\n",
			bad:   false,
		},
		{
			args:  []string{"token"},
			input: "",
			bad:   false,
		},
		{
			args:  nil,
			input: "",
			bad:   true,
		},
		{
			args: []string{
				"hash",
				"secret",
			},
			input: "",
			bad:   true,
		},
		{
			args:  []string{"hash"},
			input: "",
			bad:   true,
		},
		{
			args:  []string{"hash"},
			input: strings.Repeat("x", 4097),
			bad:   true,
		},
		{
			args:  []string{"unknown"},
			input: "",
			bad:   true,
		},
	} {
		var out bytes.Buffer
		c := NewConsoleCmd(&Env{
			Out:   &out,
			Stdin: strings.NewReader(testCase.input),
		})
		err := c.Run(context.Background(), testCase.args)
		if (err != nil) != testCase.bad {
			t.Fatalf("%v: %v", testCase.args, err)
		}
		if err == nil && testCase.args[0] == "hash" && out.String() != auth.Digest("synthetic-token")+"\n" {
			t.Fatal(out.String())
		}
		if err == nil && testCase.args[0] == "token" {
			lines := strings.Split(out.String(), "\n")
			token := strings.TrimPrefix(lines[0], "token (save now): ")
			if len(token) < 43 ||
				strings.Count(out.String(), token) != 1 ||
				!strings.Contains(out.String(), auth.Digest(token)) {
				t.Fatal("token output")
			}
		}
	}
}
