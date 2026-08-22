package rulesinput

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const secret = "leakme-topsecret-rule-body" // planted content; must never surface in errors

func TestLoadSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		src     Source
		want    Input
		wantRaw string
	}{
		{
			name:    "literal text",
			src:     Source{Kind: KindLiteral, Text: "rules: []\n"},
			want:    Input{Kind: KindLiteral, Name: "literal", Bytes: 10},
			wantRaw: "rules: []\n",
		},
		{
			name:    "named local file",
			src:     Source{Kind: KindFile, Path: path},
			want:    Input{Kind: KindFile, Name: "rules.yaml", Bytes: 10},
			wantRaw: "rules: []\n",
		},
		{
			name:    "injected stdin reader",
			src:     Source{Kind: KindStdin, Stdin: strings.NewReader("rules: []\n")},
			want:    Input{Kind: KindStdin, Name: "stdin", Bytes: 10},
			wantRaw: "rules: []\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(tt.src)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Kind != tt.want.Kind || got.Name != tt.want.Name || got.Bytes != tt.want.Bytes || got.Text != tt.wantRaw {
				t.Fatalf("Load() = %+v, want %+v with text %q", got, tt.want, tt.wantRaw)
			}
			if len(got.Text) != got.Bytes {
				t.Fatalf("Bytes = %d does not match len(Text) = %d", got.Bytes, len(got.Text))
			}
		})
	}
}

func TestLoadExactlyOneSource(t *testing.T) {
	tests := []struct {
		name string
		src  Source
		want error
	}{
		{"zero value", Source{}, ErrNoSource},
		{"literal and file", Source{Kind: KindLiteral, Text: "x", Path: "/tmp/x"}, ErrAmbiguousSource},
		{"literal and stdin", Source{Kind: KindLiteral, Text: "x", Stdin: strings.NewReader("y")}, ErrAmbiguousSource},
		{"file and stdin", Source{Kind: KindStdin, Stdin: strings.NewReader("y"), Path: "/tmp/x"}, ErrAmbiguousSource},
		{"file kind without path", Source{Kind: KindFile}, ErrAmbiguousSource},
		{"stdin kind without reader", Source{Kind: KindStdin}, ErrAmbiguousSource},
		{"unknown kind", Source{Kind: "carrier-pigeon", Text: "x"}, ErrAmbiguousSource},
		{"empty kind with text", Source{Text: "x"}, ErrAmbiguousSource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, err := Load(tt.src)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Load() error = %v, want %v", err, tt.want)
			}
			if in != (Input{}) {
				t.Fatalf("Load() returned non-zero Input on failure: %+v", in)
			}
		})
	}
}

func TestLoadEmptyInput(t *testing.T) {
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		src  Source
	}{
		{"literal", Source{Kind: KindLiteral, Text: ""}},
		{"file", Source{Kind: KindFile, Path: emptyPath}},
		{"stdin", Source{Kind: KindStdin, Stdin: strings.NewReader("")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.src)
			if !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("Load() error = %v, want %v", err, ErrEmptyInput)
			}
		})
	}
}

func TestLoadInvalidUTF8(t *testing.T) {
	bad := string([]byte{0x61, 0xff, 0xfe}) + "\n"
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		src  Source
	}{
		{"literal", Source{Kind: KindLiteral, Text: bad}},
		{"file", Source{Kind: KindFile, Path: badPath}},
		{"stdin", Source{Kind: KindStdin, Stdin: strings.NewReader(bad)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.src)
			if !errors.Is(err, ErrInvalidUTF8) {
				t.Fatalf("Load() error = %v, want %v", err, ErrInvalidUTF8)
			}
			if strings.Contains(err.Error(), bad) { // raw bytes echoed nowhere
				t.Fatalf("error leaks content: %q", err.Error())
			}
		})
	}
}

func TestLoadByteLimit(t *testing.T) {
	exact := strings.Repeat("a", MaxBytes)
	over := strings.Repeat("b", MaxBytes+1)

	dir := t.TempDir()
	okPath := filepath.Join(dir, "exact.yaml")
	if err := os.WriteFile(okPath, []byte(exact), 0o600); err != nil {
		t.Fatal(err)
	}
	overPath := filepath.Join(dir, "over.yaml")
	if err := os.WriteFile(overPath, []byte(over), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("boundary accepted from all sources", func(t *testing.T) {
		sources := []Source{
			{Kind: KindLiteral, Text: exact},
			{Kind: KindFile, Path: okPath},
			{Kind: KindStdin, Stdin: strings.NewReader(exact)},
		}
		for _, src := range sources {
			in, err := Load(src)
			if err != nil {
				t.Fatalf("%s: Load() error = %v", src.Kind, err)
			}
			if in.Bytes != MaxBytes || len(in.Text) != MaxBytes {
				t.Fatalf("%s: Bytes = %d, want %d", src.Kind, in.Bytes, MaxBytes)
			}
		}
	})

	t.Run("limit plus one rejected before unbounded read", func(t *testing.T) {
		blocking := make(chan struct{}) // never closed: a regression draining past the cap hangs loudly
		hanging := io.MultiReader(strings.NewReader(over), blockingReader{blocking})

		tests := []struct {
			name string
			src  Source
		}{
			{"literal", Source{Kind: KindLiteral, Text: over}},
			{"file", Source{Kind: KindFile, Path: overPath}},
			{"stdin", Source{Kind: KindStdin, Stdin: hanging}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := Load(tt.src)
				if !errors.Is(err, ErrTooLarge) {
					t.Fatalf("Load() error = %v, want %v", err, ErrTooLarge)
				}
				if strings.Contains(err.Error(), "bbbb") {
					t.Fatalf("error leaks content: %q", err.Error())
				}
			})
		}
	})
}

type blockingReader struct{ done <-chan struct{} }

// Read blocks forever after returning nothing, so a regression that drains
// past the cap would hang this test instead of passing silently.
func (b blockingReader) Read([]byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func TestLoadRejectsDirectoryAndNonRegular(t *testing.T) {
	dir := t.TempDir()

	t.Run("directory", func(t *testing.T) {
		_, err := Load(Source{Kind: KindFile, Path: dir})
		if !errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("Load() error = %v, want %v", err, ErrNotRegularFile)
		}
	})

	t.Run("fifo rejected without opening", func(t *testing.T) {
		fifo := filepath.Join(dir, "pipe.yaml")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
		_, err := Load(Source{Kind: KindFile, Path: fifo})
		if !errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("Load() error = %v, want %v", err, ErrNotRegularFile)
		}
	})
}

func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := Load(Source{Kind: KindFile, Path: link})
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("Load() error = %v, want %v", err, ErrSymlink)
	}

	dangling := filepath.Join(dir, "missing-target.yaml")
	if err := os.Symlink(filepath.Join(dir, "nope"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Source{Kind: KindFile, Path: dangling}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Load(dangling) error = %v, want %v", err, ErrSymlink)
	}
}

func TestLoadReadFailure(t *testing.T) {
	t.Run("stream reader fails", func(t *testing.T) {
		_, err := Load(Source{Kind: KindStdin, Stdin: failingReader{}})
		if err == nil || !strings.Contains(err.Error(), "read stream") {
			t.Fatalf("Load() error = %v, want wrapped stream read failure", err)
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("Load() conflated injected failure with EOF: %v", err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("running as root; permission bits not enforced")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "locked.yaml")
		if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		_, err := Load(Source{Kind: KindFile, Path: path})
		if err == nil || errors.Is(err, ErrSymlink) || errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("Load() error = %v, want open failure", err)
		}
	})
}

type failingReader struct{}

var errInjected = errors.New("injected i/o fault")

func (failingReader) Read([]byte) (int, error) { return 0, errInjected }

func TestLoadMetadataOnly(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "suite.yaml")
	body := "name: suite-a\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	in, err := Load(Source{Kind: KindFile, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if in.Name != "suite.yaml" { // base name only: no directories, no absolute path
		t.Fatalf("Name = %q, want %q", in.Name, "suite.yaml")
	}
	if in.Bytes != len(body) {
		t.Fatalf("Bytes = %d, want %d", in.Bytes, len(body))
	}
	if in.Text != body {
		t.Fatalf("Text = %q, want %q", in.Text, body)
	}
}

func TestErrorsNeverContainContent(t *testing.T) {
	payload := secret + "\n\x00\xff"
	cases := map[string]Source{
		"invalid utf8":   {Kind: KindLiteral, Text: payload},
		"oversize":       {Kind: KindLiteral, Text: secret + strings.Repeat("x", MaxBytes)},
		"ambiguous":      {Kind: KindLiteral, Text: payload, Stdin: strings.NewReader(payload)},
		"unknown kind":   {Kind: "fax", Text: payload},
		"failing stream": {Kind: KindStdin, Stdin: failingReader{}},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(src)
			if err == nil {
				t.Fatal("Load() succeeded; expected rejection")
			}
			if strings.Contains(err.Error(), "leakme-topsecret") {
				t.Fatalf("error %q contains input content", err.Error())
			}
		})
	}
}
