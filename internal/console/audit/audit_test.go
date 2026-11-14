package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainRotationPaginationAndTamper(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	auditLog, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	auditLog.rotateBytes = 900
	for i := range 12 {
		actor := "alice"
		if i%2 == 0 {
			actor = "bob"
		}
		if err = auditLog.Append(Record{
			Actor:   actor,
			Role:    "admin",
			Action:  "audit.read",
			Outcome: "ok",
		}); err != nil {
			t.Fatal(err)
		}
	}

	verification := auditLog.Verify()
	if !verification.Verified || verification.Records != 12 {
		t.Fatalf("%+v", verification)
	}

	records, more, err := auditLog.Read(^uint64(0), 3, "", "alice")
	if err != nil || !more || len(records) != 3 || records[0].Seq != 12 {
		t.Fatalf("%+v %t %v", records, more, err)
	}

	next, more, err := auditLog.Read(records[2].Seq, 3, "", "alice")
	if err != nil || more || len(next) != 3 || next[0].Seq != 6 {
		t.Fatalf("%+v %t %v", next, more, err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "audit*.jsonl"))
	if len(files) < 2 {
		t.Fatal("rotation not exercised")
	}

	for _, filename := range files {
		info, _ := os.Stat(filename)
		if info.Mode().Perm() != 0600 {
			t.Fatal(info.Mode())
		}
	}

	auditLog.Close()
	auditLog, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err = auditLog.Append(Record{
		Action:  "audit.verify",
		Outcome: "ok",
	}); err != nil {
		t.Fatal(err)
	}

	if verification = auditLog.Verify(); !verification.Verified || verification.Records != 13 {
		t.Fatal(verification)
	}

	auditLog.Close()
	body, _ := os.ReadFile(files[0])
	body = []byte(strings.Replace(string(body), "alice", "carol", 1))
	if err = os.WriteFile(files[0], body, 0600); err != nil {
		t.Fatal(err)
	}

	if bad, err := New(dir); err == nil {
		bad.Close()
		t.Fatal("tampered audit accepted")
	}
}

func TestAuditRejectsSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Fatal(err)
	}

	if auditLog, err := New(dir); err == nil {
		auditLog.Close()
		t.Fatal("symlink accepted")
	}
}

func TestIncompleteJSONLRecordRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	auditLog, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err = auditLog.Append(Record{
		Actor:   "alice",
		Role:    "admin",
		Action:  "audit.read",
		Outcome: "ok",
	}); err != nil {
		t.Fatal(err)
	}

	auditLog.Close()
	filename := filepath.Join(dir, "audit.jsonl")
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	if body[len(body)-1] != '\n' {
		t.Fatal("fixture not JSONL")
	}

	if err = os.WriteFile(filename, body[:len(body)-1], 0600); err != nil {
		t.Fatal(err)
	}

	if reopened, err := New(dir); err == nil {
		reopened.Close()
		t.Fatal("unterminated JSONL record accepted; a later append would concatenate two records")
	}
}

func TestVerificationReportsFirstInvalidSequence(t *testing.T) {
	cases := []struct {
		name   string
		change func([]string) []string
	}{
		{
			name: "modified",
			change: func(lines []string) []string {
				lines[1] = strings.Replace(lines[1], `"actor":"alice"`, `"actor":"carol"`, 1)
				return lines
			},
		},
		{
			name: "removed middle record",
			change: func(lines []string) []string {
				return append(lines[:1], lines[2:]...)
			},
		},
		{
			name: "reordered",
			change: func(lines []string) []string {
				lines[1], lines[2] = lines[2], lines[1]
				return lines
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			auditLog, err := New(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer auditLog.Close()
			for range 4 {
				if err := auditLog.Append(Record{
					Actor:   "alice",
					Action:  "audit.read",
					Outcome: "ok",
				}); err != nil {
					t.Fatal(err)
				}
			}
			filename := filepath.Join(dir, "audit.jsonl")
			body, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
			damaged := strings.Join(testCase.change(lines), "\n") + "\n"
			if err := os.WriteFile(filename, []byte(damaged), 0600); err != nil {
				t.Fatal(err)
			}
			verification := auditLog.Verify()
			if verification.Verified || verification.FirstInvalidSeq != 2 || verification.Records != 1 {
				t.Fatalf("verification = %+v; want first_invalid_seq=2 after one valid record", verification)
			}
			if reopened, err := New(dir); err == nil {
				reopened.Close()
				t.Fatal("startup accepted damaged audit")
			}
		})
	}
}
