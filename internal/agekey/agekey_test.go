package agekey

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"
)

func TestParseRecipient(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	valid := identity.Recipient().String()
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid", value: valid},
		{name: "empty", value: "", wantErr: true},
		{name: "whitespace", value: " " + valid, wantErr: true},
		{name: "multiple", value: valid + "," + valid, wantErr: true},
		{name: "identity", value: identity.String(), wantErr: true},
		{name: "ssh", value: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRecipient(tc.value)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseRecipient() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadIdentityFile(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, body string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "identity.txt")
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("age-keygen format", func(t *testing.T) {
		path := write(t, "# created for AegisMesh\n"+identity.String()+"\n", 0o600)
		got, _, err := LoadIdentityFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got.Recipient().String() != identity.Recipient().String() {
			t.Fatal("loaded identity does not match")
		}
	})

	t.Run("secret-manager symlink", func(t *testing.T) {
		target := write(t, identity.String()+"\n", 0o600)
		link := filepath.Join(t.TempDir(), "identity-link")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		got, _, err := LoadIdentityFile(link)
		if err != nil {
			t.Fatal(err)
		}
		if got.Recipient().String() != identity.Recipient().String() {
			t.Fatal("symlinked identity does not match")
		}
	})

	for _, tc := range []struct {
		name string
		body string
		mode os.FileMode
	}{
		{name: "empty", body: "# only a comment\n", mode: 0o600},
		{name: "multiple", body: identity.String() + "\n" + identity.String() + "\n", mode: 0o600},
		{name: "recipient not identity", body: identity.Recipient().String(), mode: 0o600},
		{name: "oversize", body: strings.Repeat("x", MaxIdentityFileBytes+1), mode: 0o600},
		{name: "group readable", body: identity.String(), mode: 0o640},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := write(t, tc.body, tc.mode)
			if _, _, err := LoadIdentityFile(path); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
}

func TestLoadIdentityFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	if _, _, err := LoadIdentityFile(path); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO identity error = %v", err)
	}
}
