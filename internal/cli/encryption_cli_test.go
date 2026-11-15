package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/recommend"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func seedEncryptedEvidence(t *testing.T, observation string) (string, event.Envelope, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	store, err := storage.New(storage.Options{
		Dir:           dir,
		MaxFileBytes:  1 << 20,
		MaxEventBytes: 256 << 10,
		Encryption: &storage.EncryptionOptions{
			Recipient: identity.Recipient().String(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	seq := &event.Sequencer{}
	envelope, err := event.New(seq, "encrypted-cli-test",
		event.SensorRef{ID: "http-decoy-1", Kind: "http", Listen: "127.0.0.1:8081"},
		event.ClassificationInteraction, []byte(observation), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, envelope, identityPath
}

func writeIdentityForCLI(t *testing.T, identity *age.X25519Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEncryptedEvidenceCLIReadPaths(t *testing.T) {
	dir, envelope, identityPath := seedEncryptedEvidence(t, detectionObservation("PI-001"))

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "list", args: []string{"inspect", "list", "--data-dir", dir, "--identity", identityPath}, want: short(envelope.ID)},
		{name: "show", args: []string{"inspect", "show", "--data-dir", dir, "--id", envelope.ID, "--identity", identityPath}, want: envelope.ID},
		{name: "recommend", args: []string{"recommend", "--data-dir", dir, "--identity", identityPath}, want: "DRY-RUN RECOMMENDATIONS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := run(t, tc.args...)
			if code != 0 || stderr != "" || !strings.Contains(out, tc.want) {
				t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
			}
		})
	}

	exportPath := filepath.Join(t.TempDir(), "export.ndjson")
	code, out, stderr := run(t, "inspect", "export", "--data-dir", dir, "--identity", identityPath, "--out", exportPath)
	if code != 0 || out != "" || !strings.Contains(stderr, "exported 1 event") {
		t.Fatalf("export: code=%d out=%q stderr=%q", code, out, stderr)
	}
	raw, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), envelope.ID) {
		t.Fatal("export omitted decrypted event")
	}
}

func TestEncryptedEvidenceCLICombinesIdentityWithFiltersLimitsAndFormats(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identityPath := writeIdentityForCLI(t, identity)
	dir := t.TempDir()
	store, err := storage.New(storage.Options{
		Dir:           dir,
		MaxFileBytes:  1 << 20,
		MaxEventBytes: 256 << 10,
		Encryption: &storage.EncryptionOptions{
			Recipient: identity.Recipient().String(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	seq := &event.Sequencer{}
	entries := []recommendationEvent{
		{sensor: "http-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
		{sensor: "tcp-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-002")},
		{sensor: "tcp-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
		{sensor: "tcp-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
	}
	envelopes := make([]event.Envelope, 0, len(entries))
	for i, entry := range entries {
		envelope, err := event.New(seq, "encrypted-filter-test",
			event.SensorRef{ID: entry.sensor, Kind: sensorKind(entry.sensor), Listen: "127.0.0.1:0"},
			entry.class, []byte(entry.observation), nil)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if err := store.Append(context.Background(), envelope); err != nil {
			t.Fatalf("append event %d: %v", i, err)
		}
		envelopes = append(envelopes, envelope)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	code, out, stderr := run(t, "inspect", "list", "--data-dir", dir,
		"--identity", identityPath,
		"--sensor", "tcp-decoy-1",
		"--kind", "tcp",
		"--finding", "PI-001",
		"--classification", event.ClassificationInteraction,
		"--limit", "1",
		"--verify",
		"--json")
	if code != 0 || stderr != "" {
		t.Fatalf("list: code=%d out=%q stderr=%q", code, out, stderr)
	}
	var listResult struct {
		Events []struct {
			ID          string `json:"id"`
			IntegrityOK *bool  `json:"integrity_ok"`
		} `json:"events"`
		CorruptLines int `json:"corrupt_lines"`
	}
	if err := json.Unmarshal([]byte(out), &listResult); err != nil {
		t.Fatalf("decode list JSON: %v\n%s", err, out)
	}
	if listResult.CorruptLines != 0 || len(listResult.Events) != 1 || listResult.Events[0].ID != envelopes[2].ID ||
		listResult.Events[0].IntegrityOK == nil || !*listResult.Events[0].IntegrityOK {
		t.Fatalf("encrypted list filters/limit/verify drifted: %+v", listResult)
	}

	code, out, stderr = run(t, "recommend", "--data-dir", dir,
		"--identity", identityPath,
		"--rule", "PI-001",
		"--sensor", "tcp-decoy-1",
		"--classification", event.ClassificationInteraction,
		"--limit", "1",
		"--json")
	if code != 0 || stderr != "" {
		t.Fatalf("recommend: code=%d out=%q stderr=%q", code, out, stderr)
	}
	var report recommend.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode recommendation JSON: %v\n%s", err, out)
	}
	if len(report.Recommendations) != 1 || report.Recommendations[0].SensorID != "tcp-decoy-1" ||
		len(report.Recommendations[0].RuleIDs) != 1 || report.Recommendations[0].RuleIDs[0] != "PI-001" ||
		len(report.Recommendations[0].Evidence) != 1 || report.Recommendations[0].Evidence[0].EventID != envelopes[2].ID {
		t.Fatalf("encrypted recommendation filters/limit drifted: %+v", report.Recommendations)
	}

	exportPath := filepath.Join(t.TempDir(), "ecs.ndjson")
	code, out, stderr = run(t, "inspect", "export", "--data-dir", dir,
		"--identity", identityPath, "--profile", "ecs", "--out", exportPath)
	if code != 0 || out != "" || !strings.Contains(stderr, "exported 4 event") {
		t.Fatalf("ECS export: code=%d out=%q stderr=%q", code, out, stderr)
	}
	exported, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exported), `"aegismesh"`) || !strings.Contains(string(exported), envelopes[2].ID) {
		t.Fatalf("ECS export omitted native decrypted evidence: %s", exported)
	}
}

func TestEncryptedEvidenceCLIRequiresMatchingIdentityWithoutPartialOutput(t *testing.T) {
	dir, _, identityPath := seedEncryptedEvidence(t, detectionObservation("PI-001"))
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := writeIdentityForCLI(t, wrong)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "list missing", args: []string{"inspect", "list", "--data-dir", dir}},
		{name: "list wrong", args: []string{"inspect", "list", "--data-dir", dir, "--identity", wrongPath}},
		{name: "show wrong", args: []string{"inspect", "show", "--data-dir", dir, "--id", "deadbeef", "--identity", wrongPath}},
		{name: "recommend wrong", args: []string{"recommend", "--data-dir", dir, "--identity", wrongPath}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := run(t, tc.args...)
			if code != 1 || out != "" || stderr == "" {
				t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
			}
			identityRaw, readErr := os.ReadFile(identityPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(stderr, strings.TrimSpace(string(identityRaw))) {
				t.Fatal("error disclosed private identity")
			}
		})
	}

	target := filepath.Join(t.TempDir(), "existing.ndjson")
	const sentinel = "keep-existing-output"
	if err := os.WriteFile(target, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "inspect", "export", "--data-dir", dir, "--identity", wrongPath, "--out", target)
	if code != 1 || out != "" || stderr == "" {
		t.Fatalf("export wrong identity: code=%d out=%q stderr=%q", code, out, stderr)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != sentinel {
		t.Fatalf("failed export replaced target: %q", raw)
	}
}

func TestEncryptedEvidenceCLIAcceptsRotatedIdentities(t *testing.T) {
	dir, envelope, identityPath := seedEncryptedEvidence(t, `{}`)
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := writeIdentityForCLI(t, wrong)

	code, out, stderr := run(t, "inspect", "list", "--data-dir", dir,
		"--identity", wrongPath, "--identity", identityPath)
	if code != 0 || stderr != "" || !strings.Contains(out, short(envelope.ID)) {
		t.Fatalf("rotated identities: code=%d out=%q stderr=%q", code, out, stderr)
	}
}

func TestIdentityFlagUsageMatrix(t *testing.T) {
	dir, envelope, identityPath := seedEncryptedEvidence(t, detectionObservation("PI-001"))
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := writeIdentityForCLI(t, wrong)
	target := filepath.Join(t.TempDir(), "existing.ndjson")
	commands := [][]string{
		{"inspect", "list", "--data-dir", dir},
		{"inspect", "show", "--data-dir", dir, "--id", envelope.ID},
		{"inspect", "export", "--data-dir", dir, "--out", target},
		{"recommend", "--data-dir", dir},
	}
	excess := []string{}
	for i := 0; i < 9; i++ {
		excess = append(excess, "--identity", identityPath)
	}
	cases := []struct {
		name string
		args []string
		code int
	}{
		{name: "omitted", code: 1},
		{name: "equals empty", args: []string{"--identity="}, code: 2},
		{name: "separate empty", args: []string{"--identity", ""}, code: 2},
		{name: "whitespace", args: []string{"--identity", "   "}, code: 2},
		{name: "padded", args: []string{"--identity", " " + identityPath}, code: 2},
		{name: "comma", args: []string{"--identity", identityPath + "," + identityPath}, code: 2},
		{name: "leading dash", args: []string{"--identity=-identity.txt"}, code: 2},
		{name: "missing value", args: []string{"--identity"}, code: 2},
		{name: "positional", args: []string{"--identity", identityPath, "extra"}, code: 2},
		{name: "duplicate", args: []string{"--identity", identityPath, "--identity", identityPath}, code: 1},
		{name: "too many", args: excess, code: 2},
		{name: "wrong", args: []string{"--identity", wrongPath}, code: 1},
		{name: "valid", args: []string{"--identity", identityPath}},
		{name: "rotated", args: []string{"--identity", wrongPath, "--identity", identityPath}},
	}
	for _, command := range commands {
		for _, tc := range cases {
			t.Run(strings.Join(command[:2], " ")+"/"+tc.name, func(t *testing.T) {
				const sentinel = "existing-output"
				if err := os.WriteFile(target, []byte(sentinel), 0o600); err != nil {
					t.Fatal(err)
				}
				args := append(append([]string(nil), command...), tc.args...)
				code, out, stderr := run(t, args...)
				if code != tc.code || (code != 0 && (out != "" || stderr == "")) {
					t.Fatalf("code=%d want=%d out=%q stderr=%q", code, tc.code, out, stderr)
				}
				if code != 0 {
					raw, err := os.ReadFile(target)
					if err != nil {
						t.Fatal(err)
					}
					if string(raw) != sentinel {
						t.Fatal("failed command changed export target")
					}
				}
			})
		}
	}
}

func TestIdentityFileValidationFailures(t *testing.T) {
	dir, _, _ := seedEncryptedEvidence(t, `{}`)
	missing := filepath.Join(t.TempDir(), "missing.txt")
	invalid := filepath.Join(t.TempDir(), "invalid.txt")
	if err := os.WriteFile(invalid, []byte("not-an-identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	public, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(t.TempDir(), "recipient.txt")
	if err := os.WriteFile(publicPath, []byte(public.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readable := writeIdentityForCLI(t, public)
	if err := os.Chmod(readable, 0o640); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{missing, invalid, publicPath, readable} {
		code, out, stderr := run(t, "inspect", "list", "--data-dir", dir, "--identity", path)
		if code != 1 || out != "" || stderr == "" {
			t.Fatalf("path=%s code=%d out=%q stderr=%q", filepath.Base(path), code, out, stderr)
		}
	}
}

func TestEncryptedEvidenceCorruptionLeavesCLIOutputsUntouched(t *testing.T) {
	dir, _, identityPath := seedEncryptedEvidence(t, detectionObservation("PI-001"))
	segments, err := filepath.Glob(filepath.Join(dir, "*.jsonl.age"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments=%v err=%v", segments, err)
	}
	raw, err := os.ReadFile(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segments[0], raw[:len(raw)-1], 0o600); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"inspect", "list", "--data-dir", dir, "--identity", identityPath},
		{"recommend", "--data-dir", dir, "--identity", identityPath},
	} {
		code, out, stderr := run(t, args...)
		if code != 1 || out != "" || stderr == "" {
			t.Fatalf("args=%v code=%d out=%q stderr=%q", args, code, out, stderr)
		}
	}

	target := filepath.Join(t.TempDir(), "existing.ndjson")
	const sentinel = "existing-output"
	if err := os.WriteFile(target, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "inspect", "export", "--data-dir", dir,
		"--identity", identityPath, "--out", target)
	if code != 1 || out != "" || stderr == "" {
		t.Fatalf("export: code=%d out=%q stderr=%q", code, out, stderr)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("corrupt export replaced target: %q", got)
	}
}

func TestInspectExportRefusesIdentityFileAliases(t *testing.T) {
	dir, _, identityPath := seedEncryptedEvidence(t, `{}`)
	original, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}

	paths := []string{identityPath}
	hardlink := filepath.Join(t.TempDir(), "identity-hardlink")
	if err := os.Link(identityPath, hardlink); err == nil {
		paths = append(paths, hardlink)
	}
	symlink := filepath.Join(t.TempDir(), "identity-symlink")
	if err := os.Symlink(identityPath, symlink); err == nil {
		paths = append(paths, symlink)
	}

	for _, target := range paths {
		code, out, stderr := run(t, "inspect", "export", "--data-dir", dir,
			"--identity", identityPath, "--out", target)
		if code != 2 || out != "" || !strings.Contains(stderr, "identity file") {
			t.Fatalf("target=%s code=%d out=%q stderr=%q", target, code, out, stderr)
		}
		got, err := os.ReadFile(identityPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(original) {
			t.Fatal("identity file changed")
		}
	}
}

func TestDoctorReportsEncryptionWithoutKeyMaterial(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	workspace := scaffoldWorkspace(t)
	configPath := filepath.Join(workspace, "mesh.yaml")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.Recipient().String()
	encryptionBlock := "storage:\n  encryption:\n    enabled: true\n    recipient: " + recipient + "\n"
	raw = []byte(strings.Replace(string(raw), "storage:\n", encryptionBlock, 1))
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, stderr := run(t, "doctor", "--config", configPath)
	if code != 0 || stderr != "" || !strings.Contains(out, "storage-crypto") || !strings.Contains(out, "age/X25519") {
		t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
	}
	if strings.Contains(out, recipient) || strings.Contains(out, identity.String()) {
		t.Fatal("doctor disclosed key material")
	}
}

func TestCompletionsAdvertiseIdentityFiles(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		code, out, stderr := run(t, "completion", shell)
		if code != 0 || stderr != "" || !strings.Contains(out, "--identity") && !strings.Contains(out, "-l identity") {
			t.Fatalf("%s: code=%d out=%q stderr=%q", shell, code, out, stderr)
		}
	}
}

func TestEncryptedShowValidatesPastExactMatch(t *testing.T) {
	dir, envelope, key := seedEncryptedEvidence(t, detectionObservation("PI-001"))
	paths, err := filepath.Glob(filepath.Join(dir, "*.jsonl.age"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	// Only the footer is damaged; the requested event is still authenticatable.
	if err := os.WriteFile(paths[0], raw[:len(raw)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "inspect", "show", "--data-dir", dir, "--id", envelope.ID, "--identity", key)
	if code != 1 || out != "" || stderr == "" {
		t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
	}
}

func TestIdentityArgumentsNeverEchoInlinePrivateKey(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir, _, _ := seedEncryptedEvidence(t, `{}`)
	for _, value := range []string{identity.String(), " " + identity.String(), identity.String() + ","} {
		code, out, stderr := run(t, "inspect", "list", "--data-dir", dir, "--identity", value)
		if code == 0 || out != "" || strings.Contains(stderr, identity.String()) {
			t.Fatal("inline identity accepted or disclosed")
		}
	}
}
