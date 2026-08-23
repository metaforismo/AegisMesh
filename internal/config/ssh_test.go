package config

import (
	"strings"
	"testing"
)

const minimalSSH = `
api_version: aegismesh.io/v1alpha1
sensors:
  - id: ssh-one
    kind: ssh
`

func TestSSHConfigDefaults(t *testing.T) {
	c, err := Load(writeTemp(t, "mesh.yaml", minimalSSH))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ssh := c.Sensors[0].SSH
	if ssh == nil {
		t.Fatal("ssh config should be materialized when omitted")
	}
	if c.Sensors[0].Listen != DefaultSSHListen {
		t.Fatalf("listen default = %q, want %q", c.Sensors[0].Listen, DefaultSSHListen)
	}
	if ssh.ServerVersion != DefaultSSHServerVersion {
		t.Fatalf("server version default = %q, want %q", ssh.ServerVersion, DefaultSSHServerVersion)
	}
	if ssh.HandshakeTimeoutSeconds != DefaultSSHHandshakeTimeoutSeconds {
		t.Fatalf("handshake timeout default = %d, want %d", ssh.HandshakeTimeoutSeconds, DefaultSSHHandshakeTimeoutSeconds)
	}
	if ssh.MaxSessionSeconds != DefaultSSHMaxSessionSeconds {
		t.Fatalf("session timeout default = %d, want %d", ssh.MaxSessionSeconds, DefaultSSHMaxSessionSeconds)
	}
	if ssh.MaxAuthAttempts != DefaultSSHMaxAuthAttempts {
		t.Fatalf("auth attempts default = %d, want %d", ssh.MaxAuthAttempts, DefaultSSHMaxAuthAttempts)
	}
}

func TestSSHConfigAcceptsBoundaries(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "minimums",
			body: "handshake_timeout_seconds: 1\n      max_session_seconds: 1\n      max_auth_attempts: 1\n",
		},
		{
			name: "maximums",
			body: "handshake_timeout_seconds: 60\n      max_session_seconds: 300\n      max_auth_attempts: 6\n",
		},
		{
			name: "printable identification",
			body: "server_version: 'SSH-2.0-AegisMesh 1.0'\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := minimalSSH + "    ssh:\n      " + tc.body
			if _, err := Load(writeTemp(t, "mesh.yaml", doc)); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
}

func TestSSHConfigRejectsExplicitEmptyAndZero(t *testing.T) {
	cases := []struct {
		name    string
		field   string
		wantErr string
	}{
		{name: "empty server version", field: `server_version: ""`, wantErr: "server_version"},
		{name: "null server version", field: "server_version: null", wantErr: "server_version"},
		{name: "zero handshake timeout", field: "handshake_timeout_seconds: 0", wantErr: "handshake_timeout_seconds"},
		{name: "zero session timeout", field: "max_session_seconds: 0", wantErr: "max_session_seconds"},
		{name: "zero auth attempts", field: "max_auth_attempts: 0", wantErr: "max_auth_attempts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := minimalSSH + "    ssh:\n      " + tc.field + "\n"
			_, err := Load(writeTemp(t, "mesh.yaml", doc))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestSSHJSONDistinguishesOmittedFromExplicitZero(t *testing.T) {
	omitted := `{"api_version":"aegismesh.io/v1alpha1","sensors":[{"id":"ssh-one","kind":"ssh"}]}`
	if _, err := Load(writeTemp(t, "mesh.json", omitted)); err != nil {
		t.Fatalf("omitted settings: %v", err)
	}
	explicit := `{"api_version":"aegismesh.io/v1alpha1","sensors":[{"id":"ssh-one","kind":"ssh","ssh":{"max_auth_attempts":0}}]}`
	if _, err := Load(writeTemp(t, "mesh.json", explicit)); err == nil || !strings.Contains(err.Error(), "max_auth_attempts") {
		t.Fatalf("explicit zero error = %v", err)
	}
}

func TestSSHConfigBlockDistinguishesEmptyFromNull(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		doc  string
	}{
		{
			name: "yaml empty mapping uses defaults",
			file: "mesh.yaml",
			doc:  minimalSSH + "    ssh: {}\n",
		},
		{
			name: "json empty mapping uses defaults",
			file: "mesh.json",
			doc:  `{"api_version":"aegismesh.io/v1alpha1","sensors":[{"id":"ssh-one","kind":"ssh","ssh":{}}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(writeTemp(t, tc.file, tc.doc))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := c.Sensors[0].SSH; got == nil || got.MaxAuthAttempts != DefaultSSHMaxAuthAttempts {
				t.Fatalf("empty SSH mapping did not materialize defaults: %+v", got)
			}
		})
	}

	for _, tc := range []struct {
		name string
		file string
		doc  string
	}{
		{
			name: "yaml null",
			file: "mesh.yaml",
			doc:  minimalSSH + "    ssh: null\n",
		},
		{
			name: "json null",
			file: "mesh.json",
			doc:  `{"api_version":"aegismesh.io/v1alpha1","sensors":[{"id":"ssh-one","kind":"ssh","ssh":null}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tc.file, tc.doc))
			if err == nil || !strings.Contains(err.Error(), "must be a mapping, not null") {
				t.Fatalf("Load error = %v, want explicit null rejection", err)
			}
		})
	}
}

func TestSSHConfigRejectsBoundsAndIdentification(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*SSHConfig)
		wantErr string
	}{
		{
			name:    "handshake below lower bound",
			mutate:  func(c *SSHConfig) { c.HandshakeTimeoutSeconds = -1 },
			wantErr: "handshake_timeout_seconds",
		},
		{
			name:    "handshake above upper bound",
			mutate:  func(c *SSHConfig) { c.HandshakeTimeoutSeconds = MaxSSHHandshakeTimeoutSeconds + 1 },
			wantErr: "handshake_timeout_seconds",
		},
		{
			name:    "session below lower bound",
			mutate:  func(c *SSHConfig) { c.MaxSessionSeconds = -1 },
			wantErr: "max_session_seconds",
		},
		{
			name:    "session above upper bound",
			mutate:  func(c *SSHConfig) { c.MaxSessionSeconds = MaxSSHSessionSeconds + 1 },
			wantErr: "max_session_seconds",
		},
		{
			name:    "auth attempts below lower bound",
			mutate:  func(c *SSHConfig) { c.MaxAuthAttempts = -1 },
			wantErr: "max_auth_attempts",
		},
		{
			name:    "auth attempts above upper bound",
			mutate:  func(c *SSHConfig) { c.MaxAuthAttempts = MaxSSHAuthAttempts + 1 },
			wantErr: "max_auth_attempts",
		},
		{
			name:    "missing protocol prefix",
			mutate:  func(c *SSHConfig) { c.ServerVersion = "AegisMesh" },
			wantErr: "SSH-2.0-",
		},
		{
			name:    "line feed",
			mutate:  func(c *SSHConfig) { c.ServerVersion = "SSH-2.0-AegisMesh\n" },
			wantErr: "CR, or LF",
		},
		{
			name:    "nul",
			mutate:  func(c *SSHConfig) { c.ServerVersion = "SSH-2.0-AegisMesh\x00" },
			wantErr: "NUL",
		},
		{
			name:    "non-printable byte",
			mutate:  func(c *SSHConfig) { c.ServerVersion = "SSH-2.0-AegisMesh\x1f" },
			wantErr: "printable ASCII",
		},
		{
			name:    "too long",
			mutate:  func(c *SSHConfig) { c.ServerVersion = "SSH-2.0-" + strings.Repeat("a", MaxSSHServerVersionBytes) },
			wantErr: "server_version",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(writeTemp(t, "mesh.yaml", minimalSSH))
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(c.Sensors[0].SSH)
			err = c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestSSHConfigRejectsUnknownAndMisplacedFields(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{
			name: "unknown nested field",
			doc: minimalSSH + `
    ssh:
      unexpected: true
`,
		},
		{
			name: "host key path is not configurable",
			doc: minimalSSH + `
    ssh:
      host_key_file: /tmp/host-key
`,
		},
		{
			name: "ssh block on http",
			doc: strings.Replace(minimalSSH, "kind: ssh", "kind: http", 1) + `
    ssh: {}
`,
		},
		{
			name: "ssh block on tcp",
			doc: strings.Replace(minimalSSH, "kind: ssh", "kind: tcp", 1) + `
    ssh: {}
`,
		},
		{
			name: "ssh field at sensor root",
			doc: minimalSSH + `
    server_version: SSH-2.0-wrong-level
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, "mesh.yaml", tc.doc)); err == nil {
				t.Fatal("expected strict schema rejection")
			}
		})
	}
}
