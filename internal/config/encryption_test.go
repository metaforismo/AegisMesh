package config

import (
	"encoding/json"
	"strings"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

func TestStorageEncryptionConfigMatrix(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.Recipient().String()
	cases := []struct {
		name, encryption string
		valid, enabled   bool
	}{
		{name: "omitted", valid: true},
		{name: "disabled", encryption: `{enabled: false}`, valid: true},
		{name: "enabled", encryption: `{enabled: true, recipient: "` + recipient + `"}`, valid: true, enabled: true},
		{name: "empty object", encryption: `{}`, valid: true},
		{name: "missing recipient", encryption: `{enabled: true}`},
		{name: "empty recipient", encryption: `{enabled: true, recipient: ""}`},
		{name: "padded recipient", encryption: `{enabled: true, recipient: " ` + recipient + `"}`},
		{name: "multiple recipients", encryption: `{enabled: true, recipient: "` + recipient + `,` + recipient + `"}`},
		{name: "recipient without enable", encryption: `{recipient: "` + recipient + `"}`},
		{name: "disabled with recipient", encryption: `{enabled: false, recipient: "` + recipient + `"}`},
		{name: "private recipient", encryption: `{enabled: true, recipient: "` + identity.String() + `"}`},
		{name: "inline identity field", encryption: `{enabled: true, recipient: "` + recipient + `", identity: "` + identity.String() + `"}`},
		{name: "identity file in config", encryption: `{enabled: true, recipient: "` + recipient + `", identity_file: "/secure/key"}`},
		{name: "identity env in config", encryption: `{enabled: true, recipient: "` + recipient + `", identity_env: "AGE_KEY"}`},
		{name: "plugin recipient", encryption: `{enabled: true, recipient: "age1yubikey1example"}`},
		{name: "wrong enabled type", encryption: `{enabled: 7}`},
	}
	for _, tc := range cases {
		for _, extension := range []string{"yaml", "json"} {
			t.Run(tc.name+"/"+extension, func(t *testing.T) {
				source := minimalValid
				if tc.encryption != "" {
					source += "\nstorage:\n  encryption: " + tc.encryption + "\n"
				}
				if extension == "json" {
					var doc any
					if err := yaml.Unmarshal([]byte(source), &doc); err != nil {
						t.Fatal(err)
					}
					raw, err := json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					source = string(raw)
				}
				cfg, err := Load(writeTemp(t, "mesh."+extension, source))
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%v err=%v", tc.valid, err)
				}
				if err != nil && strings.Contains(err.Error(), identity.String()) {
					t.Fatal("private identity disclosed")
				}
				if cfg != nil {
					enabled := cfg.Storage.Encryption != nil && cfg.Storage.Encryption.Enabled
					if enabled != tc.enabled {
						t.Fatalf("enabled=%v want=%v", enabled, tc.enabled)
					}
				}
			})
		}
	}
}
