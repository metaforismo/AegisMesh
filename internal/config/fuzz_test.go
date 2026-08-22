package config

import (
	"strings"
	"testing"
)

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(minimalValid))
	f.Add([]byte("api_version: bad\n"))
	f.Add([]byte("api_version: aegismesh.io/v1alpha1\nsensors: [{id: x, kind: http, listen: \"1.2.3.4:1\"}]\n"))
	f.Add([]byte{})
	f.Add([]byte("\x00\x01\x02"))
	f.Add([]byte(strings.Repeat("[", 500)))
	f.Add([]byte("sensors: {a: b}\n"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var c Config
		err := strictYAML(raw, &c)
		if err != nil {
			return // rejected at decode; fine
		}
		// Must not panic anywhere downstream regardless of content.
		CheckKindFields(raw, ".yaml")
		c.applyDefaults()
		if c.Runtime.DataDir != "" {
			c.SourcePath = "/tmp/fuzz/mesh.yaml"
			_ = c.Validate()
		}
	})
}
