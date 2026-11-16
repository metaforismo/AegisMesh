package strictjson

import (
	"fmt"
	"strings"
	"testing"
)

func TestObjectBoundsAndDuplicateKeys(t *testing.T) {
	fields := make([]string, 257)
	for i := range fields {
		fields[i] = fmt.Sprintf(`"field%d":0`, i)
	}
	values := strings.Repeat("0,", 255) + "0"
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"empty", "{}", true}, {"nested", `{"a":[{"b":true},null]}`, true},
		{"duplicate", `{"a":1,"a":2}`, false}, {"nested duplicate", `{"a":{"b":1,"b":2}}`, false},
		{"array root", "[]", false}, {"invalid UTF8", string([]byte{'{', '"', 255, '"', ':', '0', '}'}), false},
		{"trailing object", "{}{}", false}, {"trailing data", "{} x", false},
		{"256 fields", "{" + strings.Join(fields[:256], ",") + "}", true}, {"257 fields", "{" + strings.Join(fields, ",") + "}", false},
		{"256 array items", `{"a":[` + values + "]}", true}, {"257 array items", `{"a":[` + values + ",0]}", false},
		{"depth32", strings.Repeat(`{"a":`, 32) + "0" + strings.Repeat("}", 32), true},
		{"depth33", strings.Repeat(`{"a":`, 33) + "0" + strings.Repeat("}", 33), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidObject([]byte(tc.body)); got != tc.valid {
				t.Fatalf("valid=%t want=%t", got, tc.valid)
			}
		})
	}
}
