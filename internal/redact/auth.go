package redact

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// AuthDigest is for bounded, memory-only distinctness, never evidence. Length
// framing prevents pairs such as (ab,c) and (a,bc) from colliding structurally.
func AuthDigest(kind, username, credential string) string {
	h := sha256.New()
	for _, v := range []string{kind, username, credential} {
		n := len(v)
		h.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
		h.Write([]byte(v))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HTTPAuthAttempts emits at most 16 digests of selected auth field values.
// Basic/password pairs share the SSH namespace; bearer/API keys share key.
func HTTPAuthAttempts(headers map[string][]string) []string {
	var out []string
	for _, name := range []string{"authorization", "proxy-authorization", "x-api-key", "api-key"} {
		for _, v := range headers[name] {
			if len(out) == 16 {
				return out
			}
			if len(v) == 0 || len(v) > 16384 {
				continue
			}
			v = strings.TrimSpace(v)
			if name == "authorization" || name == "proxy-authorization" {
				scheme, value, ok := strings.Cut(v, " ")
				if !ok {
					continue
				}
				switch {
				case strings.EqualFold(scheme, "Basic"):
					b, err := base64.StdEncoding.DecodeString(value)
					if err != nil {
						continue
					}
					user, pass, ok := strings.Cut(string(b), ":")
					if !ok {
						continue
					}
					out = append(out, AuthDigest("password", user, pass))
					continue
				case strings.EqualFold(scheme, "Bearer"):
					v = strings.TrimSpace(value)
				default:
					continue
				}
			}
			if v != "" {
				out = append(out, AuthDigest("key", "", v))
			}
		}
	}
	return out
}
