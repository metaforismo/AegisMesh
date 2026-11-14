package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// Reject duplicate keys and deep containers before decoding into request types.
func validObject(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}

	var walk func(json.Token, int) error
	walk = func(token json.Token, depth int) error {
		if depth > 32 {
			return errors.New("JSON depth exceeded")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] || len(seen) >= 256 {
					return errors.New("duplicate or excessive JSON fields")
				}
				seen[key] = true
				value, err := decoder.Token()
				if err != nil {
					return err
				}
				if err = walk(value, depth+1); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > 256 {
					return errors.New("excessive JSON array")
				}
				value, err := decoder.Token()
				if err != nil {
					return err
				}
				if err = walk(value, depth+1); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		}
		return errors.New("invalid JSON delimiter")
	}

	if walk(token, 0) != nil {
		return false
	}

	_, err = decoder.Token()
	return err == io.EOF
}
