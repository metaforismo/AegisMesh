package protocol

import (
	"bytes"
	"encoding/json"
	"github.com/metaforismo/aegismesh/internal/strictjson"
)

// Decode strictly decodes one bounded JSON object, rejecting duplicate and unknown fields.
func Decode(body []byte, value any) error {
	if len(body) > MaxBodyBytes || !strictjson.ValidObject(body) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return ErrInvalid
	}
	return nil
}
