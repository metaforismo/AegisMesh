package ext

import "testing"

func FuzzRejectDuplicateJSONKeys(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"type":"hello_ok","protocol":1,"name":"observer","version":"1.0.0"}`),
		[]byte(`{"type":"response","id":"req-1","result":{"event_id":"event","accepted":true}}`),
		[]byte(`{"type":"response","type":"error"}`),
		[]byte(`{"result":{"accepted":true,"accepted":false}}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxManifestBytes {
			t.Skip()
		}
		_ = rejectDuplicateJSONKeys(raw)
	})
}
