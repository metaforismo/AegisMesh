package console_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/metaforismo/aegismesh/internal/console"
)

func TestAssetRepresentationsAndConditionalRequests(t *testing.T) {
	body := []byte(strings.Repeat("const safe = 'synthetic';\n", 100))
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.UI = fstest.MapFS{
			"index.html": {Data: body}, "assets/app.js": {Data: body},
		}
	})
	var identityETag, gzipETag string
	for _, test := range []struct {
		encoding   string
		compressed bool
		status     int
	}{
		{"gzip", true, 200}, {"br, gzip;q=0.5, identity;q=0.2", true, 200},
		{"gzip;q=0", false, 200}, {"*;q=1", true, 200}, {"*;q=1,gzip;q=0", false, 200},
		{"identity;q=0,gzip;q=0", false, 406}, {"gzip;q=bad", false, 200}, {"gzip;q=0, identity;q=NaN", false, 406},
	} {
		request, _ := http.NewRequest("GET", h.base+"/assets/app.js", nil)
		request.Header.Set("Accept-Encoding", test.encoding)
		request.Header.Set("Range", "bytes=0-9")
		response, err := h.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != test.status {
			t.Fatalf("%s: %d", test.encoding, response.StatusCode)
		}
		if response.StatusCode == 406 {
			continue
		}
		if response.Header.Get("Vary") != "Accept-Encoding" || response.Header.Get("Cache-Control") != "no-cache" ||
			response.Header.Get("Content-Security-Policy") != console.CSP || response.Header.Get("Content-Range") != "" {
			t.Fatal("asset header regression")
		}
		etag := response.Header.Get("ETag")
		if !strings.HasPrefix(etag, `"`) || strings.HasPrefix(etag, "W/") {
			t.Fatal("missing strong hash")
		}
		if test.compressed {
			gzipETag = etag
			reader, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			raw, err = io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			identityETag = etag
			if response.Header.Get("Content-Encoding") != "" {
				t.Fatal("unexpected compression")
			}
		}
		if !bytes.Equal(raw, body) {
			t.Fatal("range or encoding changed asset bytes")
		}
		request, _ = http.NewRequest("GET", h.base+"/assets/app.js", nil)
		request.Header.Set("Accept-Encoding", test.encoding)
		request.Header.Set("If-None-Match", `"other", W/`+etag)
		response, err = h.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 304 || len(raw) != 0 || response.Header.Get("Content-Security-Policy") != console.CSP {
			t.Fatal("conditional request failed")
		}
	}
	if identityETag == gzipETag {
		t.Fatal("representations share a strong ETag")
	}
	response := h.request(t, apiRequest{method: "GET", path: "/"})
	if response.header.Get("Cache-Control") != "no-store" || response.header.Get("ETag") != "" {
		t.Fatal("index became cacheable")
	}
}
