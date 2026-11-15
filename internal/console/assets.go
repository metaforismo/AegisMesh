package console

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// Snapshot a bounded manifest at construction. Requests only index memory and
// can never select an OS or injected-FS path.
func (s *Server) loadAssets() error {
	s.assets = map[string]asset{}
	if s.ui == nil {
		return nil
	}

	total := 0
	return fs.WalkDir(s.ui, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("console UI: symlinks are not supported")
		}
		if len(s.assets) >= 1024 {
			return errors.New("console UI: asset count exceeds 1024")
		}
		if name != "index.html" && strings.HasSuffix(name, "/index.html") {
			return nil
		}
		file, err := s.ui.Open(name)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(file, 16<<20+1))
		file.Close()
		if err != nil {
			return err
		}
		total += len(body)
		if len(body) > 16<<20 || total > 32<<20 {
			return errors.New("console UI: asset byte limit exceeded")
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		assetPath := "/" + name
		cache := "no-cache"
		if name == "index.html" {
			assetPath = "/"
			cache = "no-store"
		}
		representation := asset{
			body:        body,
			contentType: contentType,
			cache:       cache,
		}
		representation.etag = contentETag(body)
		if name != "index.html" && len(body) >= 256 && compressible(contentType) {
			var compressed bytes.Buffer
			writer := gzip.NewWriter(&compressed)
			if _, err := writer.Write(body); err != nil {
				return err
			}
			if err := writer.Close(); err != nil {
				return err
			}
			if compressed.Len() < len(body) {
				representation.gzip = compressed.Bytes()
				representation.gzipETag = contentETag(representation.gzip)
				total += len(representation.gzip)
				if total > 32<<20 {
					return errors.New("console UI: encoded asset byte limit exceeded")
				}
			}
		}
		s.assets[assetPath] = representation
		return nil
	})
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	s.requests.Inc("static")
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 404, "not_found", "route not found")
		return
	}

	if s.ui == nil && r.URL.Path == "/" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == "GET" {
			_, _ = io.WriteString(w, "AegisMesh console API is running. The operator UI is not bundled in this build.\n")
		}
		return
	}

	asset, ok := s.assets[r.URL.Path]
	if !ok {
		fail(w, 404, "not_found", "asset not found")
		return
	}

	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("Cache-Control", asset.cache)
	body, etag := asset.body, asset.etag
	w.Header().Set("Vary", "Accept-Encoding")
	gzipQ, identityQ := encodingQuality(r.Header.Get("Accept-Encoding"))
	if len(asset.gzip) > 0 && gzipQ > 0 && gzipQ >= identityQ {
		body, etag = asset.gzip, asset.gzipETag
		w.Header().Set("Content-Encoding", "gzip")
	} else if identityQ == 0 {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	if asset.cache != "no-store" {
		w.Header().Set("ETag", etag)
		for _, tag := range strings.Split(r.Header.Get("If-None-Match"), ",") {
			tag = strings.TrimSpace(tag)
			if tag == "*" || strings.TrimPrefix(tag, "W/") == etag {
				w.WriteHeader(304)
				return
			}
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == "GET" {
		_, _ = w.Write(body)
	}
}

func contentETag(body []byte) string { return fmt.Sprintf(`"%x"`, sha256.Sum256(body)) }

func compressible(kind string) bool {
	return strings.HasPrefix(kind, "text/") || strings.Contains(kind, "javascript") ||
		strings.Contains(kind, "json") || strings.Contains(kind, "svg+xml")
}

func encodingQuality(header string) (gzipQ, identityQ float64) {
	identityQ = 1
	wildcard := -1.0
	explicitGzip, explicitIdentity := false, false
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		quality := 1.0
		if len(fields) > 1 {
			key, value, ok := strings.Cut(strings.TrimSpace(fields[1]), "=")
			parsed, err := strconv.ParseFloat(value, 64)
			if !ok || key != "q" || err != nil || parsed < 0 || parsed > 1 || math.IsNaN(parsed) {
				quality = 0
			} else {
				quality = parsed
			}
		}
		switch strings.ToLower(strings.TrimSpace(fields[0])) {
		case "gzip":
			gzipQ, explicitGzip = quality, true
		case "identity":
			identityQ, explicitIdentity = quality, true
		case "*":
			wildcard = quality
		}
	}
	if !explicitGzip && wildcard >= 0 {
		gzipQ = wildcard
	}
	if !explicitIdentity && wildcard == 0 {
		identityQ = 0
	}
	return gzipQ, identityQ
}
