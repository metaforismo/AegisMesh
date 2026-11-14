package console

import (
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
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
		cache := "public, max-age=3600"
		if name == "index.html" {
			assetPath = "/"
			cache = "no-store"
		}
		s.assets[assetPath] = asset{
			body:        body,
			contentType: contentType,
			cache:       cache,
		}
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
	if r.Method == "GET" {
		_, _ = w.Write(asset.body)
	}
}
