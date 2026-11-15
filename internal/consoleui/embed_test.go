package consoleui

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

var allowedExt = map[string]bool{".html": true, ".css": true, ".js": true, ".svg": true}

func files(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(FS(), p)
		if err != nil {
			return err
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded UI: %v", err)
	}
	return out
}

func TestEmbeddedUIHasEntryAndOnlyStaticTypes(t *testing.T) {
	all := files(t)
	if _, ok := all["index.html"]; !ok {
		t.Fatal("index.html missing from embedded UI")
	}
	for p := range all {
		if !allowedExt[path.Ext(p)] {
			t.Errorf("%s: unexpected file type in embedded UI", p)
		}
	}
}

var (
	htmlRef      = regexp.MustCompile(`(?:href|src)="([^"]+)"`)
	inlineScript = regexp.MustCompile(`(?is)<script\b[^>]*>\s*[^<\s]`)
	scriptTag    = regexp.MustCompile(`(?i)<script\b([^>]*)>`)
	styleAttr    = regexp.MustCompile(`(?i)\sstyle\s*=`)
	styleTag     = regexp.MustCompile(`(?i)<style\b`)
	handlerAttr  = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
)

// The console server sends script-src 'self' and style-src 'self'. Anything
// inline would be blocked in production, so it must never ship.
func TestHTMLIsCSPCompatible(t *testing.T) {
	for p, body := range files(t) {
		if path.Ext(p) != ".html" {
			continue
		}
		if inlineScript.MatchString(body) {
			t.Errorf("%s: inline <script> content", p)
		}
		for _, m := range scriptTag.FindAllStringSubmatch(body, -1) {
			if !strings.Contains(m[1], "src=") {
				t.Errorf("%s: <script> without src", p)
			}
		}
		if styleAttr.MatchString(body) || styleTag.MatchString(body) {
			t.Errorf("%s: inline style", p)
		}
		if handlerAttr.MatchString(body) {
			t.Errorf("%s: inline event handler attribute", p)
		}
		for _, m := range htmlRef.FindAllStringSubmatch(body, -1) {
			ref := m[1]
			if strings.Contains(ref, "://") || strings.HasPrefix(ref, "//") {
				t.Errorf("%s: external reference %q (CSP allows same-origin only)", p, ref)
				continue
			}
			if _, err := fs.Stat(FS(), path.Join(path.Dir(p), ref)); err != nil {
				t.Errorf("%s: reference %q does not resolve: %v", p, ref, err)
			}
		}
	}
}

var (
	jsImport = regexp.MustCompile(`(?m)^\s*(?:import|export)\s[^'"]*?from\s+'([^']+)'`)
	// Lazy screen loading uses import() with a string-literal, relative,
	// same-directory-tree .js specifier (screens/index.js). That form cannot
	// carry data: the module graph is fixed at build time, every specifier is
	// checked to resolve below, and CSP script-src 'self' applies to it. Any
	// other import() (a variable, a template, a URL) stays forbidden: the
	// "dynamic import" detector counts every import( and only literal ones
	// are subtracted.
	anyDynamicImport     = regexp.MustCompile(`\bimport\s*\(`)
	literalDynamicImport = regexp.MustCompile(`\bimport\('(\.{1,2}/[A-Za-z0-9_./-]+\.js)'\)`)
	// Markup and code sinks that would turn API data into behavior.
	forbiddenJS = map[string]*regexp.Regexp{
		"innerHTML":                regexp.MustCompile(`\binnerHTML\b`),
		"outerHTML":                regexp.MustCompile(`\bouterHTML\b`),
		"insertAdjacentHTML":       regexp.MustCompile(`\binsertAdjacentHTML\b`),
		"document.write":           regexp.MustCompile(`\bdocument\.write`),
		"eval":                     regexp.MustCompile(`\beval\s*\(`),
		"new Function":             regexp.MustCompile(`\bnew\s+Function\b`),
		"string timers":            regexp.MustCompile(`\bset(?:Timeout|Interval)\s*\(\s*['"\x60]`),
		"createContextualFragment": regexp.MustCompile(`createContextualFragment`),
		"DOMParser":                regexp.MustCompile(`\bDOMParser\b`),
		"cssText":                  regexp.MustCompile(`\bcssText\b`),
		"localStorage token":       regexp.MustCompile(`(?i)localStorage\.setItem\([^)]*(token|csrf|session)`),
	}
)

func TestJavaScriptAvoidsUnsafeSinksAndImportsResolve(t *testing.T) {
	for p, body := range files(t) {
		if path.Ext(p) != ".js" {
			continue
		}
		for name, re := range forbiddenJS {
			if re.MatchString(body) {
				t.Errorf("%s: forbidden construct %s", p, name)
			}
		}
		literal := literalDynamicImport.FindAllStringSubmatch(body, -1)
		if n := len(anyDynamicImport.FindAllString(body, -1)); n != len(literal) {
			t.Errorf("%s: forbidden construct dynamic import (%d import() calls, only %d use a literal relative .js specifier)", p, n, len(literal))
		}
		for _, m := range literal {
			if _, err := fs.Stat(FS(), path.Join(path.Dir(p), m[1])); err != nil {
				t.Errorf("%s: lazy import %q does not resolve", p, m[1])
			}
		}
		for _, m := range jsImport.FindAllStringSubmatch(body, -1) {
			spec := m[1]
			if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
				t.Errorf("%s: non-relative import %q (no third-party code ships)", p, spec)
				continue
			}
			if _, err := fs.Stat(FS(), path.Join(path.Dir(p), spec)); err != nil {
				t.Errorf("%s: import %q does not resolve", p, spec)
			}
		}
	}
}

func TestCSSLoadsNothingExternal(t *testing.T) {
	ext := regexp.MustCompile(`(?i)(@import|url\(\s*['"]?(https?:)?//)`)
	for p, body := range files(t) {
		if path.Ext(p) == ".css" && ext.MatchString(body) {
			t.Errorf("%s: external stylesheet or url()", p)
		}
	}
}

// The detectors above must actually fire, or the CSP tests pass vacuously.
func TestDetectorsCatchViolations(t *testing.T) {
	cases := []struct {
		name string
		re   *regexp.Regexp
		in   string
	}{
		{"inline script", inlineScript, `<script>alert(1)</script>`},
		{"style attr", styleAttr, `<div style="color:red">`},
		{"style tag", styleTag, `<STYLE>p{}</STYLE>`},
		{"handler", handlerAttr, `<img onerror="x()">`},
		{"innerHTML", forbiddenJS["innerHTML"], `el.innerHTML = s`},
		{"eval", forbiddenJS["eval"], `eval (s)`},
		{"string timer", forbiddenJS["string timers"], "setTimeout('x()', 1)"},
		{"dynamic import", anyDynamicImport, `await import(url)`},
		{"dynamic import (template)", anyDynamicImport, "import(`./${name}.js`)"},
	}
	for _, c := range cases {
		if !c.re.MatchString(c.in) {
			t.Errorf("%s: detector missed %q", c.name, c.in)
		}
	}
	// Only a literal relative .js specifier counts as allowed.
	for _, bad := range []string{`import(url)`, "import(`./${x}.js`)", `import('https://x.test/a.js')`, `import('./a.js' + q)`, `import("./a.js")`} {
		if literalDynamicImport.MatchString(bad) {
			t.Errorf("literal dynamic import allowlist accepts %q", bad)
		}
	}
	if !literalDynamicImport.MatchString(`() => import('./overview.js')`) {
		t.Error("literal dynamic import allowlist rejects a plain screen import")
	}
	if inlineScript.MatchString(`<script type="module" src="a.js"></script>`) {
		t.Error("inline script detector flags an external module script")
	}
}
