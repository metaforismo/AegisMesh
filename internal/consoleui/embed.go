// Package consoleui embeds the operator console's static web UI.
//
// The UI is plain HTML, CSS and ES modules with no build step and no
// third-party code. It is written for the console server's Content Security
// Policy (no inline script or style, no eval, same-origin only); the tests in
// this package enforce that on every file that ships.
package consoleui

import (
	"embed"
	"io/fs"
)

//go:embed static
var embedded embed.FS

// FS returns the console UI rooted at the static directory, so "index.html"
// is the entry document and "assets/..." holds everything it loads.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		// fs.Sub only fails for an invalid path; "static" is a constant.
		panic("consoleui: " + err.Error())
	}
	return sub
}
