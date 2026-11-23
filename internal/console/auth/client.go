package auth

import "strings"

// Client families form a closed vocabulary; the raw User-Agent is never stored.
const (
	ClientUnknown = "Unknown client"
	ClientOther   = "Other client"
)

// ClientFamily reduces a User-Agent header to a fixed "<browser> on <os>" or
// tool label. Only constant strings are returned, so header text never reaches
// session listings, responses or the audit trail.
func ClientFamily(userAgent string) string {
	if userAgent == "" {
		return ClientUnknown
	}
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	ua := strings.ToLower(userAgent)
	switch {
	case strings.HasPrefix(ua, "curl/"):
		return "curl"
	case strings.HasPrefix(ua, "wget/"):
		return "Wget"
	case strings.HasPrefix(ua, "go-http-client/"):
		return "Go HTTP client"
	case strings.HasPrefix(ua, "python-requests/"), strings.HasPrefix(ua, "python-urllib"),
		strings.HasPrefix(ua, "python-httpx/"), strings.HasPrefix(ua, "aiohttp/"):
		return "Python client"
	case strings.HasPrefix(ua, "powershell/"), strings.Contains(ua, "windowspowershell"):
		return "PowerShell"
	case strings.HasPrefix(ua, "node-fetch"), strings.HasPrefix(ua, "undici"), strings.HasPrefix(ua, "axios/"):
		return "Node.js client"
	}
	browser := ""
	switch {
	case strings.Contains(ua, "edg/"), strings.Contains(ua, "edga/"), strings.Contains(ua, "edgios/"):
		browser = "Edge"
	case strings.Contains(ua, "opr/"), strings.Contains(ua, "opera"):
		browser = "Opera"
	case strings.Contains(ua, "firefox/"), strings.Contains(ua, "fxios/"):
		browser = "Firefox"
	case strings.Contains(ua, "chrome/"), strings.Contains(ua, "crios/"), strings.Contains(ua, "chromium/"):
		browser = "Chrome"
	case strings.Contains(ua, "safari/") && strings.Contains(ua, "version/"):
		browser = "Safari"
	}
	system := ""
	switch {
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ios"):
		system = "iOS"
	case strings.Contains(ua, "android"):
		system = "Android"
	case strings.Contains(ua, "cros"):
		system = "ChromeOS"
	case strings.Contains(ua, "windows"):
		system = "Windows"
	case strings.Contains(ua, "mac os x"), strings.Contains(ua, "macintosh"):
		system = "macOS"
	case strings.Contains(ua, "linux"), strings.Contains(ua, "x11"):
		system = "Linux"
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	default:
		return ClientOther
	}
}
