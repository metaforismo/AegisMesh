// Package egress enforces the outbound destination policy for every network
// connection AegisMesh initiates itself (currently: LLM provider calls).
//
// Threats addressed (THREAT-MODEL TB4): a decoy runtime that talks to a model
// provider carries captured attacker traffic OUT of the machine. The policy
// exists so that traffic can only ever reach the endpoint the operator named,
// never cloud metadata services or internal networks, and so a compromised or
// misconfigured provider hostname cannot silently pivot elsewhere.
//
// Layered enforcement:
//
//  1. URL validation at configuration time (ValidateURL): scheme, credentials
//     embedded in URLs, ambiguous hosts, and destination class are checked
//     before anything is dialed.
//  2. Connect-time validation (NewDialer's control hook): the dialer
//     re-classifies the ACTUAL resolved address inside the kernel-connect
//     critical section, closing the classic DNS-rebinding window between
//     "validate a name" and "connect to what it resolved to".
//  3. Redirect refusal: redirects are never followed; a provider answering
//     3xx is treated as a protocol failure. Same-host redirect chains would
//     still be re-resolved per hop, so refusing outright is strictly safer
//     and removes an entire ambiguity class.
//
// HONEST LIMITATIONS (documented, not hidden):
//
//   - Hostnames are re-resolved per connection. An adversary who controls
//     DNS for a configured hostname can change its destination BETWEEN
//     connections; each individual connection is still checked, but we do
//     not pin the first-seen address set. Operators who need pinning should
//     configure IP literals.
//   - Classification uses Go's stdlib IP semantics. Non-standard textual
//     forms (hex/octal IPv4 like 0x7f000001) are treated as hostnames: they
//     are not special-cased here, and whatever they eventually resolve to
//     passes through the same connect-time check.
package egress

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Policy states which destination classes this process may contact.
type Policy struct {
	// AllowLoopback permits loopback destinations (127.0.0.0/8, ::1, the
	// name "localhost") over cleartext http — the local Ollama case.
	// Link-local/cloud metadata stays denied even with this set.
	AllowLoopback bool

	// AllowPrivate permits RFC1918 and IPv6 ULA destinations — the corporate
	// LLM-gateway-on-an-internal-address case. It is an explicit operator
	// decision because it lets captured attacker traffic flow toward
	// internal networks. Link-local/cloud metadata remains denied even with
	// both flags set: no legitimate model provider lives there.
	AllowPrivate bool
}

var errDenied = fmt.Errorf("egress: destination denied by policy")

// DenyClass describes why a destination was refused, for actionable errors.
type DenyClass string

const (
	DenyScheme      DenyClass = "scheme"
	DenyUserInfo    DenyClass = "userinfo"
	DenyAmbiguous   DenyClass = "ambiguous-host"
	DenyLoopback    DenyClass = "loopback"
	DenyPrivate     DenyClass = "private"
	DenyLinkLocal   DenyClass = "link-local"
	DenyUnspecified DenyClass = "unspecified"
	DenyMulticast   DenyClass = "multicast"
	DenyCleartext   DenyClass = "cleartext"
)

func deny(class DenyClass, detail string) error {
	return fmt.Errorf("%w: %s: %s", errDenied, class, detail)
}

// IsDenied reports whether err came from this package's policy checks.
func IsDenied(err error) bool { return err != nil && strings.Contains(err.Error(), errDenied.Error()) }

// metadataIPs are cloud instance metadata endpoints. They sit in ranges that
// other flags may otherwise permit (link-local for IPv4, ULA for AWS's IPv6
// endpoint), so they are pinned here and denied unconditionally: no
// legitimate model provider lives at these addresses, while every VM-borne
// credential does.
var metadataIPs = map[string]bool{
	"169.254.169.254": true,
	"fd00:ec2::254":   true,
}

// Classify maps one IP to a denial class, or "" when permitted by p.
// Metadata endpoints, link-local, unspecified, and multicast destinations are
// denied unconditionally; loopback and private ranges require their opt-ins.
func Classify(ip net.IP, p Policy) DenyClass {
	// Canonicalize IPv4-mapped IPv6 (::ffff:a.b.c.d) to plain v4 so mapped
	// forms cannot masquerade as unlisted global addresses. Genuine v6
	// addresses are unaffected (To4 returns nil for them).
	if t4 := ip.To4(); t4 != nil {
		ip = t4
	}
	if ip.IsUnspecified() { // 0.0.0.0 / ::
		return DenyUnspecified
	}
	if metadataIPs[ip.String()] {
		return DenyLinkLocal
	}
	switch {
	case ip.IsLoopback():
		if !p.AllowLoopback {
			return DenyLoopback
		}
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return DenyLinkLocal
	case ip.IsPrivate(): // RFC1918 + remaining ULA space
		if !p.AllowPrivate {
			return DenyPrivate
		}
	case ip.IsMulticast():
		return DenyMulticast
	}
	return ""
}

// ValidateURL applies the full static policy to an operator-configured
// endpoint URL and returns the normalized *url.URL on success.
//
// Rules:
//   - schemes: exactly "http" or "https"
//   - no embedded userinfo (credentials in URLs leak into logs/hops)
//   - no query string or fragment (this validates a BASE endpoint, not a
//     resource address)
//   - host: IP literals are classified immediately; names must be non-empty,
//     pure ASCII (no IDN homograph ambiguity), and contain no separators
//     beyond dots, digits, hyphens and letters
//   - non-loopback http is denied: cleartext beyond the machine boundary
//     requires a deliberate policy change, not a default
func ValidateURL(p Policy, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, deny(DenyAmbiguous, fmt.Sprintf("unparseable URL: %v", err))
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, deny(DenyScheme, fmt.Sprintf("%q is not http(s)", u.Scheme))
	}
	if u.User != nil {
		return nil, deny(DenyUserInfo, "credentials embedded in URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return nil, deny(DenyAmbiguous, "query/fragment not allowed in an endpoint base URL")
	}
	host := u.Hostname() // strips brackets for v6, drops port
	if host == "" {
		return nil, deny(DenyAmbiguous, "empty host")
	}
	// Trailing-dot FQDN form resolves identically; normalize before checks.
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if !isASCII(host) {
		return nil, deny(DenyAmbiguous, "non-ASCII (internationalized) hostnames are not accepted")
	}
	if ip := net.ParseIP(host); ip != nil {
		if class := Classify(ip, p); class != "" {
			return nil, deny(class, fmt.Sprintf("IP %s", u.Host))
		}
	} else if !isDNSName(host) {
		return nil, deny(DenyAmbiguous, fmt.Sprintf("host %q is neither an IP nor a plausible DNS name", host))
	} else if strings.EqualFold(host, "localhost") && !p.AllowLoopback {
		return nil, deny(DenyLoopback, `name "localhost"`)
	}
	if u.Scheme == "http" {
		isLiteralLoop := isIPLiteralLoopback(host)
		if !(p.AllowLoopback && (isLiteralLoop || strings.EqualFold(host, "localhost"))) {
			return nil, deny(DenyCleartext, "non-loopback endpoints must use https")
		}
	}
	return u, nil
}

func isIPLiteralLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// isDNSName mirrors stdlib-ish hostname shape: letters/digits/hyphens/dots,
// no leading/trailing hyphen per label, length-bounded.
func isDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// NewDialer returns a dialer whose control hook re-checks every resolved
// address against the policy at connect time. This is the authoritative
// gate: it sees exactly what the OS is about to connect to, so DNS
// rebinding between validation and connection cannot bypass classification.
func NewDialer(p Policy, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	d.Control = func(network, address string, _ syscall.RawConn) error {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return deny(DenyScheme, "network "+network+" is not TCP")
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return deny(DenyAmbiguous, fmt.Sprintf("dial address %q", address))
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return deny(DenyAmbiguous, fmt.Sprintf("non-IP dial target %q", host))
		}
		if class := Classify(ip, p); class != "" {
			return deny(class, fmt.Sprintf("connect to %s", address))
		}
		return nil
	}
	return d
}

// RefuseAllRedirects is an http.Client.CheckRedirect implementation: every
// 3xx is surfaced instead of followed. See the package doc for why.
func RefuseAllRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
