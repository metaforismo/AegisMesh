package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateURLTable(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		loopback  bool
		wantErr   string // "" means accept
		wantClass DenyClass
	}{
		{"ollama default", "http://127.0.0.1:11434/v1", true, "", ""},
		{"localhost name", "http://localhost:11434/v1", true, "", ""},
		{"v6 loopback", "http://[::1]:11434/v1", true, "", ""},
		{"loopback without opt-in", "http://127.0.0.1:11434/v1", false, string(DenyLoopback), DenyLoopback},
		{"mapped v4 loopback", "http://[::ffff:127.0.0.1]/v1", false, string(DenyLoopback), DenyLoopback},
		{"cloud metadata", "http://169.254.169.254/latest/meta-data/", true, string(DenyLinkLocal), DenyLinkLocal},
		{"v6 link-local", "http://[fe80::1]/x", true, string(DenyLinkLocal), DenyLinkLocal},
		{"rfc1918 10/8", "https://10.0.0.5/v1", true, string(DenyPrivate), DenyPrivate},
		{"rfc1918 172.16/12", "https://172.16.31.5/v1", true, string(DenyPrivate), DenyPrivate},
		{"rfc1918 192.168/16", "https://192.168.1.10/v1", true, string(DenyPrivate), DenyPrivate},
		{"ula ec2 metadata", "http://[fd00:ec2::254]/v1", true, string(DenyLinkLocal), DenyLinkLocal},
		{"unspecified v4", "http://0.0.0.0/v1", true, string(DenyUnspecified), DenyUnspecified},
		{"public https ok", "https://api.example.com/v1", false, "", ""},
		{"public ip https ok", "https://203.0.113.7/v1", false, "", ""},
		{"cleartext public denied", "http://api.example.com/v1", false, string(DenyCleartext), DenyCleartext},
		{"ftp scheme", "ftp://api.example.com/x", false, string(DenyScheme), DenyScheme},
		{"file scheme", "file:///etc/passwd", false, string(DenyScheme), DenyScheme},
		{"data url", "data:text/plain,hi", false, string(DenyScheme), DenyScheme},
		{"gopher", "gopher://h/x", false, string(DenyScheme), DenyScheme},
		{"userinfo", "http://user:pass@api.example.com/v1", false, string(DenyUserInfo), DenyUserInfo},
		{"query rejected", "https://api.example.com/v1?key=1", false, string(DenyAmbiguous), DenyAmbiguous},
		{"fragment rejected", "https://api.example.com/v1#frag", false, string(DenyAmbiguous), DenyAmbiguous},
		{"idn host rejected", "https://exämple.com/v1", false, string(DenyAmbiguous), DenyAmbiguous},
		{"hex ipv4 treated as hostname", "http://0x7f000001/v1", true, string(DenyCleartext), DenyCleartext},
		{"trailing dot loopback", "http://127.0.0.1.:11434/v1", true, "", ""},
		{"empty host", "https:///v1", false, string(DenyAmbiguous), DenyAmbiguous},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ValidateURL(Policy{AllowLoopback: tc.loopback}, tc.raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateURL(%q) = %v", tc.raw, err)
				}
				if u == nil || u.Host == "" {
					t.Fatalf("accepted but returned unusable URL: %+v", u)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateURL(%q) accepted, want %q", tc.raw, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) || !IsDenied(err) {
				t.Fatalf("err = %v, want class %q via IsDenied", err, tc.wantErr)
			}
			if tc.wantClass != "" && !strings.Contains(err.Error(), string(tc.wantClass)) {
				t.Fatalf("err = %v, want denial detail %q", err, tc.wantClass)
			}
		})
	}
}

// The connect-time control hook must enforce classification on the address
// the dialer actually resolved — proven here against a real listener.
func TestDialerControlEnforcesAtConnectTime(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	denied := NewDialer(Policy{AllowLoopback: false}, time.Second)
	addr := ln.Addr().String()
	if conn, err := denied.Dial("tcp", addr); err == nil {
		conn.Close()
		t.Fatalf("dial to %s succeeded with loopback policy off", addr)
	} else if !IsDenied(err) {
		t.Fatalf("want egress denial, got: %v", err)
	}

	allowed := NewDialer(Policy{AllowLoopback: true}, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := allowed.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial with loopback opt-in failed: %v", err)
	}
	conn.Close()
}

func TestRefuseAllRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, srv.URL+"/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: RefuseAllRedirects,
		Timeout:       2 * time.Second,
	}
	resp, err := client.Get(srv.URL + "/hop") //nolint:noctx // test-only
	if err != nil {
		t.Fatalf("redirect refusal must surface the response, not error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		t.Fatalf("status = %d, want the un-followed 3xx", resp.StatusCode)
	}
}

func TestClassifyMappedForms(t *testing.T) {
	p := Policy{}
	if got := Classify(net.ParseIP("::ffff:169.254.169.254"), p); got != DenyLinkLocal {
		t.Fatalf("mapped metadata IP classified %q", got)
	}
	if got := Classify(net.ParseIP("::ffff:10.1.2.3"), p); got != DenyPrivate {
		t.Fatalf("mapped RFC1918 classified %q", got)
	}
	if got := Classify(net.ParseIP("::ffff:127.0.0.1"), Policy{}); got != DenyLoopback {
		t.Fatalf("mapped loopback classified %q", got)
	}
	if got := Classify(net.ParseIP("2001:db8::1"), p); got != "" {
		t.Fatalf("documentation-range global should pass: %q", got)
	}
}

func TestIsDNSShape(t *testing.T) {
	for bad := range map[string]bool{"": true, "-a.b": true, "a..b": true, strings.Repeat("a", 64) + ".com": true} {
		if isDNSName(bad) {
			t.Fatalf("%q accepted as DNS name", bad)
		}
	}
	if !isDNSName("api.openai.com") || !isDNSName("my_host.internal") {
		t.Fatal("plausible names rejected")
	}
}

func TestErrorsAreTypedSentinels(t *testing.T) {
	_, err := ValidateURL(Policy{}, "ftp://x")
	if !errors.Is(err, errDenied) {
		t.Fatalf("errors.Is(errDenied) failed for %v", err)
	}
}

func TestMetadataDeniedEvenWithAllOptIns(t *testing.T) {
	p := Policy{AllowLoopback: true, AllowPrivate: true}
	for _, ip := range []string{"169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254"} {
		if got := Classify(net.ParseIP(ip), p); got != DenyLinkLocal {
			t.Fatalf("metadata %s classified %q with all opt-ins on", ip, got)
		}
	}
	_, err := ValidateURL(p, "http://169.254.169.254/latest/meta-data/iam/")
	if err == nil || !strings.Contains(err.Error(), string(DenyLinkLocal)) {
		t.Fatalf("metadata URL accepted under full opt-in: %v", err)
	}
}

func TestPrivateAllowedUnderExplicitOptIn(t *testing.T) {
	p := Policy{AllowPrivate: true}
	if got := Classify(net.ParseIP("10.1.2.3"), p); got != "" {
		t.Fatalf("RFC1918 still denied under opt-in: %q", got)
	}
	u, err := ValidateURL(Policy{AllowLoopback: true, AllowPrivate: true}, "https://172.16.31.5/v1")
	if err != nil || u == nil {
		t.Fatalf("internal gateway https rejected despite opt-in: %v", err)
	}
	// cleartext to private ranges stays denied — opt-in is not a blanket pass.
	if _, err := ValidateURL(Policy{AllowLoopback: true, AllowPrivate: true}, "http://192.168.1.10/v1"); err == nil {
		t.Fatal("cleartext private destination must stay denied")
	}
}
