package auth_provider

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestIsPlatformFaceHostname(t *testing.T) {
	for _, h := range []string{"0trust.name", "www.0trust.name", "dns.0trust.name"} {
		if !isPlatformFaceHostname(h) {
			t.Fatalf("expected face host %s", h)
		}
	}
	if isPlatformFaceHostname("0trust.cloud") {
		t.Fatal("canonical host is not a face")
	}
}

func TestRedirectPlatformFaceAuth(t *testing.T) {
	p := &Provider{issuer: "https://0trust.cloud"}
	p.ensureDefaultPlatformFaces()

	req := httptest.NewRequest(http.MethodGet, "https://0trust.name/auth?return_to=/nameservice", nil)
	req.Host = "0trust.name"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	if !p.RedirectPlatformFaceAuth(w, req) {
		t.Fatal("expected redirect from face host")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("status %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://0trust.cloud/auth?return_to=") {
		t.Fatalf("location = %s", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	ret := u.Query().Get("return_to")
	if !strings.Contains(ret, "0trust.name/auth/session-consume") {
		t.Fatalf("return_to should handoff to face: %s", ret)
	}
	if !strings.Contains(ret, "dest=%2Fnameservice") && !strings.Contains(ret, "dest=/nameservice") {
		// dest is query-escaped inside return_to URL
		ru, _ := url.Parse(ret)
		if ru.Query().Get("dest") != "/nameservice" {
			t.Fatalf("dest missing in %s", ret)
		}
	}
}

func TestRedirectPlatformFaceAuthSkipsCanonical(t *testing.T) {
	p := &Provider{issuer: "https://0trust.cloud"}
	p.ensureDefaultPlatformFaces()
	// Need wa with RPID for canonicalHost — without it canonicalHost falls back to issuer host.
	req := httptest.NewRequest(http.MethodGet, "https://0trust.cloud/auth", nil)
	req.Host = "0trust.cloud"
	w := httptest.NewRecorder()
	if p.RedirectPlatformFaceAuth(w, req) {
		t.Fatal("should not redirect on canonical host")
	}
}

func TestHostMatchesTrustedProductIncludesName(t *testing.T) {
	if !hostMatchesTrustedProduct("0trust.name") {
		t.Fatal("0trust.name should be trusted")
	}
	if !hostMatchesTrustedProduct("dns.0trust.name") {
		t.Fatal("dns.0trust.name should be trusted")
	}
}

func TestAllowedReturnToPlatformFace(t *testing.T) {
	p := &Provider{issuer: "https://0trust.cloud"}
	p.ensureDefaultPlatformFaces()
	if !p.allowedReturnTo("https://0trust.name/auth/session-consume?dest=/index") {
		t.Fatal("face session-consume should be allowed return_to")
	}
	if !p.allowedReturnTo("https://0trust.name/index") {
		t.Fatal("face index should be allowed return_to")
	}
}
