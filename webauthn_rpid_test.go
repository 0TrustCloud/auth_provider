package auth_provider

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnForProductFaceUsesCanonicalRPID(t *testing.T) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "0Trust",
		RPID:          "0trust.cloud",
		RPOrigins:     []string{"https://0trust.cloud"},
	})
	if err != nil {
		t.Fatal(err)
	}
	waTunnel, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "0Trust Tunnel",
		RPID:          "0trust.services",
		RPOrigins:     []string{"https://0trust.services"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{wa: wa, waTunnel: waTunnel, tunnelRPID: "0trust.services"}

	// Product face via auth_proxy tunnel header must still use 0trust.cloud RP ID
	req := httptest.NewRequest(http.MethodGet, "/auth/login/begin", nil)
	req.Header.Set("X-0Trust-Tunnel", "1")
	req.Header.Set("X-Forwarded-Host", "social.0trust.cloud")
	got := p.webAuthnFor(req)
	if got.Config.RPID != "0trust.cloud" {
		t.Fatalf("product face RPID=%q want 0trust.cloud", got.Config.RPID)
	}
	found := false
	for _, o := range got.Config.RPOrigins {
		if o == "https://social.0trust.cloud" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RPOrigins missing face origin: %v", got.Config.RPOrigins)
	}
}

func TestWebAuthnForServicesTunnelUsesServicesRPID(t *testing.T) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "0Trust",
		RPID:          "0trust.cloud",
		RPOrigins:     []string{"https://0trust.cloud"},
	})
	if err != nil {
		t.Fatal(err)
	}
	waTunnel, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "0Trust Tunnel",
		RPID:          "0trust.services",
		RPOrigins:     []string{"https://0trust.services"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{wa: wa, waTunnel: waTunnel, tunnelRPID: "0trust.services"}

	req := httptest.NewRequest(http.MethodGet, "/auth/login/begin", nil)
	req.Header.Set("X-0Trust-Tunnel", "1")
	req.Header.Set("X-Forwarded-Host", "myapp.0trust.services")
	got := p.webAuthnFor(req)
	if got.Config.RPID != "0trust.services" {
		t.Fatalf("services tunnel RPID=%q want 0trust.services", got.Config.RPID)
	}
}
