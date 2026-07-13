package auth_provider

import (
	"testing"
)

func TestAllowedReturnTo(t *testing.T) {
	p := &Provider{issuer: "https://0trust.cloud"}

	cases := []struct {
		raw  string
		want bool
	}{
		{"", false},
		{"/access/ack", true},
		{"/dashboard", true},
		{"https://0trust.cloud/apps", true},
		{"https://tunneltug.com/dashboard", true},
		{"https://tunneltug.0trust.cloud/auth/callback", true},
		{"https://williwaw.app/", true},
		{"https://defcon.chat/docs", true},
		{"https://evil.example/phish", false},
		{"http://127.0.0.1:3000/callback", true},
		{"javascript:alert(1)", false},
	}
	for _, tc := range cases {
		if got := p.allowedReturnTo(tc.raw); got != tc.want {
			t.Errorf("allowedReturnTo(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestBuildPostAuthRedirect(t *testing.T) {
	p := &Provider{issuer: "https://0trust.cloud"}

	if got := p.buildPostAuthRedirect("/access/motionkb", "tok"); got != "/access/motionkb" {
		t.Fatalf("relative redirect = %q", got)
	}
	ext := p.buildPostAuthRedirect("https://tunneltug.com/dashboard", "tok")
	if ext != "https://tunneltug.com/dashboard" {
		t.Fatalf("external redirect = %q", ext)
	}
	local := p.buildPostAuthRedirect("http://127.0.0.1:3000/cb", "tok")
	if local == "http://127.0.0.1:3000/cb" {
		t.Fatal("expected session_id appended for localhost redirect")
	}
}