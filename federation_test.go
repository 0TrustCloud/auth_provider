package auth_provider

import "testing"

func TestFederationURL(t *testing.T) {
	got := FederationURL("https://defcon.0trust.cloud", "williwaw.app", "https://williwaw.app/")
	if got == "" {
		t.Fatal("expected federation url")
	}
	if want := "aud=williwaw.app"; !stringsContains(got, want) {
		t.Fatalf("FederationURL = %q, want substring %q", got, want)
	}
}

func TestFederatedHubRoutesShareIdentityHost(t *testing.T) {
	p := &Provider{}
	p.SetProductAuthRoutes([]ProductAuthRoute{
		{Slug: "defcon", PublicDomain: "defcon.chat", IdentityHost: "defcon.0trust.cloud", ClientName: "Ack"},
		{Slug: "williwaw", PublicDomain: "williwaw.app", IdentityHost: "defcon.0trust.cloud", ClientName: "Wiliwaw"},
		{Slug: "bandy", PublicDomain: "bandy.chat", IdentityHost: "defcon.0trust.cloud", ClientName: "Bandy"},
	})

	for _, host := range []string{"defcon.0trust.cloud", "defcon.chat", "williwaw.app", "bandy.chat"} {
		if route := p.productRouteForHost(host); route == nil {
			t.Fatalf("expected route for %s", host)
		}
	}
}

func stringsContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOfSubstring(s, sub) >= 0)
}

func indexOfSubstring(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}