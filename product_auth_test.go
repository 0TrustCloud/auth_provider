package auth_provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductRouteForHost(t *testing.T) {
	p := &Provider{}
	p.SetProductAuthRoutes([]ProductAuthRoute{
		{Slug: "williwaw", PublicDomain: "williwaw.app", IdentityHost: "williwaw.0trust.cloud", ClientName: "Wiliwaw"},
		{Slug: "mail", PublicDomain: "mail.0trust.cloud", IdentityHost: "mail.0trust.cloud", ClientName: "MeshMail"},
	})

	if route := p.productRouteForHost("williwaw.0trust.cloud"); route == nil || route.Slug != "williwaw" {
		t.Fatalf("identity host route = %#v", route)
	}
	if route := p.productRouteForHost("williwaw.app"); route == nil {
		t.Fatal("expected public domain route")
	}
	if route := p.productRouteForHost("mail.0trust.cloud"); route == nil || route.ClientName != "MeshMail" {
		t.Fatalf("mail product route = %#v", route)
	}
	if route := p.productRouteForHost("0trust.cloud"); route != nil {
		t.Fatal("platform host should not match product route")
	}
}

func TestProductClientName(t *testing.T) {
	cases := map[string]string{
		"williwaw":  "Wiliwaw",
		"mail":      "MeshMail",
		"search":    "0Trust-Search",
		"defcon":    "Ack",
		"unknown":   "",
	}
	for slug, want := range cases {
		if got := ProductClientName(slug); got != want {
			t.Fatalf("ProductClientName(%q) = %q, want %q", slug, got, want)
		}
	}
}

func TestNormalizeProductReturnTo(t *testing.T) {
	p := &Provider{}
	route := &ProductAuthRoute{PublicDomain: "williwaw.app"}

	cases := map[string]string{
		"":         "https://williwaw.app/",
		"/index":   "https://williwaw.app/",
		"/apps":    "https://williwaw.app/",
		"/feed":    "https://williwaw.app/feed",
		"https://williwaw.app/dashboard": "https://williwaw.app/dashboard",
	}
	for in, want := range cases {
		if got := p.normalizeProductReturnTo(route, in); got != want {
			t.Fatalf("normalizeProductReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProductRouteForReturnTo(t *testing.T) {
	p := &Provider{}
	p.SetProductAuthRoutes([]ProductAuthRoute{
		{Slug: "defcon", PublicDomain: "defcon.chat", IdentityHost: "defcon.0trust.cloud", ClientName: "Ack"},
	})

	if route := p.productRouteForReturnTo("https://defcon.chat/room"); route == nil || route.Slug != "defcon" {
		t.Fatalf("return_to route = %#v", route)
	}
	if route := p.productRouteForReturnTo("/access/ack"); route != nil {
		t.Fatal("relative return_to should not match product public route")
	}
}

func TestWantsAuthJSONResponse(t *testing.T) {
	cases := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{
			name: "browser navigation",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/auth?return_to=https%3A%2F%2Fmotionkb.com%2Fsites", nil)
				r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				r.Header.Set("Sec-Fetch-Dest", "document")
				return r
			}(),
			want: false,
		},
		{
			name: "webauthn finish",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/auth/login/finish?username=alice", strings.NewReader(`{}`))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Sec-Fetch-Dest", "empty")
				return r
			}(),
			want: true,
		},
		{
			name: "fetch json accept",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/auth", nil)
				r.Header.Set("Accept", "application/json")
				r.Header.Set("Sec-Fetch-Dest", "empty")
				return r
			}(),
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantsAuthJSONResponse(tc.req); got != tc.want {
				t.Fatalf("wantsAuthJSONResponse() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRespondAuthRedirectBrowser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth?return_to=https%3A%2F%2Fmotionkb.com%2Fsites", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Sec-Fetch-Dest", "document")
	rec := httptest.NewRecorder()

	respondAuthRedirect(rec, req, "https://motionkb.com/auth/callback?code=test&state=product_motionkb")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "motionkb.com/auth/callback") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestRespondAuthRedirectFetch(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login/finish", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	rec := httptest.NewRecorder()

	respondAuthRedirect(rec, req, "https://motionkb.com/auth/callback?code=test")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), `"redirect_to"`) {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestHandlePostAuthProductDefaultWithoutClient(t *testing.T) {
	p := &Provider{}
	p.SetProductAuthRoutes([]ProductAuthRoute{
		{Slug: "williwaw", PublicDomain: "williwaw.app", IdentityHost: "williwaw.0trust.cloud", ClientName: "Wiliwaw"},
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/register/finish?username=alice", nil)
	req.Header.Set("X-Forwarded-Host", "williwaw.0trust.cloud")
	rec := httptest.NewRecorder()

	route := p.productRouteForRequest(req)
	if route == nil {
		t.Fatal("expected product route")
	}
	if p.productRouteForReturnTo(strings.TrimSpace(req.URL.Query().Get("return_to"))) != nil {
		t.Fatal("unexpected return_to route")
	}
	if p.respondProductOIDCSession(rec, req, "alice", route, "") {
		t.Fatal("expected product OIDC to fail without registered client")
	}
}