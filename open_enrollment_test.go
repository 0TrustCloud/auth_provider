package auth_provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenEnrollmentHosts(t *testing.T) {
	p := &Provider{}
	p.SetOpenEnrollmentHosts([]string{
		"https://williwaw.app:443",
		"DEFCON.CHAT",
		"williwaw.0trust.cloud",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/provision/status", nil)
	req.Header.Set("X-Forwarded-Host", "williwaw.app")
	if !p.isOpenEnrollment(req) {
		t.Fatal("expected williwaw.app to allow open enrollment")
	}

	req.Header.Set("X-Forwarded-Host", "defcon.chat")
	if !p.isOpenEnrollment(req) {
		t.Fatal("expected defcon.chat to allow open enrollment")
	}

	req.Header.Set("X-Forwarded-Host", "0trust.cloud")
	if p.isOpenEnrollment(req) {
		t.Fatal("platform admin should remain invite-only")
	}
}

func TestCanRegisterOpenEnrollment(t *testing.T) {
	p := &Provider{}
	p.SetOpenEnrollmentHosts([]string{"defcon.chat"})

	req := httptest.NewRequest(http.MethodGet, "/auth/register/begin", nil)
	req.Header.Set("X-Forwarded-Host", "defcon.chat")

	allowed, reason := p.canRegister("new-user", req)
	if !allowed || reason != "" {
		t.Fatalf("canRegister = (%v, %q), want (true, \"\")", allowed, reason)
	}
}

func TestHandleProvisionStatusOpenEnrollment(t *testing.T) {
	p := &Provider{}
	p.SetOpenEnrollmentHosts([]string{"williwaw.app"})

	req := httptest.NewRequest(http.MethodGet, "/auth/provision/status?username=alice", nil)
	req.Header.Set("X-Forwarded-Host", "williwaw.app")
	rec := httptest.NewRecorder()
	p.HandleProvisionStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"open_enrollment":true`, `"verified":true`, `"ready":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %q missing %q", body, want)
		}
	}
}