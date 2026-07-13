package auth_provider

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Default platform public faces that share the control plane but are not under the
// WebAuthn RP ID (0trust.cloud). Passkeys must run on the canonical host; these
// faces get a one-time session handoff afterward.
var defaultPlatformFaceHosts = []string{
	"0trust.name",
	"www.0trust.name",
	"dns.0trust.name",
	"rdap.0trust.name",
	"ns1.0trust.name",
	"ns2.0trust.name",
}

const sessionHandoffTTL = 2 * time.Minute

type sessionHandoff struct {
	Username  string    `json:"username"`
	Token     string    `json:"token"` // raw cookie token (without user_session_ prefix)
	Dest      string    `json:"dest"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SetPlatformFaceHosts configures ICANN/public faces of the platform IdP (e.g. 0trust.name).
// Auth UI and WebAuthn ceremonies are forced onto the canonical issuer host.
func (p *Provider) SetPlatformFaceHosts(hosts []string) {
	if p == nil {
		return
	}
	if p.platformFaceHosts == nil {
		p.platformFaceHosts = make(map[string]struct{})
	}
	for _, h := range hosts {
		h = normalizeEnrollmentHost(h)
		if h != "" {
			p.platformFaceHosts[h] = struct{}{}
		}
	}
}

func (p *Provider) ensureDefaultPlatformFaces() {
	if p == nil {
		return
	}
	if len(p.platformFaceHosts) > 0 {
		return
	}
	p.SetPlatformFaceHosts(defaultPlatformFaceHosts)
}

func (p *Provider) isPlatformFaceHost(host string) bool {
	if p == nil {
		return false
	}
	p.ensureDefaultPlatformFaces()
	host = normalizeEnrollmentHost(host)
	if host == "" {
		return false
	}
	_, ok := p.platformFaceHosts[host]
	return ok
}

func (p *Provider) canonicalHost() string {
	if p == nil {
		return "0trust.cloud"
	}
	if p.wa != nil && p.wa.Config != nil && strings.TrimSpace(p.wa.Config.RPID) != "" {
		return normalizeEnrollmentHost(p.wa.Config.RPID)
	}
	if u, err := url.Parse(p.issuer); err == nil && u.Host != "" {
		return normalizeEnrollmentHost(u.Host)
	}
	return "0trust.cloud"
}

func (p *Provider) canonicalOrigin() string {
	if p != nil && strings.TrimSpace(p.issuer) != "" {
		return strings.TrimRight(p.issuer, "/")
	}
	return "https://" + p.canonicalHost()
}

func (p *Provider) isCanonicalHost(host string) bool {
	return normalizeEnrollmentHost(host) == p.canonicalHost()
}

// RedirectPlatformFaceAuth sends browsers on 0trust.name (etc.) to the canonical
// IdP so WebAuthn rpId=0trust.cloud is valid. Returns true if a redirect was written.
// Skips redirect when the face host already has a valid session cookie.
func (p *Provider) RedirectPlatformFaceAuth(w http.ResponseWriter, r *http.Request) bool {
	if p == nil || r == nil {
		return false
	}
	host := requestPublicHost(r)
	if host == "" || p.isCanonicalHost(host) || !p.isPlatformFaceHost(host) {
		return false
	}

	// Face already authenticated — do not bounce to the IdP again.
	if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
		if session, err := p.resolveSession(cookie.Value); err == nil && session.Valid {
			return false
		}
	}

	// Already on a face: send the full ceremony to 0trust.cloud, then hand back.
	dest := strings.TrimSpace(r.URL.Query().Get("return_to"))
	if dest == "" {
		dest = "/index"
	}
	// Relative dest on the face host.
	if strings.HasPrefix(dest, "/") && !strings.HasPrefix(dest, "//") {
		// keep as path for handoff dest
	} else if u, err := url.Parse(dest); err == nil && u.Host != "" {
		// Absolute return_to — if same face, use path; if elsewhere, still handoff dest path or full
		if p.isPlatformFaceHost(u.Hostname()) || p.isCanonicalHost(u.Hostname()) {
			dest = u.RequestURI()
			if dest == "" {
				dest = "/"
			}
		}
	} else {
		dest = "/index"
	}

	faceOrigin := "https://" + host
	if r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		// Local/dev may be http behind the edge; prefer https for public faces.
		faceOrigin = "https://" + host
	}

	// return_to on the canonical host points at face session-consume so cookies land on the face.
	consume := faceOrigin + "/auth/session-consume?dest=" + url.QueryEscape(dest)
	authURL := p.canonicalOrigin() + "/auth?return_to=" + url.QueryEscape(consume)
	// Preserve username hint if present.
	if u := strings.TrimSpace(r.URL.Query().Get("username")); u != "" {
		authURL += "&username=" + url.QueryEscape(u)
	}
	http.Redirect(w, r, authURL, http.StatusFound)
	return true
}

func handoffKey(code string) string {
	return "data:session_handoff:" + code
}

func (p *Provider) mintSessionHandoff(username, token, dest string) (string, error) {
	if p == nil || p.SdfEngine == nil {
		return "", fmt.Errorf("provider not ready")
	}
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/index"
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := hex.EncodeToString(raw)
	payload := sessionHandoff{
		Username:  strings.TrimSpace(username),
		Token:     strings.TrimSpace(token),
		Dest:      dest,
		ExpiresAt: time.Now().UTC().Add(sessionHandoffTTL),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	txn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Put(txn, []byte(handoffKey(code)), b, sessionHandoffTTL); err != nil {
		txn.Abort()
		return "", err
	}
	if err := txn.Commit(); err != nil {
		return "", err
	}
	return code, nil
}

func (p *Provider) consumeSessionHandoff(code string) (*sessionHandoff, error) {
	if p == nil || p.SdfEngine == nil {
		return nil, fmt.Errorf("provider not ready")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("missing code")
	}
	key := []byte(handoffKey(code))
	txn := p.SdfEngine.Store.Begin()
	raw, err := p.SdfEngine.Store.Get(txn, key)
	if err != nil || len(raw) == 0 {
		txn.Commit()
		return nil, fmt.Errorf("invalid or expired handoff")
	}
	// One-time use
	_ = p.SdfEngine.Store.Put(txn, key, nil, -1)
	_ = txn.Commit()

	var h sessionHandoff
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(h.ExpiresAt) {
		return nil, fmt.Errorf("handoff expired")
	}
	if h.Token == "" || h.Username == "" {
		return nil, fmt.Errorf("invalid handoff payload")
	}
	return &h, nil
}

// HandleSessionConsume completes a cross-host SSO handoff onto a platform face (0trust.name).
// Query: code=<one-time> & dest=/path
func (p *Provider) HandleSessionConsume(w http.ResponseWriter, r *http.Request) {
	if p == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	host := requestPublicHost(r)
	// Allow consume on face hosts or canonical (idempotent).
	if host != "" && !p.isPlatformFaceHost(host) && !p.isCanonicalHost(host) {
		http.Error(w, "host not allowed for session handoff", http.StatusForbidden)
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	dest := strings.TrimSpace(r.URL.Query().Get("dest"))
	h, err := p.consumeSessionHandoff(code)
	if err != nil {
		// Fall back to auth on canonical host.
		ret := dest
		if ret == "" {
			ret = "/index"
		}
		face := host
		if face == "" {
			face = p.canonicalHost()
		}
		auth := p.canonicalOrigin() + "/auth?return_to=" + url.QueryEscape("https://"+face+"/auth/session-consume?dest="+url.QueryEscape(ret))
		http.Redirect(w, r, auth, http.StatusFound)
		return
	}
	if dest == "" {
		dest = h.Dest
	}
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/index"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "user_session_" + h.Token,
		Path:     "/",
		Secure:   cookieSecure(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	p.logIDPAudit(h.Username, "SESSION_HANDOFF", "session consumed on "+host+" dest="+dest)
	http.Redirect(w, r, dest, http.StatusFound)
}

// faceHandoffURL builds a one-time consume URL on a platform face after login on the canonical host.
func (p *Provider) faceHandoffURL(returnTo, username, tokenString string) (string, bool) {
	if p == nil || returnTo == "" {
		return "", false
	}
	u, err := url.Parse(returnTo)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", false
	}
	host := normalizeEnrollmentHost(u.Hostname())
	if !p.isPlatformFaceHost(host) {
		return "", false
	}

	dest := strings.TrimSpace(u.Query().Get("dest"))
	if dest == "" {
		// return_to may already be /auth/session-consume or a real path
		if strings.HasPrefix(u.Path, "/auth/session-consume") {
			dest = "/index"
		} else if u.Path != "" {
			pathOnly := u.Path
			if u.RawQuery != "" && !strings.HasPrefix(pathOnly, "/auth/session-consume") {
				pathOnly = u.RequestURI()
			}
			dest = pathOnly
			if strings.HasPrefix(dest, "/auth/session-consume") {
				dest = "/index"
			}
		} else {
			dest = "/index"
		}
	}
	if !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/index"
	}

	code, err := p.mintSessionHandoff(username, tokenString, dest)
	if err != nil {
		return "", false
	}
	out := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/auth/session-consume",
		RawQuery: url.Values{
			"code": {code},
			"dest": {dest},
		}.Encode(),
	}
	return out.String(), true
}

func isPlatformFaceHostname(host string) bool {
	host = normalizeEnrollmentHost(host)
	if host == "" {
		return false
	}
	for _, h := range defaultPlatformFaceHosts {
		if host == h {
			return true
		}
	}
	return strings.HasSuffix(host, ".0trust.name") || host == "0trust.name"
}
