package auth_provider

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0TrustCloud/samln"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

const federationTTL = 5 * time.Minute

// SetSAMLnEngine wires the SAMLn compiler used for federated SSO assertions.
func (p *Provider) SetSAMLnEngine(engine *samln.SAMLnEngine) {
	p.samlnEngine = engine
}

// InitSAMLn boots the SAMLn assertion engine using the provider signing key.
func (p *Provider) InitSAMLn(db *ultimate_db.DB, issuer string, authPageID ultimate_db.PageID) error {
	if p == nil || p.signingKey == nil {
		return fmt.Errorf("provider not ready")
	}
	engine, err := samln.New(db, issuer, p.signingKey, authPageID)
	if err != nil {
		return err
	}
	p.samlnEngine = engine
	return nil
}

// HandleAuthEntry completes SSO when the hub already has a valid session.
// Also redirects platform-face hosts (0trust.name) to the canonical WebAuthn host.
// Returns true when the request was handled (redirect or JSON).
func (p *Provider) HandleAuthEntry(w http.ResponseWriter, r *http.Request) bool {
	if p == nil {
		return false
	}

	// Passkeys are bound to rpId=0trust.cloud — never run the ceremony on 0trust.name.
	if p.RedirectPlatformFaceAuth(w, r) {
		return true
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		return false
	}
	session, err := p.resolveSession(cookie.Value)
	if err != nil || !session.Valid || strings.TrimSpace(session.Subject) == "" {
		return false
	}

	returnTo := strings.TrimSpace(r.URL.Query().Get("return_to"))

	// Logged in on canonical host with return_to pointing at a face → handoff cookie.
	if handoff, ok := p.faceHandoffFromSession(returnTo, session.Subject, cookie.Value); ok {
		http.Redirect(w, r, handoff, http.StatusFound)
		return true
	}

	if route := p.productRouteForReturnTo(returnTo); route != nil {
		if p.respondProductOIDCSession(w, r, session.Subject, route, returnTo) {
			return true
		}
	}

	if returnTo != "" && p.allowedReturnTo(returnTo) {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return true
	}

	http.Redirect(w, r, "/index", http.StatusFound)
	return true
}

// faceHandoffFromSession is like faceHandoffURL but accepts a full session cookie value.
func (p *Provider) faceHandoffFromSession(returnTo, username, cookieValue string) (string, bool) {
	token := strings.TrimSpace(cookieValue)
	token = strings.TrimPrefix(token, "user_session_")
	if token == "" {
		return "", false
	}
	return p.faceHandoffURL(returnTo, username, token)
}

// HandleSAMLnFederate issues a SAMLn assertion and redirects to the target product.
func (p *Provider) HandleSAMLnFederate(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.samlnEngine == nil {
		http.Error(w, "federation unavailable", http.StatusServiceUnavailable)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/auth?"+r.URL.RawQuery, http.StatusFound)
		return
	}
	session, err := p.resolveSession(cookie.Value)
	if err != nil || !session.Valid || session.Subject == "" {
		http.Redirect(w, r, "/auth?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	audience := normalizeEnrollmentHost(r.URL.Query().Get("aud"))
	if audience == "" {
		http.Error(w, "aud required", http.StatusBadRequest)
		return
	}
	route := p.productRouteForHost(audience)
	if route == nil {
		http.Error(w, "unknown federation audience", http.StatusBadRequest)
		return
	}

	returnTo := strings.TrimSpace(r.URL.Query().Get("return_to"))
	if returnTo == "" {
		returnTo = "https://" + route.PublicDomain + "/"
	}
	returnTo = p.normalizeProductReturnTo(route, returnTo)

	jti, err := randomJTI()
	if err != nil {
		http.Error(w, "failed to issue federation token", http.StatusInternalServerError)
		return
	}

	token, err := p.samlnEngine.FederationAssertion(jti, session.Subject, route.PublicDomain, returnTo, federationTTL)
	if err != nil {
		p.logIDPError("SAMLN_FEDERATE", err.Error())
		http.Error(w, "assertion compile failed", http.StatusInternalServerError)
		return
	}

	consumeURL := "https://" + route.PublicDomain + "/auth/samln/consume"
	u, _ := url.Parse(consumeURL)
	q := u.Query()
	q.Set("assertion", token)
	q.Set("return_to", returnTo)
	u.RawQuery = q.Encode()

	p.logIDPAudit(session.Subject, "SAMLN_FEDERATE", "issued federation assertion for "+route.PublicDomain)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// HandleSAMLnExchange validates a SAMLn assertion and returns an OIDC redirect for the target app.
func (p *Provider) HandleSAMLnExchange(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.samlnEngine == nil {
		http.Error(w, "federation unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()

	var req struct {
		Assertion   string `json:"assertion"`
		ClientID    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
	}
	if json.Unmarshal(body, &req) != nil {
		_ = r.ParseForm()
		req.Assertion = r.FormValue("assertion")
		req.ClientID = r.FormValue("client_id")
		req.RedirectURI = r.FormValue("redirect_uri")
	}

	req.Assertion = strings.TrimSpace(req.Assertion)
	req.ClientID = strings.TrimSpace(req.ClientID)
	req.RedirectURI = strings.TrimSpace(req.RedirectURI)
	if req.Assertion == "" || req.ClientID == "" || req.RedirectURI == "" {
		http.Error(w, "assertion, client_id, and redirect_uri required", http.StatusBadRequest)
		return
	}

	client, err := p.getClient(req.ClientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusUnauthorized)
		return
	}
	validURI := false
	for _, uri := range client.RedirectURIs {
		if uri == req.RedirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	ru, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	audience := normalizeEnrollmentHost(ru.Hostname())
	subject, err := p.samlnEngine.ValidateAssertion(req.Assertion, audience)
	if err != nil {
		p.logIDPError("SAMLN_EXCHANGE", err.Error())
		http.Error(w, "invalid assertion", http.StatusUnauthorized)
		return
	}

	jti := federationJTI(req.Assertion)
	if jti != "" {
		_ = p.samlnEngine.ConsumeAssertion(1, jti, subject)
	}

	redirectURL, ok := p.buildOIDCRedirectForClient(subject, client, req.RedirectURI, "samln_"+audience)
	if !ok {
		http.Error(w, "exchange failed", http.StatusInternalServerError)
		return
	}

	p.logIDPAudit(subject, "SAMLN_EXCHANGE", "federated OIDC session for client "+req.ClientID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"redirect_to": redirectURL,
	})
}

// HandleSAMLnJWKS publishes the SAMLn federation signing keys.
func (p *Provider) HandleSAMLnJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &p.signingKey.PublicKey,
		KeyID:     p.keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

// FederationURL builds a SAMLn federation entry on the hub IdP.
func FederationURL(hubBase, audience, returnTo string) string {
	hubBase = strings.TrimRight(strings.TrimSpace(hubBase), "/")
	u := hubBase + "/samln/federate"
	q := url.Values{}
	q.Set("aud", audience)
	if strings.TrimSpace(returnTo) != "" {
		q.Set("return_to", returnTo)
	}
	return u + "?" + q.Encode()
}

func (p *Provider) buildOIDCRedirectForClient(username string, client *OIDCClient, redirectURI, state string) (string, bool) {
	if client == nil || client.ClientID == "" {
		return "", false
	}
	authCode, err := p.issueOIDCAuthorizationCode(username, AuthRequest{
		ClientID:    client.ClientID,
		RedirectURI: redirectURI,
		State:       state,
		Scope:       "openid profile",
	})
	if err != nil {
		return "", false
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + "code=" + url.QueryEscape(authCode) + "&state=" + url.QueryEscape(state), true
}

func federationJTI(assertion string) string {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(assertion, claims, func(t *jwt.Token) (interface{}, error) {
		return nil, nil
	})
	if err != nil {
		return ""
	}
	jti, _ := claims["jti"].(string)
	return strings.TrimSpace(jti)
}

func randomJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "fed_" + hex.EncodeToString(buf), nil
}