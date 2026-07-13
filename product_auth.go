package auth_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0TrustCloud/secure_data_format"
)

// ProductAuthRoute maps a product identity plane host to its public app and OIDC client.
type ProductAuthRoute struct {
	Slug         string
	PublicDomain string
	IdentityHost string
	ClientName   string
}

func (p *Provider) SetProductAuthRoutes(routes []ProductAuthRoute) {
	if p == nil {
		return
	}
	p.productAuthRoutes = nil
	for _, route := range routes {
		route.Slug = strings.TrimSpace(strings.ToLower(route.Slug))
		route.PublicDomain = normalizeEnrollmentHost(route.PublicDomain)
		route.IdentityHost = normalizeEnrollmentHost(route.IdentityHost)
		route.ClientName = strings.TrimSpace(route.ClientName)
		if route.PublicDomain == "" || route.ClientName == "" {
			continue
		}
		p.productAuthRoutes = append(p.productAuthRoutes, route)
	}
}

func (p *Provider) productRouteForHost(host string) *ProductAuthRoute {
	host = normalizeEnrollmentHost(host)
	if host == "" || len(p.productAuthRoutes) == 0 {
		return nil
	}
	for i := range p.productAuthRoutes {
		route := &p.productAuthRoutes[i]
		if host == route.PublicDomain ||
			(route.IdentityHost != "" && host == route.IdentityHost) {
			return route
		}
	}
	return nil
}

func (p *Provider) productRouteForRequest(r *http.Request) *ProductAuthRoute {
	return p.productRouteForHost(requestPublicHost(r))
}

func (p *Provider) productRouteForReturnTo(raw string) *ProductAuthRoute {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(p.productAuthRoutes) == 0 {
		return nil
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return p.productRouteForHost(u.Hostname())
}

func (p *Provider) getClientByName(name string) (*OIDCClient, error) {
	name = strings.TrimSpace(name)
	if name == "" || p == nil || p.SdfEngine == nil || p.SdfEngine.Store == nil {
		return nil, fmt.Errorf("client not found")
	}
	txn := p.SdfEngine.Store.Begin()
	it := p.SdfEngine.Store.NewIterator(txn, []byte("data:client:"))
	if it == nil {
		return nil, fmt.Errorf("client not found")
	}
	defer it.Close()
	for {
		_, value, err := it.Next()
		if err != nil {
			break
		}
		var client OIDCClient
		if json.Unmarshal(value, &client) != nil {
			continue
		}
		if strings.EqualFold(client.ClientName, name) {
			return &client, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}

func (p *Provider) productCallbackURI(client *OIDCClient, route *ProductAuthRoute) string {
	if route == nil || route.PublicDomain == "" {
		return ""
	}
	preferred := "https://" + route.PublicDomain + "/auth/callback"
	if client == nil {
		return preferred
	}
	for _, uri := range client.RedirectURIs {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		u, err := url.Parse(uri)
		if err != nil {
			continue
		}
		if normalizeEnrollmentHost(u.Hostname()) == route.PublicDomain && strings.HasSuffix(u.Path, "/auth/callback") {
			return uri
		}
	}
	for _, uri := range client.RedirectURIs {
		u, err := url.Parse(strings.TrimSpace(uri))
		if err != nil {
			continue
		}
		if normalizeEnrollmentHost(u.Hostname()) == route.PublicDomain {
			return strings.TrimSpace(uri)
		}
	}
	return preferred
}

func (p *Provider) normalizeProductReturnTo(route *ProductAuthRoute, returnTo string) string {
	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" || returnTo == "/index" || returnTo == "/apps" {
		return "https://" + route.PublicDomain + "/"
	}
	if strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") {
		return "https://" + route.PublicDomain + returnTo
	}
	u, err := url.Parse(returnTo)
	if err != nil {
		return "https://" + route.PublicDomain + "/"
	}
	host := normalizeEnrollmentHost(u.Hostname())
	if host == route.PublicDomain {
		return returnTo
	}
	return "https://" + route.PublicDomain + "/"
}

func (p *Provider) issueOIDCAuthorizationCode(username string, authReq AuthRequest) (string, error) {
	authCode := "code_" + fmt.Sprintf("%d", time.Now().UnixNano())
	codeKey := "data:auth_code:" + authCode
	contextData, _ := json.Marshal(map[string]string{
		"username":              username,
		"client_id":             authReq.ClientID,
		"redirect_uri":          authReq.RedirectURI,
		"nonce":                 authReq.Nonce,
		"scope":                 authReq.Scope,
		"code_challenge":        authReq.CodeChallenge,
		"code_challenge_method": authReq.CodeChallengeMethod,
	})

	targetAddress := "oidc:auth_code:" + authCode
	script := fmt.Sprintf(`oidc:code(client_id("%s") user("%s"))`, authReq.ClientID, username)
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "oidc-authorization-server",
		Nonce:         0,
		Method:        "ISSUE_AUTH_CODE",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"context_raw": string(contextData)},
	}
	if _, err := p.SdfEngine.CompileSecureData(script, tx); err != nil {
		return "", err
	}
	wTxn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(wTxn, []byte(codeKey), contextData, 5*time.Minute)
	if err := wTxn.Commit(); err != nil {
		return "", err
	}
	return authCode, nil
}

func (p *Provider) buildProductOIDCRedirectURL(username string, route *ProductAuthRoute, returnTo string) (string, bool) {
	if p == nil || route == nil {
		return "", false
	}
	client, err := p.getClientByName(route.ClientName)
	if err != nil || client == nil || client.ClientID == "" {
		return "", false
	}
	callbackURI := p.productCallbackURI(client, route)
	finalReturn := p.normalizeProductReturnTo(route, returnTo)
	state := "product_" + route.Slug

	redirectBase, err := url.Parse(callbackURI)
	if err != nil {
		return "", false
	}
	q := redirectBase.Query()
	q.Set("return_to", finalReturn)
	redirectBase.RawQuery = q.Encode()

	authCode, err := p.issueOIDCAuthorizationCode(username, AuthRequest{
		ClientID:     client.ClientID,
		RedirectURI:  callbackURI,
		State:        state,
		Scope:        "openid profile",
	})
	if err != nil {
		return "", false
	}

	out := redirectBase.String()
	sep := "?"
	if strings.Contains(out, "?") {
		sep = "&"
	}
	redirectURL := out + sep + "code=" + url.QueryEscape(authCode) + "&state=" + url.QueryEscape(state)
	p.logIDPAudit(username, "OIDC_AUTH_CODE", fmt.Sprintf(
		"product session issued for client %s user %s via %s", client.ClientID, username, route.PublicDomain))
	return redirectURL, true
}

// wantsAuthJSONResponse reports whether the client expects JSON {redirect_to}
// (WebAuthn fetch finish) vs a full browser redirect.
func wantsAuthJSONResponse(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.Method == http.MethodPost {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.Contains(ct, "application/json") {
			return true
		}
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Dest")) {
	case "empty":
		return true
	case "document", "iframe":
		return false
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		if !strings.Contains(accept, "text/html") {
			return true
		}
		jsonIdx := strings.Index(accept, "application/json")
		htmlIdx := strings.Index(accept, "text/html")
		if jsonIdx >= 0 && (htmlIdx < 0 || jsonIdx < htmlIdx) {
			return true
		}
	}
	return false
}

func respondAuthRedirect(w http.ResponseWriter, r *http.Request, redirectURL string) {
	if wantsAuthJSONResponse(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":      "success",
			"redirect_to": redirectURL,
		})
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (p *Provider) respondProductOIDCSession(w http.ResponseWriter, r *http.Request, username string, route *ProductAuthRoute, returnTo string) bool {
	redirectURL, ok := p.buildProductOIDCRedirectURL(username, route, returnTo)
	if !ok {
		return false
	}
	respondAuthRedirect(w, r, redirectURL)
	return true
}

// ProductClientName maps a product slug to its configured OIDC client_name.
func ProductClientName(slug string) string {
	switch strings.ToLower(strings.TrimSpace(slug)) {
	case "williwaw":
		return "Wiliwaw"
	case "defcon":
		return "Ack"
	case "bandy":
		return "Bandy"
	case "tunneltug":
		return "TunnelTug"
	case "motionkb":
		return "MotionKB"
	case "mail":
		return "MeshMail"
	case "search":
		return "0Trust-Search"
	default:
		return ""
	}
}