package auth_provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/samln"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_policy"
)

// AdminPinConfig pins admin WebAuthn credentials (YubiKey) without importing
// secure_bootstrap (avoids import cycles).
type AdminPinConfig struct {
	PinnedCredentialIDs []string
	BreakglassLocalhost bool
}

func cookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

type Provider struct {
	gk             *guikit.GUIKit
	wa             *webauthn.WebAuthn
	waTunnel       *webauthn.WebAuthn
	tunnelRPID     string
	issuer         string
	signingKey     *rsa.PrivateKey
	keyID          string
	SessionManager *secure_policy.SessionManager
	SdfEngine      *secure_data_format.SecureDataEngine
	Logger         *logger.LogDispatcher

	bootstrapSubjects    map[string]struct{}
	openEnrollmentHosts  map[string]struct{}
	platformFaceHosts    map[string]struct{} // e.g. 0trust.name — auth redirects to canonical RP ID host
	productAuthRoutes    []ProductAuthRoute
	samlnEngine          *samln.SAMLnEngine
	adminPin             AdminPinConfig
	OnLoginSuccess       func(username string, w http.ResponseWriter, r *http.Request)
	OnEnrollmentComplete func(username string) error
}

func (p *Provider) AllowBootstrapRegistration(subject string) {
	if subject == "" {
		return
	}
	if p.bootstrapSubjects == nil {
		p.bootstrapSubjects = make(map[string]struct{})
	}
	p.bootstrapSubjects[subject] = struct{}{}
}

// SetAdminPin configures YubiKey credential pins for bootstrap admin login.
func (p *Provider) SetAdminPin(cfg AdminPinConfig) {
	if p == nil {
		return
	}
	if len(cfg.PinnedCredentialIDs) == 0 {
		// Live credentials for admin on 0trust.cloud (data:user:admin).
		cfg.PinnedCredentialIDs = []string{
			"Og/862BgKFosmqIRjIQd8g==",
			"cj4B/mPGcc1xl6xDq3qanQ==",
		}
	}
	p.adminPin = cfg
}

func (p *Provider) AdminPin() AdminPinConfig {
	if p == nil || len(p.adminPin.PinnedCredentialIDs) == 0 {
		return AdminPinConfig{
			PinnedCredentialIDs: []string{
				"Og/862BgKFosmqIRjIQd8g==",
				"cj4B/mPGcc1xl6xDq3qanQ==",
			},
			BreakglassLocalhost: true,
		}
	}
	return p.adminPin
}

// SetOpenEnrollmentHosts allows passkey self-registration without invite/TOTP on these hosts.
func (p *Provider) SetOpenEnrollmentHosts(hosts []string) {
	if p.openEnrollmentHosts == nil {
		p.openEnrollmentHosts = make(map[string]struct{})
	}
	for _, host := range hosts {
		host = normalizeEnrollmentHost(host)
		if host != "" {
			p.openEnrollmentHosts[host] = struct{}{}
		}
	}
}

// InheritPreLaunchConfig copies startup settings from a placeholder provider into the live instance.
func (p *Provider) InheritPreLaunchConfig(from *Provider) {
	if p == nil || from == nil {
		return
	}
	if len(from.openEnrollmentHosts) > 0 {
		hosts := make([]string, 0, len(from.openEnrollmentHosts))
		for host := range from.openEnrollmentHosts {
			hosts = append(hosts, host)
		}
		p.SetOpenEnrollmentHosts(hosts)
	}
	if len(from.productAuthRoutes) > 0 {
		p.SetProductAuthRoutes(from.productAuthRoutes)
	}
	if len(from.platformFaceHosts) > 0 {
		hosts := make([]string, 0, len(from.platformFaceHosts))
		for host := range from.platformFaceHosts {
			hosts = append(hosts, host)
		}
		p.SetPlatformFaceHosts(hosts)
	}
	if len(from.adminPin.PinnedCredentialIDs) > 0 {
		p.SetAdminPin(from.adminPin)
	}
}

func normalizeEnrollmentHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	return raw
}

func requestPublicHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Header.Get("X-0Trust-Services"))
	}
	if host == "" {
		host = r.Host
	}
	return normalizeEnrollmentHost(host)
}

func (p *Provider) isOpenEnrollment(r *http.Request) bool {
	if p == nil || len(p.openEnrollmentHosts) == 0 {
		return false
	}
	host := requestPublicHost(r)
	if host == "" {
		return false
	}
	_, ok := p.openEnrollmentHosts[host]
	return ok
}

func New(gk *guikit.GUIKit, sm *secure_policy.SessionManager, sdf *secure_data_format.SecureDataEngine, rpDisplayName, rpID, rpOrigin, tunnelRPID string) (*Provider, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
	}

	if tunnelRPID == "" {
		tunnelRPID = "0trust.services"
	}
	tunnelOrigin := "https://" + tunnelRPID
	waTunnel, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName + " Tunnel",
		RPID:          tunnelRPID,
		RPOrigins:     []string{tunnelOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel WebAuthn instance: %w", err)
	}

	var privKey *rsa.PrivateKey
	masterKeyID := "data:oidc_master_key"
	
	txn := sdf.Store.Begin()
	keyBytes, err := sdf.Store.Get(txn, []byte(masterKeyID))
	txn.Commit()

	if err == nil && len(keyBytes) > 0 {
		privKey, _ = x509.ParsePKCS1PrivateKey(keyBytes)
	}

	if privKey == nil {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}
		wTxn := sdf.Store.Begin()
		_ = sdf.Store.Put(wTxn, []byte(masterKeyID), x509.MarshalPKCS1PrivateKey(privKey), 0)
		_ = wTxn.Commit()
	}

	p := &Provider{
		gk:             gk,
		wa:             wa,
		waTunnel:       waTunnel,
		tunnelRPID:     tunnelRPID,
		issuer:         rpOrigin,
		signingKey:     privKey,
		keyID:          "v1-default",
		SessionManager: sm,
		SdfEngine:      sdf,
	}
	p.ensureDefaultPlatformFaces()

	// WebAuthn Ceremony Routing Wireframes
	gk.Mux.HandleFunc("GET /auth/register/begin", p.BeginRegistration)
	gk.Mux.HandleFunc("POST /auth/register/finish", p.FinishRegistration)
	gk.Mux.HandleFunc("GET /auth/login/begin", p.BeginLogin)
	gk.Mux.HandleFunc("POST /auth/login/finish", p.FinishLogin)
	gk.Mux.HandleFunc("GET /auth/webauthn.js", p.ServeJS)
	// Cross-host SSO onto platform faces (0trust.name) after passkey on canonical host.
	gk.Mux.HandleFunc("GET /auth/session-consume", p.HandleSessionConsume)

	// Provisioned enrollment ceremony
	gk.Mux.HandleFunc("GET /auth/provision/status", p.HandleProvisionStatus)
	gk.Mux.HandleFunc("POST /auth/provision/verify", p.HandleProvisionVerify)
	gk.Mux.HandleFunc("POST /auth/bootstrap/{username}/reset-passkey", p.HandleBootstrapResetPasskey)
	// Permanent device ban (compromise response) + restore. Localhost-only.
	gk.Mux.HandleFunc("POST /auth/bootstrap/{username}/blacklist-device", p.HandleBlacklistDevice)
	gk.Mux.HandleFunc("POST /auth/bootstrap/{username}/clear-device-blacklist", p.HandleClearDeviceBlacklist)
	gk.Mux.HandleFunc("POST /auth/bootstrap/clear-all-device-blacklists", p.HandleClearAllDeviceBlacklists)
	// Deprecated aliases (same handlers)
	gk.Mux.HandleFunc("POST /auth/bootstrap/{username}/clear-device-revoke", p.HandleClearDeviceRevoke)
	gk.Mux.HandleFunc("POST /auth/bootstrap/clear-all-device-revokes", p.HandleClearAllDeviceRevokes)

	// Device Bound Session Credentials (DBSC) Mappings
	gk.Mux.HandleFunc("POST /auth/dbsc/register", p.DBSCRegister)
	gk.Mux.HandleFunc("POST /auth/dbsc/refresh", p.DBSCRefresh)

	// OIDC Discovery & Identity Core Frameworks
	gk.Mux.HandleFunc("GET /.well-known/openid-configuration", p.ServeDiscovery)
	gk.Mux.HandleFunc("GET /auth/keys", p.ServeJWKS)
	gk.Mux.HandleFunc("GET /auth/authorize", p.Authorize)
	gk.Mux.HandleFunc("POST /auth/token", p.TokenExchange)
	gk.Mux.HandleFunc("POST /auth/revoke", p.RevokeToken)
	gk.Mux.HandleFunc("POST /auth/clients/register", p.AuthGuard(p.RegisterClient))
	gk.Mux.HandleFunc("GET /api/v1/idp/session", p.HandleSessionStatus)

	// Federated SAMLn SSO (hub issues assertions; products consume via /auth/samln/consume)
	gk.Mux.HandleFunc("GET /samln/federate", p.HandleSAMLnFederate)
	gk.Mux.HandleFunc("POST /samln/exchange", p.HandleSAMLnExchange)
	gk.Mux.HandleFunc("GET /samln/keys", p.HandleSAMLnJWKS)

	return p, nil
}

// webAuthnFor picks the WebAuthn config for this request.
//
// Product IdP faces (social.0trust.cloud, motionkb.0trust.cloud, …) arrive with
// X-0Trust-Tunnel from the edge auth_proxy. They must still use the **canonical**
// RP ID (0trust.cloud) so passkeys registered on the apex also work on faces —
// otherwise login PublicKeyCredentialRequestOptions.rpId is the face host,
// allowCredentials never match, and Windows Hello never opens.
//
// Only true 0trust.services tunnel hosts use a services-scoped RP ID.
func (p *Provider) webAuthnFor(r *http.Request) *webauthn.WebAuthn {
	if p == nil || p.wa == nil {
		return p.wa
	}
	host := requestPublicHost(r)
	if host == "" {
		return p.wa
	}
	origin := "https://" + host

	// Real WAN tunnel products: {app}.0trust.services (or tunnel RP apex).
	if r.Header.Get("X-0Trust-Tunnel") == "1" && p.waTunnel != nil {
		tunnelRP := strings.TrimSpace(p.tunnelRPID)
		if tunnelRP == "" {
			tunnelRP = "0trust.services"
		}
		if host == tunnelRP || strings.HasSuffix(host, "."+tunnelRP) {
			wa, err := webauthn.New(&webauthn.Config{
				RPDisplayName: p.waTunnel.Config.RPDisplayName,
				RPID:          tunnelRP,
				RPOrigins:     []string{origin, "https://" + tunnelRP},
			})
			if err != nil {
				return p.waTunnel
			}
			return wa
		}
	}

	// Canonical platform + product faces: always RPID = 0trust.cloud, with the
	// browser origin allowed for this request.
	rpID := p.wa.Config.RPID
	if rpID == "" {
		rpID = "0trust.cloud"
	}
	origins := append([]string{}, p.wa.Config.RPOrigins...)
	if !containsString(origins, origin) {
		origins = append(origins, origin)
	}
	// Also allow apex origin if missing.
	apex := "https://" + rpID
	if !containsString(origins, apex) {
		origins = append(origins, apex)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: p.wa.Config.RPDisplayName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
	if err != nil {
		return p.wa
	}
	return wa
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func (p *Provider) HandleProvisionStatus(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	resp := map[string]interface{}{
		"username":    username,
		"bootstrap":   p.isBootstrapSubject(username),
		"provisioned": false,
		"verified":    false,
		"ready":       false,
		"registered":  false,
	}

	if p.isOpenEnrollment(r) {
		resp["open_enrollment"] = true
		resp["provisioned"] = true
		resp["verified"] = true
		resp["ready"] = true
		if p.SdfEngine != nil {
			if _, err := p.getUser(username); err == nil {
				resp["registered"] = true
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	if _, err := p.getUser(username); err == nil {
		resp["registered"] = true
	}

	if p.isBootstrapSubject(username) {
		resp["provisioned"] = true
		resp["ready"] = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	state, err := p.getProvisioningState(username)
	if err == nil && state != nil {
		resp["provisioned"] = true
		resp["verified"] = state.IsVerified
		resp["ready"] = state.IsVerified
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *Provider) HandleProvisionVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Passcode string `json:"passcode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Malformed request payload", http.StatusBadRequest)
		return
	}

	verified, err := p.VerifyProvisioningTOTP(req.Username, req.Passcode)
	if err != nil {
		p.logIDPError("TOTP_VERIFY", "verification failed for "+req.Username+": "+err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !verified {
		p.logIDPError("TOTP_VERIFY", "invalid passcode for "+req.Username)
		http.Error(w, "Invalid TOTP initialization code", http.StatusForbidden)
		return
	}

	p.logIDPAudit(req.Username, "TOTP_VERIFY", "TOTP verified for "+req.Username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "totp_verified_proceed_to_hardware"})
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func (p *Provider) getUser(username string) (*PasskeyUser, error) {
	username = normalizeUsername(username)
	dataKey := "data:user:" + username
	txn := p.SdfEngine.Store.Begin()
	val, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	if err != nil {
		return nil, err
	}
	var user PasskeyUser
	if err := json.Unmarshal(val, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *Provider) saveUser(user *PasskeyUser) error {
	user.Name = normalizeUsername(user.Name)
	val, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed encoding user profile: %w", err)
	}

	dataKey := "data:user:" + user.Name
	txn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Put(txn, []byte(dataKey), val, 0); err != nil {
		txn.Abort()
		return fmt.Errorf("failed persisting user profile: %w", err)
	}
	if err := txn.Commit(); err != nil {
		return err
	}
	if err := p.SdfEngine.Store.Flush(); err != nil && p.Logger != nil {
		p.Logger.Error("failed flushing user profile for " + user.Name + ": " + err.Error())
	}

	// Best-effort audit trail; identity persistence must not depend on SDF ledger space.
	targetAddress := "user:profile:" + user.Name
	script := fmt.Sprintf(`user:account(name("%s") status("active"))`, user.Name)
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "webauthn-identity-provider",
		Nonce:         0,
		Method:        "UPDATE_PROFILE",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"payload": string(val)},
	}
	if _, err := p.SdfEngine.CompileSecureData(script, tx); err != nil && p.Logger != nil {
		p.Logger.Error("SDF profile audit skipped for " + user.Name + ": " + err.Error())
	}
	return nil
}

// SetGUIKit allows the test suite to inject the GUIKit dependency 
// into the provider instance without exporting the internal field.
func (p *Provider) SetGUIKit(gk *guikit.GUIKit) {
    p.gk = gk
}
