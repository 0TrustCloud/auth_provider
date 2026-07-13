package auth_provider

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"encoding/base64"
	"net"
	"strings"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// sanitizeLoginAllowCredentials drops empty transports slices. Some browsers
// treat transports:[] as "no transport allowed" and never open Windows Hello.
func sanitizeLoginAllowCredentials(options *protocol.CredentialAssertion) {
	if options == nil {
		return
	}
	for i := range options.Response.AllowedCredentials {
		if len(options.Response.AllowedCredentials[i].Transport) == 0 {
			options.Response.AllowedCredentials[i].Transport = nil
		}
	}
}

func (p *Provider) saveSession(sessionKey string, sessionData webauthn.SessionData) error {
	val, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}

	dataKey := "data:webauthn_session:" + sessionKey
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{dataKey: val}, 5*time.Minute)

	txn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Put(txn, []byte(dataKey), val, 5*time.Minute); err != nil {
		txn.Abort()
		return err
	}
	return txn.Commit()
}

func (p *Provider) savePendingRegistration(username string, userID []byte) error {
	val, err := json.Marshal(pendingRegistration{UserID: userID})
	if err != nil {
		return err
	}
	dataKey := "data:pending_reg:" + username
	txn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Put(txn, []byte(dataKey), val, 5*time.Minute); err != nil {
		txn.Abort()
		return err
	}
	return txn.Commit()
}

func (p *Provider) loadPendingRegistration(username string) ([]byte, error) {
	dataKey := "data:pending_reg:" + username
	txn := p.SdfEngine.Store.Begin()
	val, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()
	if err != nil {
		return nil, err
	}
	var pending pendingRegistration
	if err := json.Unmarshal(val, &pending); err != nil {
		return nil, err
	}
	return pending.UserID, nil
}

func (p *Provider) clearPendingRegistration(username string) {
	dataKey := "data:pending_reg:" + username
	txn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(txn, []byte(dataKey), nil, -1)
	_ = txn.Commit()
}

func (p *Provider) getSession(sessionKey string) (webauthn.SessionData, error) {
	dataKey := "data:webauthn_session:" + sessionKey
	txID := ultimate_db.GlobalCacheStore.BeginOCC()

	var sessionData webauthn.SessionData
	val, err := ultimate_db.GlobalCacheStore.Read(txID, dataKey)
	if err != nil {
		txn := p.SdfEngine.Store.Begin()
		val, err = p.SdfEngine.Store.Get(txn, []byte(dataKey))
		txn.Commit()
		if err != nil {
			return sessionData, err
		}
	}

	err = json.Unmarshal(val, &sessionData)
	return sessionData, err
}

func (p *Provider) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_BEGIN", "missing username")
		http.Error(w, "Must supply username", http.StatusBadRequest)
		return
	}

	if _, err := p.getUser(username); err == nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_BEGIN", "passkey already registered: "+username)
		msg := "Passkey already registered for this user — use Sign In with Passkey"
		if p.isBootstrapSubject(username) {
			msg = "Passkey already registered — use Sign In with Passkey. To re-register, an operator must reset the bootstrap passkey."
		}
		http.Error(w, msg, http.StatusConflict)
		return
	}

	if allowed, reason := p.canRegister(username, r); !allowed {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_BEGIN", "registration denied for "+username+": "+reason)
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	userHandle := make([]byte, 32)
	if _, err := rand.Read(userHandle); err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_BEGIN", "failed generating user handle for "+username)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	user := &PasskeyUser{ID: userHandle, Name: username, DisplayName: username}

	options, sessionData, err := p.webAuthnFor(r).BeginRegistration(user)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_BEGIN", "ceremony error for "+username+": "+err.Error())
		http.Error(w, "WebAuthn error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := p.savePendingRegistration(username, userHandle); err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_BEGIN", "pending registration save failed for "+username)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if err := p.saveSession("reg_"+username, *sessionData); err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_BEGIN", "session save failed for "+username)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	p.logIDPRequest(r, "WEBAUTHN_REGISTER_BEGIN", "passkey registration started for "+username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (p *Provider) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if _, err := p.getUser(username); err == nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_FINISH", "username already registered: "+username)
		http.Error(w, "Username already taken", http.StatusConflict)
		return
	}

	if allowed, reason := p.canRegister(username, r); !allowed {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_FINISH", "registration denied for "+username+": "+reason)
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	sessionData, err := p.getSession("reg_" + username)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_FINISH", "session expired for "+username)
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	userID := sessionData.UserID
	if len(userID) == 0 {
		userID, err = p.loadPendingRegistration(username)
		if err != nil || len(userID) == 0 {
			p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_FINISH", "registration state missing for "+username)
			http.Error(w, "Registration state expired", http.StatusBadRequest)
			return
		}
	}

	user := &PasskeyUser{
		ID:          userID,
		Name:        username,
		DisplayName: username,
	}

	credential, err := p.webAuthnFor(r).FinishRegistration(user, sessionData, r)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_FINISH", "ceremony failed for "+username+": "+err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Universal admin (admin / hash 8c6976e5…): only pinned YubiKey may register
	// (all hosts including social.0trust.cloud). Localhost breakglass only.
	if isUniversalAdminUsername(username) && !p.adminCredentialAllowed(r, credential.ID) {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_FINISH", "admin credential not pinned for "+username)
		http.Error(w, "Admin authenticator not authorized (use breakglass from localhost if replacing the key)", http.StatusForbidden)
		return
	}

	user.Credentials = append(user.Credentials, *credential)
	if err := p.saveUser(user); err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_REGISTER_FINISH", "failed saving user "+username+": "+err.Error())
		http.Error(w, "Failed to save user profile", http.StatusInternalServerError)
		return
	}
	p.clearPendingRegistration(username)

	if !p.isBootstrapSubject(username) {
		if err := p.consumeProvisioningTicket(username); err != nil && p.Logger != nil {
			p.Logger.Error("failed consuming provisioning ticket for " + username + ": " + err.Error())
		}
		if p.OnEnrollmentComplete != nil {
			if err := p.OnEnrollmentComplete(username); err != nil && p.Logger != nil {
				p.Logger.Error("enrollment completion hook failed for " + username + ": " + err.Error())
			}
		}
	}

	p.logIDPAudit(username, "WEBAUTHN_REGISTER", "passkey registered for "+username)
	p.handlePostAuthBound(username, webauthnHardwareBinding(credential), w, r)
}

func (p *Provider) BeginLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_LOGIN_BEGIN", "no account for "+username)
		// Distinguish missing account so open-enrollment faces can offer Register.
		http.Error(w, `No account for "`+username+`" — use Register Passkey first (open enrollment) or ask an admin for an invite`, http.StatusNotFound)
		return
	}
	if len(user.WebAuthnCredentials()) == 0 {
		p.logIDPRequestErr(r, "WEBAUTHN_LOGIN_BEGIN", "user has no credentials: "+username)
		http.Error(w, `No passkey registered for "`+username+`" — use Register Passkey first`, http.StatusNotFound)
		return
	}

	wa := p.webAuthnFor(r)
	// Match registration-style UV so platform authenticators (Windows Hello)
	// surface the same prompt path as credentials.create.
	options, sessionData, err := wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_LOGIN_BEGIN", "ceremony error for "+username+": "+err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Empty transports arrays make some browsers skip platform authenticators.
	sanitizeLoginAllowCredentials(options)

	if err := p.saveSession("login_"+username, *sessionData); err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_LOGIN_BEGIN", "session save failed for "+username)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	nCreds := 0
	if options != nil && options.Response.AllowedCredentials != nil {
		nCreds = len(options.Response.AllowedCredentials)
	}
	rpID := ""
	if wa != nil && wa.Config != nil {
		rpID = wa.Config.RPID
	}
	p.logIDPRequest(r, "WEBAUTHN_LOGIN_BEGIN",
		fmt.Sprintf("login started for %s (allowCredentials=%d rpId=%s)", username, nCreds, rpID))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (p *Provider) FinishLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	user, err := p.getUser(username)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_LOGIN_FINISH", "user not found")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sessionData, err := p.getSession("login_" + username)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_LOGIN_FINISH", "session expired for "+username)
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	credential, err := p.webAuthnFor(r).FinishLogin(user, sessionData, r)
	if err != nil {
		p.logIDPRequestErr(r, "WEBAUTHN_LOGIN_FINISH", "ceremony failed for "+username+": "+err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Login: WebAuthn already proved possession of a credential registered on
	// this account (allowCredentials). Do NOT re-check the YAML pin list here —
	// stale/mismatched pin encodings were rejecting the real YubiKey after a
	// successful ceremony. Pin enforcement applies only when *registering* a
	// new admin authenticator (FinishRegistration).

	for i, c := range user.Credentials {
		if bytes.Equal(c.ID, credential.ID) {
			user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
			break
		}
	}
	if err := p.saveUser(user); err != nil && p.Logger != nil {
		p.Logger.Error("failed updating sign count for " + username + ": " + err.Error())
	}
	p.logIDPAudit(username, "WEBAUTHN_LOGIN", "passkey login succeeded for "+username)
	// Bind this session to the passkey that just authenticated — required for
	// DBSC checks on MeshMail / Williwaw / bandy (global identity key).
	p.handlePostAuthBound(username, webauthnHardwareBinding(credential), w, r)
}

// webauthnHardwareBinding derives durable DBSC material from the WebAuthn credential.
// Register once → login anywhere with the same key → products see dbsc_bound.
func webauthnHardwareBinding(credential *webauthn.Credential) string {
	if credential == nil {
		return ""
	}
	if len(credential.PublicKey) > 0 {
		return "webauthn-pub:" + base64.RawURLEncoding.EncodeToString(credential.PublicKey)
	}
	if len(credential.ID) > 0 {
		return "webauthn-cred:" + base64.RawURLEncoding.EncodeToString(credential.ID)
	}
	return ""
}

// adminCredentialAllowed enforces pinned YubiKey IDs when *registering* a new
// admin authenticator. Compares raw credential bytes after decoding all common
// base64 forms so YAML pins match WebAuthn regardless of padding/URL encoding.
// Localhost breakglass bypasses the pin so a broken key can be replaced.
func (p *Provider) adminCredentialAllowed(r *http.Request, credID []byte) bool {
	cfg := p.AdminPin()
	if cfg.BreakglassLocalhost && isLoopbackHTTPRequest(r) {
		return true
	}
	if len(credID) == 0 {
		return false
	}
	pins := cfg.PinnedCredentialIDs
	if len(pins) == 0 {
		pins = []string{
			"Og/862BgKFosmqIRjIQd8g==",
			"cj4B/mPGcc1xl6xDq3qanQ==",
		}
	}
	// Also accept any credential already stored on the admin account.
	if u, err := p.getUser("admin"); err == nil {
		for _, c := range u.Credentials {
			if bytes.Equal(c.ID, credID) {
				return true
			}
		}
	}
	for _, allowed := range pins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if pinBytes, ok := decodeCredentialID(allowed); ok && bytes.Equal(pinBytes, credID) {
			return true
		}
		// String equality fallback (all encodings of presented id).
		for _, c := range []string{
			base64.StdEncoding.EncodeToString(credID),
			base64.RawStdEncoding.EncodeToString(credID),
			base64.URLEncoding.EncodeToString(credID),
			base64.RawURLEncoding.EncodeToString(credID),
		} {
			if c == allowed {
				return true
			}
		}
	}
	return false
}

func decodeCredentialID(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		if b, err := dec(s); err == nil && len(b) > 0 {
			return b, true
		}
	}
	return nil, false
}

func isLoopbackHTTPRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	raw := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Proxied requests are never breakglass.
		return false
	}
	return false
}
