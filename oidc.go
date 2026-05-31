package auth_provider

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

func (p *Provider) getClient(clientID string) (*OIDCClient, error) {
	dataKey := "data:client:" + clientID
	txn := p.SdfEngine.Store.Begin()
	val, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	if err != nil {
		return nil, err
	}
	var client OIDCClient
	if err := json.Unmarshal(val, &client); err != nil {
		return nil, err
	}
	return &client, nil
}

func (p *Provider) handlePostAuth(username string, w http.ResponseWriter, r *http.Request) {
	if p.OnLoginSuccess != nil {
		p.OnLoginSuccess(username, w, r)
	}

	cleanUsername := strings.TrimSpace(username)
	if strings.HasPrefix(cleanUsername, "user_session_") {
		cleanUsername = strings.TrimPrefix(cleanUsername, "user_session_")
	}

	tokenString, jti, err := p.SessionManager.IssueCookieToken([]byte(cleanUsername), 24*time.Hour)
	if err != nil {
		http.Error(w, "Failed to issue secure session", http.StatusInternalServerError)
		return
	}

	sessionCookie := &http.Cookie{
		Name:     "session_id",
		Value:    "user_session_" + tokenString,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	}

	cookieString := sessionCookie.String() + "; Sec-Provided-Session-Key"
	w.Header().Add("Set-Cookie", cookieString)

	nonceBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	regChallenge := base64.URLEncoding.EncodeToString(nonceBytes)

	registrationHeader := fmt.Sprintf(`"/auth/dbsc/register"; challenge="%s"; es256`, regChallenge)
	w.Header().Set("Sec-Session-Registration", registrationHeader)

	sessionData := ActiveSession{Username: cleanUsername}
	sessionBytes, _ := json.Marshal(sessionData)

	dataKey := "data:session:" + jti
	sTxn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(sTxn, []byte(dataKey), sessionBytes, 24*time.Hour)
	_ = sTxn.Commit()

	oidcCookie, err := r.Cookie("oidc_flow_id")
	if err == nil && oidcCookie.Value != "" {
		flowID := oidcCookie.Value
		flowKey := "data:oidc_flow:" + flowID

		txn := p.SdfEngine.Store.Begin()
		authReqBytes, err := p.SdfEngine.Store.Get(txn, []byte(flowKey))
		txn.Commit()

		if err == nil {
			var authReq AuthRequest
			if json.Unmarshal(authReqBytes, &authReq) == nil {
				authCode := "code_" + fmt.Sprintf("%d", time.Now().UnixNano())
				codeKey := "data:auth_code:" + authCode

				contextData, _ := json.Marshal(map[string]string{
					"username":              cleanUsername,
					"client_id":             authReq.ClientID,
					"redirect_uri":          authReq.RedirectURI,
					"nonce":                 authReq.Nonce,
					"scope":                 authReq.Scope,
					"code_challenge":        authReq.CodeChallenge,
					"code_challenge_method": authReq.CodeChallengeMethod,
				})

				targetAddress := "oidc:auth_code:" + authCode
				script := fmt.Sprintf(`oidc:code(client_id("%s") user("%s"))`, authReq.ClientID, cleanUsername)

				// Register authorization code parameters securely via SDF compilation
				tx := secure_data_format.DataInvocation{
					TargetAddress: targetAddress,
					Caller:        "oidc-authorization-server",
					Nonce:         0,
					Method:        "ISSUE_AUTH_CODE",
					Profile:       secure_data_format.ProfileGrant,
					Args:          map[string]interface{}{"context_raw": string(contextData)},
				}

				_, err = p.SdfEngine.CompileSecureData(script, tx)
				if err != nil {
					http.Error(w, "SDF compiler rejected authorization token generation", http.StatusInternalServerError)
					return
				}

				wTxn := p.SdfEngine.Store.Begin()
				_ = p.SdfEngine.Store.Put(wTxn, []byte(codeKey), contextData, 5*time.Minute)
				_ = wTxn.Commit()

				http.SetCookie(w, &http.Cookie{Name: "oidc_flow_id", Value: "", Path: "/", MaxAge: -1})

				redirectURL := fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectURI, authCode, authReq.State)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"redirect_to": redirectURL})
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (p *Provider) ServeDiscovery(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/auth/authorize",
		"token_endpoint":                        p.issuer + "/auth/token",
		"revocation_endpoint":                   p.issuer + "/auth/revoke",
		"jwks_uri":                              p.issuer + "/auth/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

func (p *Provider) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &p.signingKey.PublicKey,
		KeyID:     p.keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func (p *Provider) Authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	client, err := p.getClient(clientID)
	if err != nil || responseType != "code" {
		http.Error(w, "Unauthorized client or unsupported response type", http.StatusBadRequest)
		return
	}

	validURI := false
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	sessionCookie, err := r.Cookie("session_id")
	if err == nil {
		subjectID, validationErr := p.SessionManager.ValidateCookieToken(sessionCookie.Value)
		if validationErr == nil {
			mfaKey := "data:mfa_verified_" + subjectID
			txn := p.SdfEngine.Store.Begin()
			mfaVerified, _ := p.SdfEngine.Store.Get(txn, []byte(mfaKey))
			txn.Commit()

			if string(mfaVerified) != "true" {
				http.Redirect(w, r, "/mfa/verify?target="+r.URL.String(), http.StatusFound)
				return
			}
		}
	}

	flowID := "flow_" + fmt.Sprintf("%d", time.Now().UnixNano())
	flowKey := "data:oidc_flow:" + flowID

	authReq := AuthRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	authReqBytes, _ := json.Marshal(authReq)

	wTxn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(wTxn, []byte(flowKey), authReqBytes, 10*time.Minute)
	_ = wTxn.Commit()

	http.SetCookie(w, &http.Cookie{Name: "oidc_flow_id", Value: flowID, Path: "/", Secure: true, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (p *Provider) TokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_ = r.ParseForm()
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")

	_, err := p.getClient(clientID)
	if err != nil {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	contextKey := []byte("data:auth_code:" + code)
	txn := p.SdfEngine.Store.Begin()
	contextBytes, err := p.SdfEngine.Store.Get(txn, contextKey)
	txn.Commit()

	if err != nil {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	wTxn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Delete(wTxn, contextKey)
	_ = wTxn.Commit()

	var context map[string]string
	_ = json.Unmarshal(contextBytes, &context)

	if context["client_id"] != clientID {
		http.Error(w, "Client mismatch", http.StatusBadRequest)
		return
	}

	storedChallenge := context["code_challenge"]
	if storedChallenge != "" {
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier == "" {
			http.Error(w, "Missing code_verifier for PKCE", http.StatusBadRequest)
			return
		}

		challengeMethod := context["code_challenge_method"]
		if challengeMethod == "S256" {
			hash := sha256.Sum256([]byte(codeVerifier))
			expectedChallenge := strings.TrimRight(base64.URLEncoding.EncodeToString(hash[:]), "=")

			if expectedChallenge != storedChallenge {
				http.Error(w, "Invalid code_verifier", http.StatusBadRequest)
				return
			}
		} else {
			if codeVerifier != storedChallenge {
				http.Error(w, "Invalid code_verifier", http.StatusBadRequest)
				return
			}
		}
	}

	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	accessToken := hex.EncodeToString(tokenBytes)
	tokenKey := "data:token:" + accessToken

	targetAddress := "oauth:token:" + accessToken
	script := `token:credential(type("bearer") scope("openid"))`

	// Compile the resulting authenticated OAuth token state structure via SDF
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "oidc-token-exchange-engine",
		Nonce:         0,
		Method:        "ISSUE_ACCESS_TOKEN",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"username": context["username"]},
	}

	_, err = p.SdfEngine.CompileSecureData(script, tx)
	if err != nil {
		http.Error(w, "SDF compiler rejected token issuance configuration", http.StatusInternalServerError)
		return
	}

	aTxn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(aTxn, []byte(tokenKey), []byte(context["username"]), 1*time.Hour)
	_ = aTxn.Commit()

	now := time.Now()
	idClaims := jwt.MapClaims{
		"iss":                p.issuer,
		"sub":                context["username"],
		"aud":                clientID,
		"exp":                now.Add(1 * time.Hour).Unix(),
		"iat":                now.Unix(),
		"nonce":              context["nonce"],
		"preferred_username": context["username"],
		"scopes":             strings.Split(context["scope"], " "),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	token.Header["kid"] = p.keyID
	idTokenString, err := token.SignedString(p.signingKey)
	if err != nil {
		http.Error(w, "Token production error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idTokenString,
		"scope":        context["scope"],
	})
}

func (p *Provider) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_ = r.ParseForm()
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}

	targetAddress := "oauth:token:" + token
	script := `token:credential(status("revoked"))`

	// Issue explicit revocation tracking criteria through the SDF compiler
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "oidc-revocation-endpoint",
		Nonce:         1,
		Method:        "REVOKE_ACCESS_TOKEN",
		Profile:       secure_data_format.ProfileGrant,
	}

	_, _ = p.SdfEngine.CompileSecureData(script, tx)

	tokenKey := "data:token:" + token
	txn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Delete(txn, []byte(tokenKey))
	_ = txn.Commit()

	w.WriteHeader(http.StatusOK)
}

func (p *Provider) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	idBytes := make([]byte, 16)
	secretBytes := make([]byte, 32)
	_, _ = rand.Read(idBytes)
	_, _ = rand.Read(secretBytes)

	client := OIDCClient{
		ClientID:     hex.EncodeToString(idBytes),
		ClientSecret: hex.EncodeToString(secretBytes),
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
	}

	clientBytes, _ := json.Marshal(client)
	targetAddress := "oidc:client:" + client.ClientID
	script := fmt.Sprintf(`client:profile(name("%s") status("active"))`, req.ClientName)

	// Persist the explicit client definition matrix via structural SDF records
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "oidc-client-registration-authority",
		Nonce:         0,
		Method:        "REGISTER_OIDC_CLIENT",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"client_raw": string(clientBytes)},
	}

	_, err := p.SdfEngine.CompileSecureData(script, tx)
	if err != nil {
		http.Error(w, "SDF engine rejected dynamic client identity token generation", http.StatusInternalServerError)
		return
	}

	dataKey := "data:client:" + client.ClientID
	txn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(txn, []byte(dataKey), clientBytes, 0)
	_ = txn.Commit()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(client)
}
