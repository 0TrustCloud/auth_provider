package auth_provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_policy"
)

type Provider struct {
	gk             *guikit.GUIKit
	wa             *webauthn.WebAuthn
	issuer         string
	signingKey     *rsa.PrivateKey
	keyID          string
	SessionManager *secure_policy.SessionManager
	SdfEngine      *secure_data_format.SecureDataEngine

	OnLoginSuccess func(username string, w http.ResponseWriter, r *http.Request)
}

func New(gk *guikit.GUIKit, sm *secure_policy.SessionManager, sdf *secure_data_format.SecureDataEngine, rpDisplayName, rpID, rpOrigin string) (*Provider, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
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
		issuer:         rpOrigin,
		signingKey:     privKey,
		keyID:          "v1-default",
		SessionManager: sm,
		SdfEngine:      sdf,
	}

	// WebAuthn Ceremony Routing Wireframes
	gk.Mux.HandleFunc("GET /auth/register/begin", p.BeginRegistration)
	gk.Mux.HandleFunc("POST /auth/register/finish", p.FinishRegistration)
	gk.Mux.HandleFunc("GET /auth/login/begin", p.BeginLogin)
	gk.Mux.HandleFunc("POST /auth/login/finish", p.FinishLogin)
	gk.Mux.HandleFunc("GET /auth/webauthn.js", p.ServeJS)

	// Admin TOTP Verification Paths
	gk.Mux.HandleFunc("POST /auth/provision/verify", p.HandleProvisionVerify)

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

	return p, nil
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
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !verified {
		http.Error(w, "Invalid TOTP initialization code", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "totp_verified_proceed_to_hardware"})
}

func (p *Provider) getUser(username string) (*PasskeyUser, error) {
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
	val, _ := json.Marshal(user)
	targetAddress := "user:profile:" + user.Name
	script := fmt.Sprintf(`user:account(name("%s") status("active"))`, user.Name)

	// Compile profile state modifications directly via the SDF framework
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "webauthn-identity-provider",
		Nonce:         0,
		Method:        "UPDATE_PROFILE",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"payload": string(val)},
	}

	_, err := p.SdfEngine.CompileSecureData(script, tx)
	if err != nil {
		return fmt.Errorf("sdf engine rejected identity profile compilation: %w", err)
	}

	// Mirror structural data payload into metadata slots for fast unmarshaling loops
	dataKey := "data:user:" + user.Name
	txn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Put(txn, []byte(dataKey), val, 0); err != nil {
		txn.Abort()
		return err
	}
	return txn.Commit()
}
