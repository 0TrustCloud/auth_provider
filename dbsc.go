package auth_provider

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

func (p *Provider) loadActiveSession(jti string) (ActiveSession, []byte, error) {
	dataKey := "data:session:" + jti
	txID := ultimate_db.GlobalCacheStore.BeginOCC()

	sessionBytes, err := ultimate_db.GlobalCacheStore.Read(txID, dataKey)
	if err != nil {
		txn := p.SdfEngine.Store.Begin()
		sessionBytes, err = p.SdfEngine.Store.Get(txn, []byte(dataKey))
		txn.Commit()
		if err != nil {
			return ActiveSession{}, nil, err
		}
	}

	var session ActiveSession
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return ActiveSession{}, nil, err
	}
	return session, sessionBytes, nil
}

func (p *Provider) persistActiveSession(jti string, session ActiveSession) error {
	dataKey := "data:session:" + jti
	updatedBytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{dataKey: updatedBytes}, 24*time.Hour)

	wTxn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Put(wTxn, []byte(dataKey), updatedBytes, 24*time.Hour); err != nil {
		wTxn.Abort()
		return err
	}
	return wTxn.Commit()
}

func (p *Provider) DBSCRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JWT string `json:"jwt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid DBSC registration payload", http.StatusBadRequest)
		return
	}

	token, _, err := new(jwt.Parser).ParseUnverified(req.JWT, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "Invalid JWT format", http.StatusBadRequest)
		return
	}

	jwkBytes, err := json.Marshal(token.Header["jwk"])
	if err != nil || string(jwkBytes) == "null" {
		http.Error(w, "Missing JWK in registration", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "No active session to bind", http.StatusUnauthorized)
		return
	}

	jti, err := p.extractJTIFromCookie(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session token format", http.StatusUnauthorized)
		return
	}

	session, _, err := p.loadActiveSession(jti)
	if err != nil || session.Username == "" {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	session.DBSCPubKey = string(jwkBytes)

	targetAddress := "session:hardware_binding:" + jti
	script := `session:hardware(type("tpm") status("bound"))`
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "dbsc-hardware-attestation-service",
		Nonce:         1,
		Method:        "REGISTER_HARDWARE_BINDING",
		Profile:       secure_data_format.ProfileProofOfPoss,
		Args: map[string]interface{}{
			"jti":          jti,
			"dbsc_pub_key": string(jwkBytes),
		},
	}
	if _, err = p.SdfEngine.CompileSecureData(script, tx); err != nil && p.Logger != nil {
		p.Logger.Error("SDF hardware binding audit skipped for " + session.Username + ": " + err.Error())
	}

	if err := p.persistActiveSession(jti, session); err != nil {
		http.Error(w, "Failed to persist hardware binding", http.StatusInternalServerError)
		return
	}

	p.logIDPAudit(session.Username, "DBSC_REGISTER", "hardware session binding registered for "+session.Username)
	w.WriteHeader(http.StatusOK)
}

func (p *Provider) DBSCRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Session missing", http.StatusUnauthorized)
		return
	}

	jti, err := p.extractJTIFromCookie(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session token format", http.StatusUnauthorized)
		return
	}

	session, _, err := p.loadActiveSession(jti)
	if err != nil || session.Username == "" {
		http.Error(w, "Session expired completely", http.StatusUnauthorized)
		return
	}

	if session.DBSCPubKey == "" {
		http.Error(w, "Session is not bound to hardware", http.StatusBadRequest)
		return
	}

	responseHeader := r.Header.Get("Sec-Session-Response")
	if responseHeader == "" {
		nonceBytes := make([]byte, 32)
		_, _ = rand.Read(nonceBytes)
		nonce := base64.URLEncoding.EncodeToString(nonceBytes)

		targetAddress := "challenge:dbsc:" + nonce
		script := fmt.Sprintf(`challenge:verification(nonce("%s"))`, nonce)

		tx := secure_data_format.DataInvocation{
			TargetAddress: targetAddress,
			Caller:        "dbsc-challenge-generator",
			Nonce:         0,
			Method:        "ISSUE_CHALLENGE",
			Profile:       secure_data_format.ProfileProofOfPoss,
			Args:          map[string]interface{}{"username": session.Username},
		}

		if _, err = p.SdfEngine.CompileSecureData(script, tx); err != nil && p.Logger != nil {
			p.Logger.Error("SDF challenge audit skipped for " + session.Username + ": " + err.Error())
		}

		txID := ultimate_db.GlobalCacheStore.BeginOCC()
		nonceKey := "data:dbsc_nonce:" + nonce
		_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{nonceKey: []byte(session.Username)}, 2*time.Minute)

		nTxn := p.SdfEngine.Store.Begin()
		_ = p.SdfEngine.Store.Put(nTxn, []byte(nonceKey), []byte(session.Username), 2*time.Minute)
		_ = nTxn.Commit()

		p.logIDPInfo("DBSC_REFRESH", "challenge issued for "+session.Username)
		w.Header().Set("Sec-Session-Challenge", fmt.Sprintf(`"%s"`, nonce))
		http.Error(w, "Challenge required", http.StatusUnauthorized)
		return
	}

	token, _ := jwt.Parse(responseHeader, func(token *jwt.Token) (interface{}, error) {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON([]byte(session.DBSCPubKey)); err != nil {
			return nil, err
		}
		return jwk.Key, nil
	})

	if token != nil && token.Valid {
		p.logIDPAudit(session.Username, "DBSC_REFRESH", "session refreshed for "+session.Username)
		cookie.MaxAge = 86400
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusOK)
		return
	}

	p.logIDPError("DBSC_REFRESH", "invalid DBSC response for "+session.Username)
	http.Error(w, "Invalid DBSC response", http.StatusForbidden)
}