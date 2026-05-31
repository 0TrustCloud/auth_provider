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
	if err != nil {
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

	dataKey := "data:session:" + jti
	txn := p.SdfEngine.Store.Begin()
	sessionBytes, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	if err == nil && len(sessionBytes) > 0 {
		var session ActiveSession
		_ = json.Unmarshal(sessionBytes, &session)
		session.DBSCPubKey = string(jwkBytes)
		updatedBytes, _ := json.Marshal(session)

		targetAddress := "session:hardware_binding:" + jti
		script := `session:hardware(type("tpm") status("bound"))`

		// Formally compile the physical device attestation coupling matrix via SDF
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

		_, err = p.SdfEngine.CompileSecureData(script, tx)
		if err != nil {
			http.Error(w, "SDF engine rejected hardware configuration token", http.StatusInternalServerError)
			return
		}

		txID := ultimate_db.GlobalCacheStore.BeginOCC()
		_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{dataKey: updatedBytes}, 24*time.Hour)

		wTxn := p.SdfEngine.Store.Begin()
		_ = p.SdfEngine.Store.Put(wTxn, []byte(dataKey), updatedBytes, 24*time.Hour)
		_ = wTxn.Commit()
	}

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

	dataKey := "data:session:" + jti
	txID := ultimate_db.GlobalCacheStore.BeginOCC()

	sessionBytes, err := ultimate_db.GlobalCacheStore.Read(txID, dataKey)
	if err != nil {
		txn := p.SdfEngine.Store.Begin()
		sessionBytes, err = p.SdfEngine.Store.Get(txn, []byte(dataKey))
		txn.Commit()
		if err != nil || len(sessionBytes) == 0 {
			http.Error(w, "Session expired completely", http.StatusUnauthorized)
			return
		}
	}

	var session ActiveSession
	_ = json.Unmarshal(sessionBytes, &session)

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

		// Register verification parameters using the token architecture
		tx := secure_data_format.DataInvocation{
			TargetAddress: targetAddress,
			Caller:        "dbsc-challenge-generator",
			Nonce:         0,
			Method:        "ISSUE_CHALLENGE",
			Profile:       secure_data_format.ProfileProofOfPoss,
			Args:          map[string]interface{}{"username": session.Username},
		}

		_, err = p.SdfEngine.CompileSecureData(script, tx)
		if err != nil {
			http.Error(w, "SDF failed to mint proof-of-possession verification parameter", http.StatusInternalServerError)
			return
		}

		nonceKey := "data:dbsc_nonce:" + nonce
		_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{nonceKey: []byte(session.Username)}, 2*time.Minute)

		nTxn := p.SdfEngine.Store.Begin()
		_ = p.SdfEngine.Store.Put(nTxn, []byte(nonceKey), []byte(session.Username), 2*time.Minute)
		_ = nTxn.Commit()

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
		cookie.MaxAge = 86400
		cookieStr := cookie.String() + "; Sec-Provided-Session-Key"
		w.Header().Add("Set-Cookie", cookieStr)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Invalid DBSC response", http.StatusForbidden)
}
