package auth_provider

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/pquerna/otp/totp"
	github_webauthn "github.com/go-webauthn/webauthn/webauthn"
)

type ProvisioningState struct {
	Username    string    `json:"username"`
	TOTPSecret  string    `json:"totp_secret"`
	IsVerified  bool      `json:"is_verified"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (p *Provider) ProvisionUserEntry(username string) (string, error) {
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for TOTP: %w", err)
	}
	totpSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	state := ProvisioningState{
		Username:   username,
		TOTPSecret: totpSecret,
		IsVerified: false,
		ExpiresAt:  time.Now().Add(30 * time.Minute),
	}

	stateBytes, _ := json.Marshal(state)
	targetAddress := "provision:totp:" + username
	script := `provision:registration(factor("totp") stage("initialized"))`

	// Compile initial enrollment checkpoint parameters via the SDF core engine
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "user-provisioning-service",
		Nonce:         0,
		Method:        "INITIALIZE_PROVISIONING",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"totp_secret": totpSecret},
	}

	_, err := p.SdfEngine.CompileSecureData(script, tx)
	if err != nil {
		return "", fmt.Errorf("failed compiling provisioning ticket via SDF: %w", err)
	}

	dataKey := "data:provision:" + username
	txn := p.SdfEngine.Store.Begin()
	err = p.SdfEngine.Store.Put(txn, []byte(dataKey), stateBytes, 30*time.Minute)
	if err != nil {
		txn.Abort()
		return "", fmt.Errorf("failed to write provisioning state data slot: %w", err)
	}
	if err := txn.Commit(); err != nil {
		return "", err
	}

	issuerEscaped := url.QueryEscape(p.issuer)
	userEscaped := url.QueryEscape(username)
	otpauthURI := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuerEscaped, userEscaped, totpSecret, issuerEscaped)

	return otpauthURI, nil
}

func (p *Provider) VerifyProvisioningTOTP(username, passcode string) (bool, error) {
	dataKey := "data:provision:" + username
	txn := p.SdfEngine.Store.Begin()
	stateBytes, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	if err != nil || len(stateBytes) == 0 {
		return false, errors.New("provisioning session expired or not found")
	}

	var state ProvisioningState
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		return false, err
	}

	if time.Now().After(state.ExpiresAt) {
		return false, errors.New("provisioning time limit exceeded")
	}

	isValid := totp.Validate(passcode, state.TOTPSecret)
	if !isValid {
		return false, nil
	}

	state.IsVerified = true
	updatedBytes, _ := json.Marshal(state)

	targetAddress := "provision:totp:" + username
	script := `provision:registration(factor("totp") stage("verified"))`

	// Update provisioning state tracking records securely via SDF compilation
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "user-provisioning-service",
		Nonce:         1,
		Method:        "VERIFY_PROVISIONING_FACTOR",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"status": "cleared_for_hardware"},
	}

	_, err = p.SdfEngine.CompileSecureData(script, tx)
	if err != nil {
		return false, fmt.Errorf("failed recording verified factor update token: %w", err)
	}

	wTxn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Put(wTxn, []byte(dataKey), updatedBytes, 15*time.Minute)
	return true, wTxn.Commit()
}

func (p *Provider) CompleteHardwareEnrollment(username string, tpmPublicBytes []byte, r *http.Request) error {
	dataKey := "data:provision:" + username
	txn := p.SdfEngine.Store.Begin()
	stateBytes, err := p.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	if err != nil || len(stateBytes) == 0 {
		return errors.New("provisioning verification records missing")
	}

	var state ProvisioningState
	_ = json.Unmarshal(stateBytes, &state)

	if !state.IsVerified {
		return errors.New("unauthorized hardware upgrade: TOTP factor unverified")
	}

	passkeyUser := &PasskeyUser{
		ID:          tpmPublicBytes, 
		Name:        username,
		DisplayName: username,
		Credentials: make([]github_webauthn.Credential, 0),
	}

	sessionData, err := p.getSession("reg_" + username)
	if err != nil {
		return fmt.Errorf("passkey context session dropped: %w", err)
	}

	credential, err := p.wa.FinishRegistration(passkeyUser, sessionData, r)
	if err != nil {
		return fmt.Errorf("webauthn hardware ceremony failure: %w", err)
	}

	passkeyUser.Credentials = append(passkeyUser.Credentials, *credential)

	if err := p.saveUser(passkeyUser); err != nil {
		return fmt.Errorf("failed committing hardware profile to db: %w", err)
	}

	// Burn provisioning token context using the SDF engine
	targetAddress := "provision:totp:" + username
	script := `provision:registration(status("consumed"))`
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "user-provisioning-service",
		Nonce:         2,
		Method:        "CONSUME_PROVISIONING_TICKET",
		Profile:       secure_data_format.ProfileGrant,
	}
	_, _ = p.SdfEngine.CompileSecureData(script, tx)

	burnTxn := p.SdfEngine.Store.Begin()
	_ = p.SdfEngine.Store.Delete(burnTxn, []byte(dataKey))
	return burnTxn.Commit()
}
