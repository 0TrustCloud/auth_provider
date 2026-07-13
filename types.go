package auth_provider

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

type PasskeyUser struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"displayName"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u *PasskeyUser) WebAuthnID() []byte                          { return u.ID }
func (u *PasskeyUser) WebAuthnName() string                        { return u.Name }
func (u *PasskeyUser) WebAuthnDisplayName() string                 { return u.DisplayName }
func (u *PasskeyUser) WebAuthnIcon() string                        { return "" }
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type OIDCClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

type AuthRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type ActiveSession struct {
	Username   string `json:"username"`
	DBSCPubKey string `json:"dbsc_pub_key,omitempty"`
}

type pendingRegistration struct {
	UserID []byte `json:"user_id"`
}
