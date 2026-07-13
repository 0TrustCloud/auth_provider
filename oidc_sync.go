package auth_provider

import (
	"encoding/json"
	"fmt"

	"github.com/0TrustCloud/secure_data_format"
)

// PutOIDCClient mirrors a registry client into the runtime SDF store (data:client:*).
func (p *Provider) PutOIDCClient(client OIDCClient) error {
	if p == nil || p.SdfEngine == nil {
		return fmt.Errorf("auth provider unavailable")
	}
	if client.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	clientBytes, err := json.Marshal(client)
	if err != nil {
		return err
	}

	targetAddress := "oidc:client:" + client.ClientID
	name := client.ClientName
	if name == "" {
		name = client.ClientID
	}
	script := fmt.Sprintf(`client:profile(name("%s") status("active"))`, name)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "oidc-registry-sync",
		Method:        "REGISTER_OIDC_CLIENT",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"client_raw": string(clientBytes)},
	}
	if _, err := p.SdfEngine.CompileSecureData(script, tx); err != nil {
		return fmt.Errorf("sdf rejected client sync: %w", err)
	}

	dataKey := "data:client:" + client.ClientID
	txn := p.SdfEngine.Store.Begin()
	if err := p.SdfEngine.Store.Put(txn, []byte(dataKey), clientBytes, 0); err != nil {
		_ = txn.Commit()
		return err
	}
	return txn.Commit()
}