package fauna

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const pathConfigRotateRootHelpSyn = `
Request to rotate the Fauna root key used by Vault
`

const pathConfigRotateRootHelpDesc = `
This path attempts to rotate the Fauna root key used by Vault for this mount.
It is only valid if Vault has been configured with a secret via the config/root
endpoint.
`

const RootKeyName = "vault-root"

func pathConfigRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathConfigRotateRootUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathConfigRotateRootHelpSyn,
		HelpDescription: pathConfigRotateRootHelpDesc,
	}
}

func (b *backend) pathConfigRotateRootUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// have to get the client config first because that takes out a read lock
	client, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("nil Fauna client")
	}

	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	rawRootConfig, err := req.Storage.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if rawRootConfig == nil {
		return nil, fmt.Errorf("no configuration found for config/root")
	}
	var config rootConfig
	if err := rawRootConfig.DecodeJSON(&config); err != nil {
		return nil, errwrap.Wrapf("error reading root configuration: {{err}}", err)
	}

	if config.Secret == "" {
		return logical.ErrorResponse("Cannot call config/rotate-root when secret is empty"), nil
	}

	keyName := fmt.Sprintf("vault-root-%d", time.Now().Unix())
	key, err := client.createKey(&FaunaRoleEntry{
		Role:  "admin",
		Extra: map[string]any{"name": keyName},
	})
	if err != nil {
		return nil, errwrap.Wrapf("error generating new root key: {{err}}", err)
	}

	oldSecret := config.Secret

	config.Secret = key.Secret

	newEntry, err := logical.StorageEntryJSON("config/root", config)
	if err != nil {
		return nil, errwrap.Wrapf("error generating new config/root JSON: {{err}}", err)
	}
	if err := req.Storage.Put(ctx, newEntry); err != nil {
		return nil, errwrap.Wrapf("error saving new config/root: {{err}}", err)
	}

	b.faunaClient = nil

	if err := client.deleteKeyBySecret(oldSecret); err != nil {
		return nil, errwrap.Wrapf("error deleting old key: {{err}}", err)
	}

	return &logical.Response{}, nil
}
