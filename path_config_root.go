package fauna

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const pathConfigRootHelpSyn = `
Configure the root credentials that are used to manage Fauna.
`

const pathConfigRootHelpDesc = `
Before doing anything, the Fauna backend needs credentials that are able
to manage Fauna keys. This endpoint is used to configure those credentials.
`

func pathConfigRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			"secret": {
				Type:        framework.TypeString,
				Description: "Fauna secret with permission to create new keys.",
				Required:    true,
			},
			"endpoint": {
				Type:        framework.TypeString,
				Description: "Endpoint to custom Fauna server URL",
				Required:    true,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRootRead,
			logical.UpdateOperation: b.pathConfigRootWrite,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

type rootConfig struct {
	Secret   string `json:"secret"`
	Endpoint string `json:"endpoint"`
}

func (b *backend) pathConfigRootRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.clientMutex.RLock()
	defer b.clientMutex.RUnlock()

	entry, err := req.Storage.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var config rootConfig

	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	configData := map[string]interface{}{
		"secret":   config.Secret,
		"endpoint": config.Endpoint,
	}
	return &logical.Response{
		Data: configData,
	}, nil
}

func (b *backend) pathConfigRootWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	endpoint := data.Get("endpoint").(string)
	secret := data.Get("secret").(string)

	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	entry, err := logical.StorageEntryJSON("config/root", rootConfig{
		Secret:   secret,
		Endpoint: endpoint,
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// clear possible cached Fauna clients after successfully updating
	// config/root
	b.faunaClient = nil

	return nil, nil
}
