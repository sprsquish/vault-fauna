package fauna

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const pathKeyHelpSyn = `
Generate Fauna keys from a specific Vault role.
`

const pathKeyHelpDesc = `
This path will generate new, never before used Fauna keys for
accessing Fauna. The IAM policy used to back this key pair will be
the "name" parameter. For example, if this backend is mounted at "fauna",
then "fauna/deploy" would generate access keys for the "deploy" role.

The keys will have a lease associated with them. The keys can be revoked
by using the lease ID.
`

func pathKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: framework.GenericNameWithAtRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Lifetime of the returned credentials in seconds",
				Default:     3600,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathRead,
			logical.UpdateOperation: b.pathRead,
		},

		HelpSynopsis:    pathKeyHelpSyn,
		HelpDescription: pathKeyHelpDesc,
	}
}

func (b *backend) pathRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	// Read the policy
	role, err := b.roleRead(ctx, req.Storage, roleName, true)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Role '%s' not found", roleName)), nil
	}

	return b.faunaKeyCreate(ctx, req.Storage, req.DisplayName, roleName, role)
}

func (b *backend) pathKeyRollback(ctx context.Context, req *logical.Request, _kind string, data any) error {
	var entry walKey
	if err := mapstructure.Decode(data, &entry); err != nil {
		return err
	}

	// Get the client
	client, err := b.client(ctx, req.Storage)
	if err != nil {
		return err
	}

	ref, err := client.strToRef(entry.Ref)
	if err != nil {
		return err
	}

	err = client.deleteKey(*ref)
	if err != nil {
		return err
	}

	return nil
}

type walKey struct {
	Ref string
}
