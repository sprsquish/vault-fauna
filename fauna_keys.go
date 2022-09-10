package fauna

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const faunaKeyType = "fauna_keys"

func faunaKeys(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: faunaKeyType,
		Fields: map[string]*framework.FieldSchema{
			"secret": {
				Type:        framework.TypeString,
				Description: "Key Secret",
			},
		},

		Renew:  b.faunaKeysRenew,
		Revoke: b.faunaKeysRevoke,
	}
}

func (b *backend) faunaKeyCreate(
	ctx context.Context,
	s logical.Storage,
	displayName, policyName string,
	role *FaunaRoleEntry) (*logical.Response, error) {
	client, err := b.client(ctx, s)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Create the keys
	faunaKey, err := client.createKey(role)
	if err != nil {
		return logical.ErrorResponse("Error creating key: %s", err), err
	}

	refJSON, err := faunaKey.Ref.MarshalJSON()
	if err != nil {
		return logical.ErrorResponse("Error creating key: %s", err), err
	}

	resp := b.Secret(faunaKeyType).Response(map[string]any{
		"secret": faunaKey.Secret,
	}, map[string]any{
		"ref": string(refJSON),
	})

	lease, err := b.Lease(ctx, s)
	if err != nil || lease == nil {
		lease = &configLease{}
	}

	resp.Secret.TTL = lease.Lease
	resp.Secret.MaxTTL = lease.LeaseMax

	return resp, nil
}

func (b *backend) faunaKeysRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lease, err := b.Lease(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = lease.Lease
	resp.Secret.MaxTTL = lease.LeaseMax
	return resp, nil
}

func (b *backend) faunaKeysRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Use the key rollback mechanism to delete this key
	if err := b.pathKeyRollback(ctx, req, "key", req.Secret.InternalData); err != nil {
		return nil, err
	}
	return nil, nil
}
