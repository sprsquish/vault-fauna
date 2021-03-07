package fauna

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const faunaKeyType = "faunaKey"

func faunaKeys(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: faunaKeyType,
		Fields: map[string]*framework.FieldSchema{
			"secret": &framework.FieldSchema{
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

	keyhash := fmt.Sprintf("vault-%s-%s-%d-%d", displayName, policyName, time.Now().Unix(), rand.Int31n(10000))

	// Write to the WAL that this key will be created. We do this before
	// the key is created because if switch the order then the WAL put
	// can fail, which would put us in an awkward position: we have a key
	// we need to rollback but can't put the WAL entry to do the rollback.
	walID, err := framework.PutWAL(ctx, s, "key", &walKey{
		KeyHash: keyhash,
	})
	if err != nil {
		return nil, errwrap.Wrapf("error writing WAL entry: {{err}}", err)
	}

	// Create the keys
	faunaKey, err := client.createKey(keyhash, role)
	if err != nil {
		return logical.ErrorResponse("Error creating key: %s", err), err
	}

	// Remove the WAL entry, we succeeded! If we fail, we don't return
	// the secret because it'll get rolled back anyways, so we have to return
	// an error here.
	if err := framework.DeleteWAL(ctx, s, walID); err != nil {
		return nil, errwrap.Wrapf("failed to commit WAL entry: {{err}}", err)
	}

	// Return the info!
	resp := b.Secret(faunaKeyType).Response(map[string]interface{}{
		"secret": faunaKey.Secret,
	}, map[string]interface{}{
		"keyhash": faunaKey.HashedSecret,
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
	// Get the keyhash from the internal data
	keyhashRaw, ok := req.Secret.InternalData["keyhash"]
	if !ok {
		return nil, fmt.Errorf("secret is missing keyhash internal data")
	}
	keyhash, ok := keyhashRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing keyhash internal data")
	}

	// Use the key rollback mechanism to delete this key
	err := b.pathKeyRollback(ctx, req, "key", map[string]interface{}{
		"keyhash": keyhash,
	})
	if err != nil {
		return nil, err
	}

	return nil, nil
}
