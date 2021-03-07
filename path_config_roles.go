package fauna

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameWithAtRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the policy",
				//DisplayAttrs: &framework.DisplayAttributes{
				//Name: "Policy Name",
				//},
			},

			"key_role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Fauna role to associate with the key.`,
			},

			"database": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `A reference for the database associated with this key.`,
			},

			"extra": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `JSON-encoded data to add to the generated key`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathRolesDelete,
			logical.ReadOperation:   b.pathRolesRead,
			logical.UpdateOperation: b.pathRolesWrite,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.roleMutex.RLock()
	defer b.roleMutex.RUnlock()
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.roleRead(ctx, req.Storage, d.Get("name").(string), true)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp logical.Response

	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()
	roleEntry, err := b.roleRead(ctx, req.Storage, roleName, false)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &FaunaRoleEntry{}
	}

	if keyRoleRaw, ok := d.GetOk("key_role"); ok {
		roleEntry.KeyRole = keyRoleRaw.(string)
	}

	if databaseRaw, ok := d.GetOk("database"); ok {
		roleEntry.Database = databaseRaw.(string)
	}

	if extraRaw, ok := d.GetOk("extra"); ok {
		compacted := extraRaw.(string)
		if len(compacted) > 0 {
			compacted, err = compactJSON(extraRaw.(string))
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("cannot parse extra: %q", extraRaw.(string))), nil
			}
		}
		roleEntry.Extra = compacted
	}

	err = setFaunaRole(ctx, req.Storage, roleName, roleEntry)
	if err != nil {
		return nil, err
	}

	if len(resp.Warnings) == 0 {
		return nil, nil
	}

	return &resp, nil
}

func (b *backend) roleRead(ctx context.Context, s logical.Storage, roleName string, shouldLock bool) (*FaunaRoleEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}
	if shouldLock {
		b.roleMutex.RLock()
	}
	entry, err := s.Get(ctx, "role/"+roleName)
	if shouldLock {
		b.roleMutex.RUnlock()
	}
	if err != nil {
		return nil, err
	}
	var roleEntry FaunaRoleEntry
	if entry != nil {
		if err := entry.DecodeJSON(&roleEntry); err != nil {
			return nil, err
		}
		return &roleEntry, nil
	}

	if shouldLock {
		b.roleMutex.Lock()
		defer b.roleMutex.Unlock()
	}
	entry, err = s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}

	if entry != nil {
		if err := entry.DecodeJSON(&roleEntry); err != nil {
			return nil, err
		}
		return &roleEntry, nil
	}

	return nil, nil
}

func setFaunaRole(ctx context.Context, s logical.Storage, roleName string, roleEntry *FaunaRoleEntry) error {
	if roleName == "" {
		return fmt.Errorf("empty role name")
	}
	if roleEntry == nil {
		return fmt.Errorf("nil roleEntry")
	}
	entry, err := logical.StorageEntryJSON("role/"+roleName, roleEntry)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("nil result when writing to storage")
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

type FaunaRoleEntry struct {
	KeyRole  string `json:"key_role"` // Fauna role to associated with the key.
	Database string `json:"database"` // Fauna database to associated with the key.
	Extra    string `json:"extra"`    // JSON-serialized inline extra data to add to the key.
}

func (r *FaunaRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"key_role": r.KeyRole,
		"database": r.Database,
		"extra":    r.Extra,
	}

	return respData
}

func compactJSON(input string) (string, error) {
	var compacted bytes.Buffer
	err := json.Compact(&compacted, []byte(input))
	return compacted.String(), err
}

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and reference policies that keys can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create Fauna keys. These roles are associated with key roles that
map directly to the route to read the Fauna keys. For example, if the
backend is mounted at "fauna" and you create a role at "fauna/roles/deploy"
then a user could request access credentials at "fauna/deploy".

To validate the keys, attempt to read an access key after writing the policy.
`
