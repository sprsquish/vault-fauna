package fauna

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The Fauna  backend dynamically generates Fauna keys. The Fauna keys
have a configurable lease set and are automatically revoked at the
end of the lease.

After mounting this backend, credentials to generate Fauna keys must
be configured with the "root" path and policies must be written using
the "roles/" endpoints before any keys can be generated.
`

const (
	rootConfigPath    = "config/root"
	minKeyRollbackAge = 1 * time.Second
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config/root",
			},
		},

		Paths: []*framework.Path{
			pathConfigRoot(&b),
			pathConfigRotateRoot(&b),
			pathConfigLease(&b),
			pathRoles(&b),
			pathListRoles(&b),
			pathKey(&b),
		},

		Secrets: []*framework.Secret{
			faunaKeys(&b),
		},

		Invalidate:        b.invalidate,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: minKeyRollbackAge,
		BackendType:       logical.TypeLogical,
	}

	return &b
}

type backend struct {
	*framework.Backend

	// Mutex to protect access to reading and writing policies
	roleMutex sync.RWMutex

	// Mutex to protect access to fauna clients and client configs
	clientMutex sync.RWMutex

	// client hold configured Fauna client for reuse, and
	// to enable mocking with Fauna iface for tests
	faunaClient *FaunaClient
}

func (b *backend) invalidate(ctx context.Context, key string) {
	switch {
	case key == rootConfigPath:
		b.clearClient()
	}
}

// clearClient clears the backend's Fauna client
func (b *backend) clearClient() {
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()
	b.faunaClient = nil
}

// clientFauna returns the configured Fauna client. If nil, it constructs a new one
// and returns it, setting it the internal variable
func (b *backend) client(ctx context.Context, s logical.Storage) (*FaunaClient, error) {
	b.clientMutex.RLock()
	if b.faunaClient != nil {
		b.clientMutex.RUnlock()
		return b.faunaClient, nil
	}

	// Upgrade the lock for writing
	b.clientMutex.RUnlock()
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	// check client again, in the event that a client was being created while we
	// waited for Lock()
	if b.faunaClient != nil {
		return b.faunaClient, nil
	}

	client, err := nonCachedClient(ctx, s, b.Logger())
	if err != nil {
		return nil, err
	}
	b.faunaClient = client

	return b.faunaClient, nil
}
