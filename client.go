package fauna

import (
	"context"
	"fmt"
	"strings"

	f "github.com/fauna/faunadb-go/v5/faunadb"
	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

type FaunaKey struct {
	Secret   string  `fauna:"secret"`
	Ref      f.RefV  `fauna:"ref"`
	Role     f.Value `fauna:"role"`
	Database f.RefV  `fauna:"database"`
}

type FaunaClient struct {
	client *f.FaunaClient
	logger hclog.Logger
}

func (fc *FaunaClient) strToRef(refStr string) (*f.RefV, error) {
	var value f.Value
	if err := f.UnmarshalJSON([]byte(refStr), &value); err != nil {
		return nil, err
	}

	ref := value.(f.RefV)
	return &ref, nil
}

func (fc *FaunaClient) deleteKey(ref f.RefV) error {
	_, err := fc.client.Query(f.Delete(ref))
	return err
}

func (fc *FaunaClient) deleteKeyBySecret(secret string) error {
	query := f.Delete(f.Select("ref", f.KeyFromSecret(secret)))
	_, err := fc.client.Query(query)
	return err
}

func (fc *FaunaClient) createKey(role *FaunaRoleEntry) (*FaunaKey, error) {
	create := f.Obj{}

	if role.Database != "" {
		create["database"] = f.Database(role.Database)
	}

	roleTokens := strings.Split(role.Role, "/")
	if len(roleTokens) == 2 {
		create["role"] = f.Role(roleTokens[1])
	} else {
		create["role"] = roleTokens[0]
	}

	if role.Extra != nil {
		create["data"] = role.Extra
	}

	res, err := fc.client.Query(f.CreateKey(create))
	if err != nil {
		return nil, err
	}

	var faunaKey FaunaKey
	err = res.Get(&faunaKey)
	if err != nil {
		return nil, err
	}

	return &faunaKey, nil
}

// NOTE: The caller is required to ensure that b.clientMutex is at least read locked
func nonCachedClient(ctx context.Context, s logical.Storage, logger hclog.Logger) (*FaunaClient, error) {
	var faunaSecret string
	var endpoint string
	var endpointConfig f.ClientConfig

	entry, err := s.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var config rootConfig
		if err := entry.DecodeJSON(&config); err != nil {
			return nil, errwrap.Wrapf("error reading root configuration: {{err}}", err)
		}

		faunaSecret = config.Secret
		endpoint = config.Endpoint
	}

	httpClient := f.HTTP(cleanhttp.DefaultClient())

	if endpoint != "" {
		endpointConfig = f.Endpoint(endpoint)
	} else {
		endpointConfig = func(cli *f.FaunaClient) {}
	}

	// observer := f.Observer(func(qr *f.QueryResult) {
	// 	logger.Debug(fmt.Sprintf("Query: %s\nResult: %s", qr.Query, qr.Result))
	// })

	faunaClient := f.NewFaunaClient(
		faunaSecret,
		endpointConfig,
		httpClient)

	if faunaClient == nil {
		return nil, fmt.Errorf("could not obtain Fauna client")
	}

	client := &FaunaClient{
		client: faunaClient,
		logger: logger,
	}

	return client, nil
}
