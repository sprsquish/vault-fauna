package fauna

import (
	"context"
	"fmt"

	f "github.com/fauna/faunadb-go/v4/faunadb"
	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

const IndexName = "keys-by-hash-for-vault"

type FaunaKey struct {
	Name         string `fauna:"data.name"`
	Secret       string `fauna:"secret"`
	HashedSecret string `fauna:"hashed_secret"`
	Role         string `fauna:"role"`
	Database     f.RefV `fauna:"database"`
}

type FaunaClient struct {
	client *f.FaunaClient
}

func (fc *FaunaClient) ensureKeyIndex() error {
	createStmt := f.CreateIndex(f.Obj{
		"name":   IndexName,
		"source": f.Keys(),
		"terms": f.Arr{f.Obj{
			"field": f.Arr{"hashed_secret"},
		}}})

	query := f.If(
		f.Exists(f.Index(IndexName)),
		f.Null(),
		createStmt)

	_, err := fc.client.Query(query)
	return err
}

func (fc *FaunaClient) deleteKey(hash string) error {
	query := f.Map(
		f.Paginate(f.MatchTerm(f.Index(IndexName), hash)),
		f.Lambda("ref", f.Delete(f.Var("ref"))))

	_, err := fc.client.Query(query)
	return err
}

func (fc *FaunaClient) deleteKeyBySecret(secret string) error {
	query := f.Delete(f.Select("ref", f.KeyFromSecret(secret)))
	_, err := fc.client.Query(query)
	return err
}

func (fc *FaunaClient) createKey(name string, role *FaunaRoleEntry) (*FaunaKey, error) {
	data := f.Obj{
		"role": role.KeyRole,
		"data": f.Obj{"name": name}}
	if role.Database != "" {
		data["database"] = f.Database(role.Database)
	}

	res, err := fc.client.Query(f.CreateKey(data))
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

	httpClient := cleanhttp.DefaultClient()

	if endpoint != "" {
		endpointConfig = f.Endpoint(endpoint)
	} else {
		endpointConfig = func(cli *f.FaunaClient) {}
	}

	observer := func(qr *f.QueryResult) {
		logger.Info(fmt.Sprintf("Query: %s\nResult: %s", qr.Query, qr.Result))
		// TODO: wire up logging
	}

	faunaClient := f.NewFaunaClient(
		faunaSecret,
		endpointConfig,
		f.HTTP(httpClient),
		f.Observer(observer))

	if faunaClient == nil {
		return nil, fmt.Errorf("could not obtain Fauna client")
	}

	client := &FaunaClient{
		client: faunaClient,
	}

	if err := client.ensureKeyIndex(); err != nil {
		return nil, err
	}

	return client, nil
}
