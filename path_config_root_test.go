package fauna

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend_PathConfigRoot(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]any{
		"secret":   "fauna-secret",
		"endpoint": "https://db.fauna.com",
	}

	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Path:      "config/root",
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: config writing failed: resp:%#v\n err: %v", resp, err)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   config.StorageView,
		Path:      "config/root",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: config reading failed: resp:%#v\n err: %v", resp, err)
	}

	if !reflect.DeepEqual(resp.Data, configData) {
		t.Errorf("bad: expected to read config root as %#v, got %#v instead", configData, resp.Data)
	}
}
