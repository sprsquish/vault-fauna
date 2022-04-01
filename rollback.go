package fauna

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	walRollbackMap := map[string]framework.WALRollbackFunc{
		"key": b.pathKeyRollback,
	}

	stateFlags := consts.ReplicationPerformanceSecondary | consts.ReplicationPerformanceStandby
	if !b.System().LocalMount() && b.System().ReplicationState().HasState(stateFlags) {
		return nil
	}

	f, ok := walRollbackMap[kind]
	if !ok {
		return fmt.Errorf("unknown type to rollback")
	}

	return f(ctx, req, kind, data)
}
