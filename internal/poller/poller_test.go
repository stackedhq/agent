package poller

import (
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/executor"
)

func TestOpTimeout(t *testing.T) {
	cases := []struct {
		op   client.Operation
		want time.Duration
	}{
		{client.Operation{Type: "deploy"}, 45 * time.Minute},
		{client.Operation{Type: "db_backup"}, 2 * time.Hour},
		{client.Operation{Type: "db_restore"}, 2 * time.Hour},
		{client.Operation{Type: "db_migrate"}, 2 * time.Hour},
		{client.Operation{Type: "volume_migrate"}, 2 * time.Hour},
		{client.Operation{Type: "release_command"}, 45*time.Minute + executor.ReleaseCommandTimeout},
		{client.Operation{Type: "cron_run", Payload: map[string]interface{}{}}, time.Hour + jobSetupSlack},
		{client.Operation{Type: "cron_run", Payload: map[string]interface{}{"timeoutSeconds": float64(60)}}, time.Minute + jobSetupSlack},
		{client.Operation{Type: "db_provision"}, 30 * time.Minute},
		{client.Operation{Type: "proxy_config"}, 10 * time.Minute},
		{client.Operation{Type: "something_new"}, 10 * time.Minute},
	}
	for _, c := range cases {
		if got := opTimeout(c.op); got != c.want {
			t.Fatalf("opTimeout(%s) = %s, want %s", c.op.Type, got, c.want)
		}
	}
}
