package executor

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// Operation context.
//
// Operations run one at a time, so the context of the running op is kept in
// a package-level slot instead of being threaded through every handler.
// Commands started through opCommand are bound to it: when the poller's
// per-op deadline expires, they are killed and the handler unwinds.
//
// Note for `docker exec` / `docker run`: killing the docker CLI does not stop
// the process inside the container. Job containers are stopped explicitly
// with `docker kill` (see runJobContainer).

var (
	opCtxMu sync.Mutex
	opCtx   = context.Background()
)

// commandWaitDelay bounds how long Wait blocks after the context is done (or
// after the child exits while a grandchild still holds its output pipe)
// before the pipes are force-closed.
const commandWaitDelay = 30 * time.Second

// setOpContext installs ctx as the running op's context and returns a func
// that restores the previous one.
func setOpContext(ctx context.Context) func() {
	opCtxMu.Lock()
	prev := opCtx
	opCtx = ctx
	opCtxMu.Unlock()
	return func() {
		opCtxMu.Lock()
		opCtx = prev
		opCtxMu.Unlock()
	}
}

// currentOpContext returns the running op's context (Background when no op
// is running).
func currentOpContext() context.Context {
	opCtxMu.Lock()
	defer opCtxMu.Unlock()
	return opCtx
}

// opCommand is exec.Command bound to the running op's context.
func opCommand(name string, args ...string) *exec.Cmd {
	return opCommandContext(currentOpContext(), name, args...)
}

// opCommandContext is exec.CommandContext with the child in its own process
// group, so cancellation kills everything it spawned (`docker compose` runs
// as a plugin subprocess of `docker`, git spawns remote helpers, nixpacks
// spawns buildx). Killing only the direct child would leave those holding
// the output pipe and the reader blocked.
func opCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = commandWaitDelay
	setKillProcessGroup(cmd)
	return cmd
}
