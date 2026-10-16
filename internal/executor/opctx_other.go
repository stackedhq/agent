//go:build !unix

package executor

import "os/exec"

func setKillProcessGroup(cmd *exec.Cmd) {}
