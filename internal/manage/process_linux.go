//go:build linux

package manage

import (
	"os/exec"
	"syscall"
)

func logProcessGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
