//go:build !linux

package manage

import "os/exec"

func logProcessGroup(cmd *exec.Cmd) {}
