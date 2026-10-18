package manage

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/app"
)

const updateStatusPath = app.ConfigDir + "/update-status.json"

type UpdateStatus struct {
	Running bool      `json:"running"`
	Log     []string  `json:"log"`
	Error   string    `json:"error"`
	Updated time.Time `json:"updated"`
}

// The worker lives in its own systemd unit, so restarting the web panel cannot
// kill the update before tunnel restarts, health checks and rollback complete.
func StartUpdateWorker() error {
	args := []string{"--unit=arange-tun-update", "--collect", "--property=Type=exec", app.BinPath, "--apply-update"}
	if out, err := exec.Command("systemd-run", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("could not start update worker (another update may be running): %w: %s", err, out)
	}
	return nil
}

func ReadUpdateStatus() UpdateStatus {
	var s UpdateStatus
	if b, err := os.ReadFile(updateStatusPath); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func RunUpdateWorker() error {
	var mu sync.Mutex
	s := UpdateStatus{Running: true, Log: []string{}}
	save := func() {
		s.Updated = time.Now().UTC()
		b, _ := json.Marshal(s)
		_ = app.WriteFileAtomic(updateStatusPath, b, 0600)
	}
	save()
	err := ApplyUpdate(func(line string) {
		mu.Lock()
		defer mu.Unlock()
		if len(s.Log) >= 200 {
			s.Log = s.Log[1:]
		}
		s.Log = append(s.Log, line)
		save()
	})
	mu.Lock()
	defer mu.Unlock()
	s.Running = false
	if err != nil {
		s.Error = err.Error()
	}
	save()
	return err
}
